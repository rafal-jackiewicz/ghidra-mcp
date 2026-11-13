// Copyright 2026 Rafał Jackiewicz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include "registrar.hpp"

#include <nlohmann/json.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#include "util.hpp"

using nlohmann::ordered_json;

namespace {

// Long enough for Ghidra auto-analysis of a large binary.
const int kToolTimeoutSec = 600;

enum class Kind { ClaudeCli, Json, Toml, Yaml };
enum class Outcome { Registered, Updated, Unchanged, Removed, NotPresent, Failed };

struct Harness {
    const char* key;
    const char* title;
    Kind kind;
    const char* configPath;   // relative to $HOME
    const char* altPath;      // second location of the config (e.g. a snap's home), or null
    const char* detectDir;    // relative to $HOME; presence means the harness is installed
    const char* binary;       // executable looked up in $PATH, or null
    const char* section;      // JSON object holding the servers
    // Builds the JSON entry for this harness (Json and ClaudeCli fallback only).
    ordered_json (*entry)(const RegisterOptions&);
};

ordered_json authHeaders(const RegisterOptions& o) {
    return {{"Authorization", "Bearer " + o.token}};
}

ordered_json entryClaude(const RegisterOptions& o) {
    ordered_json e = {{"type", "http"}, {"url", o.url}};
    if (!o.token.empty()) e["headers"] = authHeaders(o);
    return e;
}
ordered_json entryKimi(const RegisterOptions& o) {
    ordered_json e = {{"url", o.url}, {"toolTimeoutMs", kToolTimeoutSec * 1000}};
    if (!o.token.empty()) e["headers"] = authHeaders(o);
    return e;
}
ordered_json entryGeminiLike(const RegisterOptions& o) {  // Gemini CLI and Qwen Code
    ordered_json e = {{"httpUrl", o.url}, {"timeout", kToolTimeoutSec * 1000}};
    if (!o.token.empty()) e["headers"] = authHeaders(o);
    return e;
}
ordered_json entryOpencode(const RegisterOptions& o) {
    ordered_json e = {{"type", "remote"}, {"url", o.url}, {"enabled", true}};
    if (!o.token.empty()) e["headers"] = authHeaders(o);
    return e;
}
ordered_json entryPi(const RegisterOptions& o) {
    ordered_json e = {{"url", o.url}, {"timeout", kToolTimeoutSec}};
    if (!o.token.empty()) e["headers"] = authHeaders(o);
    return e;
}
ordered_json entryCursor(const RegisterOptions& o) {
    ordered_json e = {{"url", o.url}};
    if (!o.token.empty()) e["headers"] = authHeaders(o);
    return e;
}

const Harness kHarnesses[] = {
    {"claude", "Claude Code", Kind::ClaudeCli, ".claude.json", nullptr, ".claude", "claude",
     "mcpServers", entryClaude},
    {"kimi", "Kimi Code", Kind::Json, ".kimi-code/mcp.json", nullptr, ".kimi-code", "kimi",
     "mcpServers", entryKimi},
    {"qwen", "Qwen Code", Kind::Json, ".qwen/settings.json", nullptr, ".qwen", "qwen",
     "mcpServers", entryGeminiLike},
    {"gemini", "Gemini CLI (Google)", Kind::Json, ".gemini/settings.json",
     "snap/gemini-cli/common/.gemini/settings.json", ".gemini",
     "gemini", "mcpServers", entryGeminiLike},
    {"codex", "Codex CLI (OpenAI)", Kind::Toml, ".codex/config.toml", nullptr, ".codex", "codex",
     nullptr, nullptr},
    {"opencode", "opencode", Kind::Json, ".config/opencode/opencode.json",
     ".config/opencode/opencode.jsonc", ".config/opencode", "opencode", "mcp", entryOpencode},
    {"hermes", "Hermes Agent", Kind::Yaml, ".hermes/config.yaml", nullptr, ".hermes", "hermes",
     nullptr, nullptr},
    {"pi", "Pi", Kind::Json, ".pi/agent/mcp.json", nullptr, ".pi", "pi", "mcpServers", entryPi},
    {"cursor", "Cursor", Kind::Json, ".cursor/mcp.json", nullptr, ".cursor", "cursor-agent",
     "mcpServers", entryCursor},
};

std::string findInPath(const char* binary) {
    const char* path = getenv("PATH");
    if (!binary || !path) return "";
    std::stringstream ss(path);
    std::string dir;
    while (std::getline(ss, dir, ':')) {
        std::string candidate = (dir.empty() ? "." : dir) + "/" + binary;
        if (access(candidate.c_str(), X_OK) == 0 && util::isFile(candidate)) return candidate;
    }
    return "";
}

// The config files to edit: every known location that exists, else the default one.
std::vector<std::string> configFiles(const Harness& h) {
    const std::string home = util::homeDir() + "/";
    std::vector<std::string> files;
    if (util::isFile(home + h.configPath)) files.push_back(home + h.configPath);
    if (h.altPath && util::isFile(home + h.altPath)) files.push_back(home + h.altPath);
    if (files.empty()) files.push_back(home + h.configPath);
    return files;
}

std::string configFile(const Harness& h) { return configFiles(h).front(); }

bool detected(const Harness& h) {
    return util::isDir(util::homeDir() + "/" + h.detectDir) || util::isFile(configFile(h)) ||
           !findInPath(h.binary).empty();
}

std::string quoted(const std::string& s) {
    // JSON string syntax is also a valid TOML basic string and YAML double-quoted scalar.
    return ordered_json(s).dump();
}

std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::stringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

std::string joinLines(const std::vector<std::string>& lines) {
    std::string out;
    for (const std::string& l : lines) out += l + "\n";
    return out;
}

std::string trimmed(const std::string& s) {
    size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return "";
    return s.substr(a, s.find_last_not_of(" \t") - a + 1);
}

// Replaces path atomically, keeping its permissions and a one-time backup of the original.
bool saveConfig(const std::string& path, const std::string& content, std::string& err) {
    std::string target = path;
    char resolved[PATH_MAX];
    if (realpath(path.c_str(), resolved)) target = resolved;  // keep symlinked configs linked

    mode_t mode = 0600;
    struct stat st;
    const bool exists = stat(target.c_str(), &st) == 0;
    if (exists) {
        mode = st.st_mode & 0777;
        const std::string backup = target + ".ghidra-mcp.bak";
        std::string original;
        if (!util::isFile(backup) && util::readFile(target, original) &&
            !util::writeFile(backup, original, static_cast<int>(mode))) {
            err = "cannot write backup " + backup + ": " + strerror(errno);
            return false;
        }
    } else {
        size_t slash = target.find_last_of('/');
        if (slash != std::string::npos && !util::makeDirs(target.substr(0, slash), 0700)) {
            err = "cannot create " + target.substr(0, slash) + ": " + strerror(errno);
            return false;
        }
    }
    const std::string tmp = target + ".ghidra-mcp.tmp";
    if (!util::writeFile(tmp, content, static_cast<int>(mode)) ||
        chmod(tmp.c_str(), mode) != 0 || rename(tmp.c_str(), target.c_str()) != 0) {
        err = "cannot write " + target + ": " + strerror(errno);
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

// ---------------------------------------------------------------- JSON configs

// Loads a JSON config (comments tolerated). Missing or empty file yields an empty object.
bool loadJson(const std::string& path, ordered_json& root, bool& hadComments, std::string& err) {
    hadComments = false;
    std::string text;
    if (!util::readFile(path, text) || trimmed(text).find_first_not_of("\r\n") == std::string::npos) {
        root = ordered_json::object();
        return true;
    }
    root = ordered_json::parse(text, nullptr, false, false);
    if (root.is_discarded()) {
        root = ordered_json::parse(text, nullptr, false, true);
        hadComments = !root.is_discarded();
    }
    if (root.is_discarded() || !root.is_object()) {
        err = path + " is not a valid JSON object; not touching it";
        return false;
    }
    return true;
}

Outcome editJson(const Harness& h, const std::string& path, bool unregister,
                 const RegisterOptions& opt, std::string& note) {
    ordered_json root;
    bool comments;
    if (!loadJson(path, root, comments, note)) return Outcome::Failed;

    const bool hasSection = root.contains(h.section) && root[h.section].is_object();
    const bool present = hasSection && root[h.section].contains(opt.name);
    Outcome outcome;
    if (unregister) {
        if (!present) return Outcome::NotPresent;
        root[h.section].erase(opt.name);
        outcome = Outcome::Removed;
    } else {
        const ordered_json entry = h.entry(opt);
        if (present && root[h.section][opt.name] == entry) return Outcome::Unchanged;
        if (root.contains(h.section) && !hasSection) {
            note = "\"" + std::string(h.section) + "\" in " + path + " is not an object";
            return Outcome::Failed;
        }
        root[h.section][opt.name] = entry;
        outcome = present ? Outcome::Updated : Outcome::Registered;
    }
    if (comments)
        note = opt.dryRun ? "comments in the file will be dropped (original kept as .ghidra-mcp.bak)"
                          : "comments in the file were dropped (original kept as .ghidra-mcp.bak)";
    if (!opt.dryRun && !saveConfig(path, root.dump(2) + "\n", note)) return Outcome::Failed;
    return outcome;
}

// ---------------------------------------------------------------- Codex (TOML)

bool isOurTomlHeader(const std::string& line, const std::string& name) {
    std::string t = trimmed(line);
    if (t.size() < 2 || t[0] != '[' || t[1] == '[') return false;
    size_t end = t.find(']');
    if (end == std::string::npos) return false;
    std::string key = trimmed(t.substr(1, end - 1));
    for (const std::string& base : {"mcp_servers." + name, "mcp_servers.\"" + name + "\""}) {
        if (key == base || key.compare(0, base.size() + 1, base + ".") == 0) return true;
    }
    return false;
}

Outcome editToml(const std::string& path, bool unregister, const RegisterOptions& opt,
                 std::string& note) {
    std::string text;
    util::readFile(path, text);
    std::vector<std::string> lines = splitLines(text), kept, old;
    bool inOurs = false;
    for (const std::string& line : lines) {
        std::string t = trimmed(line);
        if (!t.empty() && t[0] == '[') inOurs = isOurTomlHeader(line, opt.name);
        (inOurs ? old : kept).push_back(line);
    }
    while (!old.empty() && trimmed(old.back()).empty()) old.pop_back();

    std::vector<std::string> block = {"[mcp_servers." + opt.name + "]",
                                      "url = " + quoted(opt.url),
                                      "tool_timeout_sec = " + std::to_string(kToolTimeoutSec)};
    if (!opt.token.empty())
        block.push_back("http_headers = { \"Authorization\" = " + quoted("Bearer " + opt.token) +
                        " }");

    Outcome outcome;
    if (unregister) {
        if (old.empty()) return Outcome::NotPresent;
        outcome = Outcome::Removed;
    } else {
        if (old == block) return Outcome::Unchanged;
        outcome = old.empty() ? Outcome::Registered : Outcome::Updated;
    }
    while (!kept.empty() && trimmed(kept.back()).empty()) kept.pop_back();
    if (!unregister) {
        if (!kept.empty()) kept.push_back("");
        kept.insert(kept.end(), block.begin(), block.end());
    }
    if (!opt.dryRun && !saveConfig(path, joinLines(kept), note)) return Outcome::Failed;
    return outcome;
}

// ---------------------------------------------------------------- Hermes (YAML)

size_t indentOf(const std::string& line) { return line.find_first_not_of(' '); }

bool isBlankOrComment(const std::string& line) {
    std::string t = trimmed(line);
    return t.empty() || t[0] == '#';
}

Outcome editYaml(const std::string& path, bool unregister, const RegisterOptions& opt,
                 std::string& note) {
    std::string text;
    util::readFile(path, text);
    std::vector<std::string> lines = splitLines(text);

    // Locate the top-level "mcp_servers:" mapping.
    size_t top = lines.size();
    for (size_t i = 0; i < lines.size(); i++) {
        if (lines[i].compare(0, 12, "mcp_servers:") != 0) continue;
        std::string rest = trimmed(lines[i].substr(12));
        if (rest.empty() || rest[0] == '#') {
            top = i;
        } else if (rest == "{}" || rest == "null" || rest == "~") {
            lines[i] = "mcp_servers:";
            top = i;
        } else {
            note = "mcp_servers in " + path + " uses inline syntax; add the server by hand";
            return Outcome::Failed;
        }
        break;
    }

    // Children of mcp_servers: lines up to the next top-level key.
    size_t end = top;
    size_t childIndent = 2;
    bool sawChild = false;
    if (top < lines.size()) {
        for (end = top + 1; end < lines.size(); end++) {
            if (isBlankOrComment(lines[end])) continue;
            size_t ind = indentOf(lines[end]);
            if (ind == 0) break;
            if (!sawChild) {
                childIndent = ind;
                sawChild = true;
            }
        }
    }

    // Find our entry among the children.
    size_t first = lines.size(), last = lines.size();
    for (size_t i = top + 1; i < end && top < lines.size(); i++) {
        if (isBlankOrComment(lines[i]) || indentOf(lines[i]) != childIndent) continue;
        std::string key = trimmed(lines[i]);
        if (key == opt.name + ":" || key == "\"" + opt.name + "\":" ||
            key == "'" + opt.name + "':") {
            first = i;
            for (last = i + 1; last < end; last++) {
                if (!isBlankOrComment(lines[last]) && indentOf(lines[last]) <= childIndent) break;
            }
            while (last > first + 1 && isBlankOrComment(lines[last - 1])) last--;
            break;
        }
    }

    const std::string in1(childIndent, ' '), in2(childIndent * 2, ' '), in3(childIndent * 3, ' ');
    std::vector<std::string> block = {in1 + opt.name + ":", in2 + "url: " + quoted(opt.url),
                                      in2 + "timeout: " + std::to_string(kToolTimeoutSec)};
    if (!opt.token.empty()) {
        block.push_back(in2 + "headers:");
        block.push_back(in3 + "Authorization: " + quoted("Bearer " + opt.token));
    }

    const bool present = first < lines.size();
    Outcome outcome;
    if (unregister) {
        if (!present) return Outcome::NotPresent;
        lines.erase(lines.begin() + first, lines.begin() + last);
        outcome = Outcome::Removed;
    } else if (present) {
        if (std::vector<std::string>(lines.begin() + first, lines.begin() + last) == block)
            return Outcome::Unchanged;
        lines.erase(lines.begin() + first, lines.begin() + last);
        lines.insert(lines.begin() + first, block.begin(), block.end());
        outcome = Outcome::Updated;
    } else {
        if (top == lines.size()) {
            if (!lines.empty() && !trimmed(lines.back()).empty()) lines.push_back("");
            lines.push_back("mcp_servers:");
            top = lines.size() - 1;
        }
        lines.insert(lines.begin() + top + 1, block.begin(), block.end());
        outcome = Outcome::Registered;
    }
    if (!opt.dryRun && !saveConfig(path, joinLines(lines), note)) return Outcome::Failed;
    return outcome;
}

// ---------------------------------------------------------------- Claude Code (its own CLI)

// Runs a program without a shell; output is discarded. Returns its exit status or -1.
int runQuiet(const std::string& program, const std::vector<std::string>& args) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, 0);
            dup2(devnull, 1);
            dup2(devnull, 2);
        }
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(program.c_str()));
        for (const std::string& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        execv(program.c_str(), argv.data());
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

bool claudeHasEntry(const Harness& h, const RegisterOptions& opt, ordered_json* entry = nullptr) {
    ordered_json root;
    bool comments;
    std::string err;
    if (!loadJson(configFile(h), root, comments, err)) return false;
    if (!root.contains(h.section) || !root[h.section].is_object() ||
        !root[h.section].contains(opt.name))
        return false;
    if (entry) *entry = root[h.section][opt.name];
    return true;
}

// Claude Code rewrites ~/.claude.json while it runs, so changes go through its own CLI when
// it is installed; the file is edited directly only as a fallback.
Outcome editClaude(const Harness& h, bool unregister, const RegisterOptions& opt,
                   std::string& note) {
    const std::string cli = findInPath(h.binary);
    if (cli.empty()) return editJson(h, configFile(h), unregister, opt, note);

    ordered_json existing;
    const bool present = claudeHasEntry(h, opt, &existing);
    if (unregister) {
        if (!present) return Outcome::NotPresent;
        if (!opt.dryRun && runQuiet(cli, {"mcp", "remove", "--scope", "user", opt.name}) != 0) {
            note = "'claude mcp remove' failed";
            return Outcome::Failed;
        }
        return Outcome::Removed;
    }
    if (present && existing == h.entry(opt)) return Outcome::Unchanged;
    if (opt.dryRun) return present ? Outcome::Updated : Outcome::Registered;

    if (present) runQuiet(cli, {"mcp", "remove", "--scope", "user", opt.name});
    std::vector<std::string> args = {"mcp", "add", "--transport", "http", "--scope", "user",
                                     opt.name, opt.url};
    if (!opt.token.empty()) {
        args.push_back("--header");
        args.push_back("Authorization: Bearer " + opt.token);
    }
    if (runQuiet(cli, args) != 0) {
        note = "'claude mcp add' failed; try: claude mcp add --transport http --scope user " +
               opt.name + " " + opt.url;
        return Outcome::Failed;
    }
    return present ? Outcome::Updated : Outcome::Registered;
}

// ---------------------------------------------------------------- driver

Outcome apply(const Harness& h, const std::string& path, bool unregister,
              const RegisterOptions& opt, std::string& note) {
    switch (h.kind) {
        case Kind::ClaudeCli: return editClaude(h, unregister, opt, note);
        case Kind::Json: return editJson(h, path, unregister, opt, note);
        case Kind::Toml: return editToml(path, unregister, opt, note);
        case Kind::Yaml: return editYaml(path, unregister, opt, note);
    }
    return Outcome::Failed;
}

bool isRegistered(const Harness& h, const RegisterOptions& opt) {
    // A dry-run unregister reports whether an entry exists without changing anything.
    RegisterOptions probe = opt;
    probe.dryRun = true;
    for (const std::string& path : configFiles(h)) {
        std::string note;
        if (apply(h, path, true, probe, note) == Outcome::Removed) return true;
    }
    return false;
}

const Harness* findHarness(const std::string& key) {
    for (const Harness& h : kHarnesses)
        if (key == h.key) return &h;
    return nullptr;
}

std::string displayPath(const std::string& path) {
    const std::string home = util::homeDir();
    return path.compare(0, home.size() + 1, home + "/") == 0 ? "~" + path.substr(home.size())
                                                              : path;
}

}  // namespace

std::string harnessKeys() {
    std::string keys;
    for (const Harness& h : kHarnesses) keys += (keys.empty() ? "" : ",") + std::string(h.key);
    return keys;
}

int listHarnesses(const RegisterOptions& opt) {
    printf("%-9s %-20s %-10s %-11s %s\n", "KEY", "HARNESS", "INSTALLED", "REGISTERED", "CONFIG");
    for (const Harness& h : kHarnesses) {
        std::string paths;
        for (const std::string& path : configFiles(h))
            paths += (paths.empty() ? "" : ", ") + displayPath(path);
        printf("%-9s %-20s %-10s %-11s %s\n", h.key, h.title, detected(h) ? "yes" : "no",
               isRegistered(h, opt) ? "yes" : "no", paths.c_str());
    }
    printf("\nREGISTERED refers to the server name \"%s\" (change with --name).\n",
           opt.name.c_str());
    return 0;
}

int runRegistration(const std::string& list, bool unregister, const RegisterOptions& opt) {
    for (unsigned char c : opt.name) {
        if (!isalnum(c) && c != '-' && c != '_') {
            fprintf(stderr, "ghidra-mcp: invalid --name '%s' (use letters, digits, - and _)\n",
                    opt.name.c_str());
            return 2;
        }
    }
    if (opt.name.empty()) {
        fprintf(stderr, "ghidra-mcp: --name must not be empty\n");
        return 2;
    }

    // Resolve the harness selection.
    std::vector<const Harness*> selected;
    const bool all = list.empty() || list == "all";
    if (all) {
        for (const Harness& h : kHarnesses)
            if (detected(h)) selected.push_back(&h);
        if (selected.empty()) {
            fprintf(stderr,
                    "ghidra-mcp: no supported harness found on this machine.\n"
                    "Name one explicitly to create its configuration, e.g. --register codex.\n"
                    "Supported: %s\n",
                    harnessKeys().c_str());
            return 1;
        }
    } else {
        std::stringstream ss(list);
        std::string key;
        while (std::getline(ss, key, ',')) {
            key = trimmed(key);
            if (key.empty()) continue;
            const Harness* h = findHarness(key);
            if (!h) {
                fprintf(stderr, "ghidra-mcp: unknown harness '%s'. Supported: %s, all\n",
                        key.c_str(), harnessKeys().c_str());
                return 2;
            }
            selected.push_back(h);
        }
    }

    if (!unregister)
        printf("%s \"%s\" -> %s%s\n", opt.dryRun ? "Would register" : "Registering",
               opt.name.c_str(), opt.url.c_str(),
               opt.token.empty() ? "" : " (with bearer token)");

    int failures = 0, changed = 0;
    for (const Harness* h : selected) {
        for (const std::string& path : configFiles(*h)) {
            std::string note;
            const Outcome outcome = apply(*h, path, unregister, opt, note);
            const char* word = "";
            switch (outcome) {
                case Outcome::Registered: word = opt.dryRun ? "would register" : "registered"; break;
                case Outcome::Updated: word = opt.dryRun ? "would update" : "updated"; break;
                case Outcome::Unchanged: word = "already registered"; break;
                case Outcome::Removed: word = opt.dryRun ? "would remove" : "removed"; break;
                case Outcome::NotPresent: word = "not registered"; break;
                case Outcome::Failed: word = "FAILED"; break;
            }
            if (outcome == Outcome::Failed) failures++;
            if (outcome == Outcome::Registered || outcome == Outcome::Updated ||
                outcome == Outcome::Removed)
                changed++;
            printf("  %-20s %-18s %s\n", h->title, word, displayPath(path).c_str());
            if (!note.empty()) printf("  %-20s   note: %s\n", "", note.c_str());
        }
    }

    if (changed && !opt.dryRun) {
        printf("\nRestart the harness (or reload its MCP servers) to pick up the change.\n");
        if (!unregister) {
            printf("The server must be running for the tools to appear: start ghidra-mcp with "
                   "the same\n--port/--endpoint%s.\n",
                   opt.token.empty() ? "" : "/--token");
            if (!opt.token.empty())
                printf("The token is stored in plain text in the files listed above.\n");
        }
    }
    return failures ? 1 : 0;
}
