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

// ghidra-mcp: exposes a local Ghidra installation as an MCP (Model Context Protocol) server.

#include <getopt.h>
#include <glob.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include "bridge.hpp"
#include "audit.hpp"
#include "http.hpp"
#include "mcp.hpp"
#include "registrar.hpp"
#include "util.hpp"
#include "version.hpp"

static std::atomic<bool> gStop{false};

static void onSignal(int) { gStop = true; }

static void usage(FILE* out, const char* argv0) {
    fprintf(out,
"ghidra-mcp %s - expose a Ghidra installation as an MCP server\n"
"\n"
"Usage: %s [options]\n"
"\n"
"Transport:\n"
"  -p, --port PORT          TCP port to listen on (default 8765)\n"
"  -H, --host ADDR          address to bind (default 127.0.0.1; use 0.0.0.0 to accept\n"
"                           connections from other machines / bridged VMs)\n"
"  -t, --token TOKEN        require \"Authorization: Bearer TOKEN\" from clients\n"
"                           (default: $GHIDRA_MCP_TOKEN; recommended with --host 0.0.0.0)\n"
"  -e, --endpoint PATH      URL path of the MCP endpoint (default /ghidra-mcp)\n"
"      --token-file FILE    several tokens, one per person: lines of NAME:TOKEN. The name\n"
"                           appears in the audit log\n"
"      --stdio              speak MCP over stdin/stdout instead of HTTP\n"
"\n"
"Ghidra:\n"
"  -g, --ghidra-home DIR    Ghidra installation (default: $GHIDRA_INSTALL_DIR, else the\n"
"                           highest version in ~/ghidra-install/ghidra_*,\n"
"                           else /opt/ghidra*)\n"
"  -j, --java-home DIR      JDK for Ghidra (default: $JAVA_HOME, else a JDK 21 in\n"
"                           /usr/lib/jvm)\n"
"  -d, --project-dir DIR    directory of the Ghidra project (default ~/ghidra-projects)\n"
"  -n, --project-name NAME  Ghidra project name (default ghidra-mcp)\n"
"      --upload-dir DIR     where uploaded binaries are stored\n"
"                           (default <project-dir>/uploads)\n"
"      --max-upload-mb N    largest accepted upload in MiB (default 2048)\n"
"      --startup-timeout S  seconds to wait for Ghidra to start (default 300)\n"
"      --lazy               start Ghidra on the first tool call, not at launch\n"
"\n"
"Harness registration (edits the harness's user-level MCP config, then exits):\n"
"      --register[=LIST]    add this server to harnesses; LIST is comma-separated from\n"
"                           %s\n"
"                           (default: every harness found on this machine)\n"
"      --unregister[=LIST]  remove this server from harnesses\n"
"      --harnesses          list supported harnesses and whether they are registered\n"
"      --name NAME          server name used in the harness (default ghidra)\n"
"      --url URL            URL to register (default: http://127.0.0.1:PORT/ENDPOINT built\n"
"                           from --host/--port/--endpoint)\n"
"      --dry-run            show what --register/--unregister would change\n"
"\n"
"Accountability:\n"
"      --audit-log FILE     append a record of every tool call (who, when, which tool,\n"
"                           arguments, digest of the result) to FILE; the records are\n"
"                           chained by hashes so that tampering can be detected\n"
"      --verify-audit FILE  check such a file and exit\n"
"\n"
"General:\n"
"  -v, --verbose            log requests and bridge traffic to stderr\n"
"  -V, --version            print version and exit\n"
"  -h, --help               show this help and exit\n"
"\n"
"Endpoints (HTTP mode; ENDPOINT is the --endpoint path):\n"
"  POST ENDPOINT            MCP Streamable HTTP transport\n"
"  GET  ENDPOINT/sse        MCP legacy HTTP+SSE transport (POST ENDPOINT/messages)\n"
"  PUT  ENDPOINT/upload/<ticket>/<name>\n"
"                           binary upload; URLs come from the prepare_upload tool\n"
"  GET  /health             liveness check\n"
"\n"
"Clients on this machine use http://127.0.0.1:PORT/ghidra-mcp. A QEMU guest with user-mode\n"
"networking reaches the same server at http://10.0.2.2:PORT/ghidra-mcp. For bridged or tap\n"
"networking start with --host 0.0.0.0 --token SECRET and use the host's address.\n",
            GHIDRA_MCP_VERSION, argv0, harnessKeys().c_str());
}

static std::string newestMatch(const std::string& pattern) {
    glob_t g;
    std::string best;
    if (glob(pattern.c_str(), 0, nullptr, &g) == 0) {
        // The highest version wins: 12.1.10 is newer than 12.1.4, whatever the alphabet says.
        for (size_t i = 0; i < g.gl_pathc; i++)
            if (util::isDir(g.gl_pathv[i]) &&
                (best.empty() || strverscmp(g.gl_pathv[i], best.c_str()) > 0))
                best = g.gl_pathv[i];
    }
    globfree(&g);
    return best;
}

static bool isLoopback(const std::string& host) {
    return host == "127.0.0.1" || host == "localhost" || host == "::1" ||
           host.compare(0, 4, "127.") == 0;
}

int main(int argc, char** argv) {
    HttpConfig http;
    BridgeConfig bridgeCfg;
    std::string uploadDir, auditPath, tokenFile, verifyPath, cliToken;
    bool stdio = false, lazy = false;
    enum class Action { Serve, Register, Unregister, ListHarnesses } action = Action::Serve;
    std::string harnessList;
    RegisterOptions reg;
    long maxUploadMb = 2048;

    const char* env;
    if ((env = getenv("GHIDRA_MCP_TOKEN"))) cliToken = env;
    if ((env = getenv("GHIDRA_INSTALL_DIR"))) bridgeCfg.ghidraHome = env;
    if ((env = getenv("JAVA_HOME"))) bridgeCfg.javaHome = env;
    bridgeCfg.projectDir = util::homeDir() + "/ghidra-projects";
    bridgeCfg.projectName = "ghidra-mcp";

    enum {
        OPT_STDIO = 1000, OPT_UPLOAD_DIR, OPT_MAX_UPLOAD, OPT_TIMEOUT, OPT_LAZY, OPT_REGISTER,
        OPT_UNREGISTER, OPT_HARNESSES, OPT_NAME, OPT_URL, OPT_DRY_RUN, OPT_AUDIT, OPT_TOKEN_FILE,
        OPT_VERIFY_AUDIT
    };
    static const struct option longOpts[] = {
        {"port", required_argument, nullptr, 'p'},
        {"host", required_argument, nullptr, 'H'},
        {"token", required_argument, nullptr, 't'},
        {"endpoint", required_argument, nullptr, 'e'},
        {"stdio", no_argument, nullptr, OPT_STDIO},
        {"ghidra-home", required_argument, nullptr, 'g'},
        {"java-home", required_argument, nullptr, 'j'},
        {"project-dir", required_argument, nullptr, 'd'},
        {"project-name", required_argument, nullptr, 'n'},
        {"upload-dir", required_argument, nullptr, OPT_UPLOAD_DIR},
        {"max-upload-mb", required_argument, nullptr, OPT_MAX_UPLOAD},
        {"startup-timeout", required_argument, nullptr, OPT_TIMEOUT},
        {"lazy", no_argument, nullptr, OPT_LAZY},
        {"register", optional_argument, nullptr, OPT_REGISTER},
        {"unregister", optional_argument, nullptr, OPT_UNREGISTER},
        {"harnesses", no_argument, nullptr, OPT_HARNESSES},
        {"name", required_argument, nullptr, OPT_NAME},
        {"url", required_argument, nullptr, OPT_URL},
        {"dry-run", no_argument, nullptr, OPT_DRY_RUN},
        {"audit-log", required_argument, nullptr, OPT_AUDIT},
        {"token-file", required_argument, nullptr, OPT_TOKEN_FILE},
        {"verify-audit", required_argument, nullptr, OPT_VERIFY_AUDIT},
        {"verbose", no_argument, nullptr, 'v'},
        {"version", no_argument, nullptr, 'V'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}};

    auto number = [&](const char* text, const char* what, long min, long max) {
        char* end = nullptr;
        long v = strtol(text, &end, 10);
        if (!*text || *end || v < min || v > max) {
            fprintf(stderr, "%s: invalid %s '%s' (expected %ld-%ld)\n", argv[0], what, text, min,
                    max);
            exit(2);
        }
        return v;
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:H:t:e:g:j:d:n:vVh", longOpts, nullptr)) != -1) {
        switch (opt) {
            case 'p': http.port = static_cast<int>(number(optarg, "port", 1, 65535)); break;
            case 'H': http.host = optarg; break;
            case 't': cliToken = optarg; break;
            case 'e': http.endpoint = optarg; break;
            case OPT_STDIO: stdio = true; break;
            case 'g': bridgeCfg.ghidraHome = optarg; break;
            case 'j': bridgeCfg.javaHome = optarg; break;
            case 'd': bridgeCfg.projectDir = optarg; break;
            case 'n': bridgeCfg.projectName = optarg; break;
            case OPT_UPLOAD_DIR: uploadDir = optarg; break;
            case OPT_MAX_UPLOAD: maxUploadMb = number(optarg, "upload size", 1, 1 << 20); break;
            case OPT_TIMEOUT:
                bridgeCfg.startupTimeoutSec =
                    static_cast<int>(number(optarg, "startup timeout", 5, 86400));
                break;
            case OPT_LAZY: lazy = true; break;
            case OPT_REGISTER:
            case OPT_UNREGISTER:
                action = opt == OPT_REGISTER ? Action::Register : Action::Unregister;
                if (optarg) {
                    harnessList = optarg;
                } else if (optind < argc && argv[optind][0] != '-') {
                    harnessList = argv[optind++];  // also accept "--register LIST"
                }
                break;
            case OPT_HARNESSES: action = Action::ListHarnesses; break;
            case OPT_NAME: reg.name = optarg; break;
            case OPT_URL: reg.url = optarg; break;
            case OPT_DRY_RUN: reg.dryRun = true; break;
            case OPT_AUDIT: auditPath = optarg; break;
            case OPT_TOKEN_FILE: tokenFile = optarg; break;
            case OPT_VERIFY_AUDIT: verifyPath = optarg; break;
            case 'v': util::verbose = true; break;
            case 'V': printf("ghidra-mcp %s\n", GHIDRA_MCP_VERSION); return 0;
            case 'h': usage(stdout, argv[0]); return 0;
            default:
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                return 2;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "%s: unexpected argument '%s'\nTry '%s --help' for more information.\n",
                argv[0], argv[optind], argv[0]);
        return 2;
    }

    if (!verifyPath.empty()) return AuditLog::verify(verifyPath);

    // Tokens: --token gives the user "default"; a token file names one user per line.
    if (!cliToken.empty()) http.users.emplace_back("default", cliToken);
    if (!tokenFile.empty()) {
        std::string text;
        if (!util::readFile(tokenFile, text)) {
            fprintf(stderr, "%s: cannot read token file %s\n", argv[0], tokenFile.c_str());
            return 1;
        }
        struct stat st {};
        if (stat(tokenFile.c_str(), &st) == 0 && (st.st_mode & 077) != 0)
            fprintf(stderr, "%s: warning: %s can be read by other users; chmod 600 it\n", argv[0],
                    tokenFile.c_str());
        size_t pos = 0;
        int lineNo = 0;
        while (pos < text.size()) {
            size_t end = text.find('\n', pos);
            std::string line = text.substr(pos, end == std::string::npos ? end : end - pos);
            pos = end == std::string::npos ? text.size() : end + 1;
            lineNo++;
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
            if (line.empty() || line[0] == '#') continue;
            size_t colon = line.find(':');
            if (colon == std::string::npos || colon == 0 || colon + 1 >= line.size()) {
                fprintf(stderr, "%s: %s line %d: expected NAME:TOKEN\n", argv[0], tokenFile.c_str(),
                        lineNo);
                return 2;
            }
            http.users.emplace_back(line.substr(0, colon), line.substr(colon + 1));
        }
    }

    // Normalise the endpoint path: leading slash, no trailing slash, URL-safe characters.
    while (http.endpoint.size() > 1 && http.endpoint.back() == '/') http.endpoint.pop_back();
    if (http.endpoint == "/") http.endpoint.clear();
    if (!http.endpoint.empty() && http.endpoint[0] != '/') http.endpoint.insert(0, "/");
    for (unsigned char ch : http.endpoint) {
        if (!isalnum(ch) && !strchr("/-_.~", ch)) {
            fprintf(stderr, "%s: invalid --endpoint '%s' (use letters, digits, / - _ . ~)\n",
                    argv[0], http.endpoint.c_str());
            return 2;
        }
    }

    if (action != Action::Serve) {
        const std::string host =
            http.host == "0.0.0.0" || http.host == "::" ? std::string("127.0.0.1") : http.host;
        if (reg.url.empty())
            reg.url = "http://" + (host.find(':') != std::string::npos ? "[" + host + "]" : host) +
                      ":" + std::to_string(http.port) + http.endpoint;
        reg.token = cliToken;
        if (action == Action::ListHarnesses) return listHarnesses(reg);
        return runRegistration(harnessList, action == Action::Unregister, reg);
    }

    // Resolve defaults.
    if (bridgeCfg.ghidraHome.empty())
        bridgeCfg.ghidraHome = newestMatch(util::homeDir() + "/ghidra-install/ghidra_*");
    if (bridgeCfg.ghidraHome.empty()) bridgeCfg.ghidraHome = newestMatch("/opt/ghidra*");
    if (bridgeCfg.ghidraHome.empty() ||
        !util::isFile(bridgeCfg.ghidraHome + "/support/analyzeHeadless")) {
        fprintf(stderr,
                "%s: no Ghidra installation found%s%s.\n"
                "Pass --ghidra-home DIR (the directory containing ghidraRun) or set "
                "GHIDRA_INSTALL_DIR.\n",
                argv[0], bridgeCfg.ghidraHome.empty() ? "" : " at ",
                bridgeCfg.ghidraHome.c_str());
        return 1;
    }
    if (bridgeCfg.javaHome.empty()) {
        bridgeCfg.javaHome = newestMatch("/usr/lib/jvm/temurin-21-*");
        if (bridgeCfg.javaHome.empty()) bridgeCfg.javaHome = newestMatch("/usr/lib/jvm/*-21-*");
    }
    if (bridgeCfg.projectDir.empty() || bridgeCfg.projectDir[0] != '/') {
        char cwd[4096];
        if (getcwd(cwd, sizeof cwd))
            bridgeCfg.projectDir = std::string(cwd) + "/" + bridgeCfg.projectDir;
    }
    // Ghidra refuses project locations with a path element that starts with '.'.
    if (bridgeCfg.projectDir.find("/.") != std::string::npos) {
        fprintf(stderr, "%s: --project-dir must not contain hidden ('.name') path elements: %s\n",
                argv[0], bridgeCfg.projectDir.c_str());
        return 1;
    }
    const char* xdgData = getenv("XDG_DATA_HOME");
    bridgeCfg.dataDir =
        (xdgData && *xdgData ? std::string(xdgData) : util::homeDir() + "/.local/share") +
        "/ghidra-mcp";
    if (uploadDir.empty()) uploadDir = bridgeCfg.projectDir + "/uploads";
    http.maxUploadBytes = static_cast<uint64_t>(maxUploadMb) << 20;

    struct sigaction sa {};
    sa.sa_handler = onSignal;  // no SA_RESTART: blocking reads return so we can shut down
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);

    Bridge bridge(bridgeCfg);
    McpConfig mcpCfg;
    mcpCfg.uploadDir = uploadDir;
    mcpCfg.httpUploads = !stdio;
    mcpCfg.endpoint = http.endpoint;
    mcpCfg.fallbackBaseUrl = "http://" + (http.host == "0.0.0.0" || http.host == "::"
                                              ? std::string("127.0.0.1")
                                              : http.host) +
                             ":" + std::to_string(http.port);
    McpServer mcp(bridge, mcpCfg);
    if (!auditPath.empty()) {
        std::string err;
        if (!mcp.audit.open(auditPath, err)) {
            fprintf(stderr, "%s: %s\n", argv[0], err.c_str());
            return 1;
        }
        mcp.audit.start(GHIDRA_MCP_VERSION, bridgeCfg.projectDir + "/" + bridgeCfg.projectName);
    }

    util::logInfo("ghidra-mcp %s, Ghidra at %s", GHIDRA_MCP_VERSION,
                  bridgeCfg.ghidraHome.c_str());

    HttpServer server(http, mcp);
    if (!stdio) {
        std::string err;
        if (!server.listen(err)) {
            fprintf(stderr, "%s: %s\n", argv[0], err.c_str());
            return 1;
        }
        util::logInfo("listening on http://%s:%d%s (streamable HTTP) and %s/sse (legacy SSE)",
                      http.host.c_str(), http.port,
                      http.endpoint.empty() ? "/" : http.endpoint.c_str(), http.endpoint.c_str());
        if (!isLoopback(http.host) && http.users.empty())
            util::logInfo("WARNING: reachable from the network without --token; anyone who can "
                          "connect can use Ghidra and upload files");
    }

    std::thread warmup;
    if (!lazy) {
        warmup = std::thread([&bridge] {
            std::string err;
            if (!bridge.start(err) && !gStop)
                util::logInfo("Ghidra failed to start: %s", err.c_str());
        });
    }

    if (stdio) {
        std::string line;
        while (!gStop && std::getline(std::cin, line)) {
            if (line.find_first_not_of(" \t\r") == std::string::npos) continue;
            std::string out = mcp.handle(line, "", CallContext{"stdio", ""});
            if (!out.empty()) {
                fwrite(out.data(), 1, out.size(), stdout);
                fputc('\n', stdout);
                fflush(stdout);
            }
        }
    } else {
        server.run(gStop);
    }

    util::logInfo("shutting down");
    bridge.stop();
    if (warmup.joinable()) warmup.join();
    bridge.stop();  // in case the warm-up finished starting Ghidra after the first stop
    return 0;
}
