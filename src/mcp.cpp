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

#include "mcp.hpp"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstring>
#include <vector>

#include "util.hpp"
#include "version.hpp"

using nlohmann::json;

namespace {

const char* const kProtocolVersions[] = {"2025-06-18", "2025-03-26", "2024-11-05"};

struct Param {
    const char* name;
    const char* type;  // JSON schema type
    const char* description;
    bool required;
};

struct Tool {
    const char* name;
    const char* description;
    std::vector<Param> params;
    bool readOnly;
    bool takesProgram;  // accepts the optional "program" argument
};

const Param kOffset = {"offset", "integer", "Number of entries to skip (default 0).", false};
const Param kLimit = {"limit", "integer", "Maximum entries to return (default 100).", false};

const std::vector<Tool>& tools() {
    static const std::vector<Tool> list = {
        {"list_programs",
         "List the binaries already imported into the Ghidra project, and which one is current.",
         {}, true, false},
        {"import_binary",
         "Import a binary into Ghidra, run auto-analysis and make it the current program. "
         "Ghidra detects ELF, PE (Windows .exe/.dll/.sys), Mach-O, DEX, COFF, Intel HEX and "
         "more by itself. For raw firmware/shellcode pass 'language' and 'base_address'. "
         "'path' is a path on the machine where the ghidra-mcp server runs; if the file is on "
         "another machine (for example you run inside a VM), call prepare_upload first. "
         "Analysis of a large binary can take minutes.",
         {{"path", "string", "Path of the file on the Ghidra host.", true},
          {"language", "string",
           "Ghidra language ID, e.g. x86:LE:64:default, ARM:LE:32:Cortex, "
           "AARCH64:LE:64:v8A. Only needed for raw binaries or to override detection; see "
           "list_languages.",
           false},
          {"compiler", "string", "Compiler spec ID, e.g. gcc, windows, default.", false},
          {"base_address", "string",
           "Load address for a raw binary, e.g. 0x08000000. Implies raw import.", false},
          {"raw_binary", "boolean", "Force the raw binary loader (requires 'language').", false},
          {"name", "string", "Name for the program inside the project (default: file name).",
           false},
          {"analyze", "boolean", "Run auto-analysis after import (default true).", false}},
         false, false},
        {"open_program",
         "Make a program from the project the current one. Other tools act on the current "
         "program unless given 'program'.",
         {{"name", "string", "Program name or project path from list_programs.", true}},
         false, false},
        {"close_program", "Close a program (it stays in the project).", {}, false, true},
        {"delete_program", "Permanently remove a program and its analysis from the project.",
         {{"name", "string", "Program name or project path from list_programs.", true}},
         false, false},
        {"analyze_program", "Run (or re-run) Ghidra auto-analysis on a program.", {}, false,
         true},
        {"program_info",
         "Show format, processor, compiler, image base, size, hashes and analysis state.", {},
         true, true},
        {"list_languages",
         "List Ghidra processor language IDs (and their compiler specs) for raw imports.",
         {{"filter", "string", "Case-insensitive substring, e.g. arm, tricore, powerpc.", false},
          kOffset, kLimit},
         true, false},
        {"list_functions", "List functions with entry address and size.",
         {{"filter", "string", "Case-insensitive substring of the function name.", false},
          kOffset, kLimit},
         true, true},
        {"function_info",
         "Show a function's signature, parameters, locals, callers and callees.",
         {{"function", "string", "Function name or any address inside it.", true}}, true, true},
        {"decompile_function", "Decompile a function to C pseudocode.",
         {{"function", "string", "Function name or any address inside it.", true},
          {"timeout", "integer", "Decompiler timeout in seconds (default 60).", false}},
         true, true},
        {"disassemble", "Disassemble instructions starting at an address or symbol.",
         {{"address", "string", "Start address (0x...) or symbol/function name.", true},
          {"count", "integer", "Number of instructions (default 40).", false},
          {"whole_function", "boolean",
           "Disassemble the entire function containing the address.", false}},
         true, true},
        {"list_strings", "List strings found in the program, with their addresses.",
         {{"filter", "string", "Case-insensitive substring of the string.", false},
          {"min_length", "integer", "Minimum string length (default 1).", false},
          kOffset, kLimit},
         true, true},
        {"search_symbols", "Search all symbols (functions, labels, data, imports) by name.",
         {{"query", "string", "Case-insensitive substring of the symbol name.", false},
          kOffset, kLimit},
         true, true},
        {"list_imports", "List imported (external) symbols and the libraries they come from.",
         {{"filter", "string", "Case-insensitive substring.", false}, kOffset, kLimit},
         true, true},
        {"list_exports", "List exported symbols / entry points.",
         {{"filter", "string", "Case-insensitive substring.", false}, kOffset, kLimit},
         true, true},
        {"list_segments", "List memory blocks (sections/segments) with ranges and permissions.",
         {}, true, true},
        {"xrefs_to", "List cross-references to an address or symbol (who calls/reads/writes it).",
         {{"address", "string", "Target address (0x...) or symbol name.", true}, kOffset,
          kLimit},
         true, true},
        {"xrefs_from", "List references going out of an instruction/data item or function.",
         {{"address", "string", "Source address (0x...) or symbol name.", true},
          {"whole_function", "boolean",
           "List references from the entire function containing the address.", false},
          kOffset, kLimit},
         true, true},
        {"read_memory", "Hex dump of program memory.",
         {{"address", "string", "Start address (0x...) or symbol name.", true},
          {"length", "integer", "Number of bytes (default 64, max 65536).", false}},
         true, true},
        {"search_bytes", "Search program memory for a byte pattern.",
         {{"pattern", "string",
           "Hex bytes, ?? for a wildcard byte, e.g. \"e8 ?? ?? ?? ?? 85 c0\".", true},
          {"limit", "integer", "Maximum matches (default 50).", false}},
         true, true},
        {"rename_function", "Rename a function.",
         {{"function", "string", "Current function name or address.", true},
          {"new_name", "string", "New name.", true}},
         false, true},
        {"rename_variable",
         "Rename a parameter or local variable of a function (as shown by decompile_function).",
         {{"function", "string", "Function name or address.", true},
          {"old_name", "string", "Current variable name.", true},
          {"new_name", "string", "New variable name.", true}},
         false, true},
        {"set_function_signature",
         "Set a function's prototype (return type, name, parameters) from a C declaration.",
         {{"function", "string", "Function name or address.", true},
          {"signature", "string", "C prototype, e.g. \"int check(char *key, int len)\".", true}},
         false, true},
        {"create_label", "Create (or replace) the primary label at an address.",
         {{"address", "string", "Address (0x...).", true},
          {"name", "string", "Label name.", true}},
         false, true},
        {"set_comment", "Set or clear a comment at an address.",
         {{"address", "string", "Address (0x...) or symbol name.", true},
          {"comment", "string", "Comment text; empty clears the comment.", true},
          {"type", "string",
           "eol (default), pre (shown in the decompiler), post, plate or repeatable.", false}},
         false, true},
        {"define_type",
         "Define a C structure, union, enum or typedef in the program so that function "
         "signatures and the decompiler can use it. Returns the layout with field offsets.",
         {{"declaration", "string",
           "C declaration, e.g. \"struct Point { int x; int y; };\". Fixed-width names "
           "such as uint8_t and uint32_t are understood.",
           true}},
         false, true},
        {"set_variable_type",
         "Give a parameter or local variable of a function a data type, for example a "
         "structure created with define_type. Decompile again afterwards.",
         {{"function", "string", "Function name or address.", true},
          {"variable", "string", "Current variable name, as shown by decompile_function.", true},
          {"type", "string", "Type, e.g. \"Passenger\", \"Passenger *\", \"char[24]\".", true}},
         false, true},
        {"set_data_type",
         "Apply a data type to a global address, for example turn a block of bytes into an "
         "array of structures so that code using it becomes readable.",
         {{"address", "string", "Address (0x...) or symbol name of the data.", true},
          {"type", "string", "Type, e.g. \"Record[64]\", \"uint\", \"char *[5]\".", true}},
         false, true},
        {"create_function",
         "Disassemble at an address and define a function there (useful for raw firmware).",
         {{"address", "string", "Entry address (0x...).", true},
          {"name", "string", "Optional function name.", false}},
         false, true},
    };
    return list;
}

json toolSchema(const std::vector<Param>& params, bool takesProgram) {
    json props = json::object();
    json required = json::array();
    for (const Param& p : params) {
        props[p.name] = {{"type", p.type}, {"description", p.description}};
        if (p.required) required.push_back(p.name);
    }
    if (takesProgram) {
        props["program"] = {{"type", "string"},
                            {"description",
                             "Program name from list_programs (default: the current program)."}};
    }
    json schema = {{"type", "object"}, {"properties", props}};
    if (!required.empty()) schema["required"] = required;
    return schema;
}

json toolEntry(const char* name, const char* description, const json& schema, bool readOnly) {
    return {{"name", name},
            {"description", description},
            {"inputSchema", schema},
            {"annotations", {{"readOnlyHint", readOnly}, {"openWorldHint", false}}}};
}

json textResult(const std::string& text, bool isError) {
    return {{"content", json::array({{{"type", "text"}, {"text", text}}})},
            {"isError", isError}};
}

json rpcError(const json& id, int code, const std::string& message) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", message}}}};
}

std::string argToString(const json& v) {
    if (v.is_string()) return v.get<std::string>();
    if (v.is_boolean()) return v.get<bool>() ? "true" : "false";
    if (v.is_null()) return "";
    return v.dump();
}

std::string dump(const json& j) {
    // Ghidra output can contain bytes that are not valid UTF-8; replace instead of throwing.
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

}  // namespace

struct McpDispatch {
    McpServer& s;
    const std::string& baseUrl;

    std::string uploadBase() const { return baseUrl.empty() ? s.cfg_.fallbackBaseUrl : baseUrl; }

    std::string instructions() const {
        std::string text =
            "This server gives you a Ghidra reverse-engineering session running on the server "
            "host. Typical flow: list_programs -> import_binary (or open_program) -> "
            "list_functions / list_strings / list_imports -> decompile_function, xrefs_to, "
            "disassemble -> rename_function, rename_variable, set_comment to record findings. "
            "Tools act on the current program; changes are saved to the Ghidra project.\n"
            "import_binary takes a path on the server host. ";
        if (s.cfg_.httpUploads) {
            text += "If the binary is on a different machine than the server (for example you "
                    "are running inside a virtual machine or on another OS), call "
                    "prepare_upload: it returns a one-line curl command that sends the file to "
                    "the server and tells you the path to import. upload_binary (base64) works "
                    "for files of a few kilobytes.";
        } else {
            text += "upload_binary (base64) can transfer small files that are not on the host.";
        }
        return text;
    }

    json prepareUpload(const json& args) {
        std::string fileName =
            util::safeFileName(args.value("filename", std::string("upload.bin")));
        std::string ticket = util::randomHex(16);
        {
            std::lock_guard<std::mutex> lock(s.ticketMutex_);
            time_t now = time(nullptr);
            for (auto it = s.tickets_.begin(); it != s.tickets_.end();)
                it = it->second.expires < now ? s.tickets_.erase(it) : std::next(it);
            s.tickets_[ticket] = {fileName, now + 3600};
        }
        std::string url = uploadBase() + s.cfg_.endpoint + "/upload/" + ticket + "/" + fileName;
        std::string text =
            "Upload the file from the machine where it is stored with ONE of these commands "
            "(replace FILE with its local path), then read the response: it contains the "
            "server-side path to pass to import_binary.\n\n"
            "Linux / macOS:\n  curl -sS -T FILE '" + url + "'\n\n"
            "Windows (cmd or PowerShell; note curl.exe):\n  curl.exe -sS -T \"FILE\" \"" + url +
            "\"\n\n"
            "Windows PowerShell without curl:\n  (Invoke-WebRequest -UseBasicParsing -Method "
            "Put -InFile \"FILE\" -Uri \"" + url + "\").Content\n\n"
            "The URL is single-use and valid for one hour. If the host name in the URL is not "
            "reachable from that machine, replace it with the address you use to reach this "
            "MCP server (from a QEMU guest with user-mode networking that is 10.0.2.2).";
        return textResult(text, false);
    }

    json uploadBinary(const json& args) {
        if (!args.contains("content_base64") || !args["content_base64"].is_string())
            return textResult("Missing required argument 'content_base64'.", true);
        std::string data;
        if (!util::base64Decode(args["content_base64"].get<std::string>(), data))
            return textResult("content_base64 is not valid base64.", true);
        if (!util::makeDirs(s.cfg_.uploadDir))
            return textResult("Cannot create " + s.cfg_.uploadDir + ": " + strerror(errno), true);
        std::string path = util::uniquePath(
            s.cfg_.uploadDir, util::safeFileName(args.value("filename", std::string("upload.bin"))));
        if (!util::writeFile(path, data, 0600))
            return textResult("Cannot write " + path + ": " + strerror(errno), true);
        return textResult("Stored " + std::to_string(data.size()) + " bytes at " + path +
                              "\nNow call import_binary with path=\"" + path + "\".",
                          false);
    }

    json listTools() {
        json arr = json::array();
        for (const Tool& t : tools())
            arr.push_back(toolEntry(t.name, t.description, toolSchema(t.params, t.takesProgram),
                                    t.readOnly));
        if (s.cfg_.httpUploads) {
            arr.push_back(toolEntry(
                "prepare_upload",
                "Get a one-line command (curl / PowerShell) that uploads a binary from the "
                "machine you are running on to the Ghidra host. Use this when the file to "
                "analyse is not on the Ghidra host, e.g. inside a Windows, macOS or Linux VM. "
                "After running the command, pass the returned path to import_binary.",
                toolSchema({{"filename", "string", "File name of the binary, e.g. app.exe.",
                             true}},
                           false),
                false));
        }
        arr.push_back(toolEntry(
            "upload_binary",
            "Send a small file (a few KB) to the Ghidra host as base64 and get the path to "
            "import. For anything larger use prepare_upload or a path on the host.",
            toolSchema({{"filename", "string", "File name, e.g. sample.bin.", true},
                        {"content_base64", "string", "File content, base64 encoded.", true}},
                       false),
            false));
        return {{"tools", arr}};
    }

    json callTool(const json& params) {
        if (!params.is_object() || !params.contains("name") || !params["name"].is_string())
            throw std::invalid_argument("tools/call requires a string 'name'");
        const std::string name = params["name"].get<std::string>();
        json args = params.value("arguments", json::object());
        if (args.is_null()) args = json::object();
        if (!args.is_object()) throw std::invalid_argument("'arguments' must be an object");

        if (name == "prepare_upload" && s.cfg_.httpUploads) return prepareUpload(args);
        if (name == "upload_binary") return uploadBinary(args);

        for (const Tool& t : tools()) {
            if (name != t.name) continue;
            for (const Param& p : t.params) {
                if (p.required && (!args.contains(p.name) || args[p.name].is_null()))
                    return textResult(std::string("Missing required argument '") + p.name +
                                          "' for " + name + ".",
                                      true);
            }
            Bridge::Args bargs;
            for (auto it = args.begin(); it != args.end(); ++it) {
                if (it.key().find_first_of("=\t\n\r") != std::string::npos) continue;
                bargs.emplace_back(it.key(), argToString(it.value()));
            }
            Bridge::Result r = s.bridge_.call(name, bargs);
            return textResult(r.text.empty() ? "(no output)" : r.text, !r.ok);
        }
        throw std::invalid_argument("Unknown tool: " + name);
    }

    // Returns true and fills out when the message needs a response.
    bool one(const json& msg, json& out) {
        if (!msg.is_object() || !msg.contains("method") || !msg["method"].is_string()) {
            if (msg.is_object() && (msg.contains("result") || msg.contains("error")))
                return false;  // a response to something we never asked; ignore
            out = rpcError(nullptr, -32600, "Invalid Request");
            return true;
        }
        const std::string method = msg["method"].get<std::string>();
        const bool hasId = msg.contains("id") && !msg["id"].is_null();
        const json id = hasId ? msg["id"] : json(nullptr);
        const json params = msg.value("params", json::object());
        util::logDebug("rpc %s", method.c_str());

        json result;
        try {
            if (method == "initialize") {
                std::string version = kProtocolVersions[0];
                if (params.is_object() && params.contains("protocolVersion") &&
                    params["protocolVersion"].is_string()) {
                    for (const char* v : kProtocolVersions)
                        if (params["protocolVersion"] == v) version = v;
                }
                result = {{"protocolVersion", version},
                          {"capabilities", {{"tools", {{"listChanged", false}}}}},
                          {"serverInfo",
                           {{"name", "ghidra-mcp"},
                            {"title", "Ghidra"},
                            {"version", GHIDRA_MCP_VERSION}}},
                          {"instructions", instructions()}};
            } else if (method == "ping") {
                result = json::object();
            } else if (method == "tools/list") {
                result = listTools();
            } else if (method == "tools/call") {
                result = callTool(params);
            } else if (method == "resources/list") {
                result = {{"resources", json::array()}};
            } else if (method == "resources/templates/list") {
                result = {{"resourceTemplates", json::array()}};
            } else if (method == "prompts/list") {
                result = {{"prompts", json::array()}};
            } else if (!hasId) {
                return false;  // notifications (initialized, cancelled, ...) need no answer
            } else {
                out = rpcError(id, -32601, "Method not found: " + method);
                return true;
            }
        } catch (const std::invalid_argument& e) {
            if (!hasId) return false;
            out = rpcError(id, -32602, e.what());
            return true;
        } catch (const std::exception& e) {
            if (!hasId) return false;
            out = rpcError(id, -32603, e.what());
            return true;
        }
        if (!hasId) return false;
        out = {{"jsonrpc", "2.0"}, {"id", id}, {"result", result}};
        return true;
    }
};

McpServer::McpServer(Bridge& bridge, McpConfig cfg) : bridge_(bridge), cfg_(std::move(cfg)) {}

std::string McpServer::handle(const std::string& body, const std::string& baseUrl) {
    json msg = json::parse(body, nullptr, false);
    if (msg.is_discarded()) return dump(rpcError(nullptr, -32700, "Parse error"));

    McpDispatch d{*this, baseUrl};
    json out;
    if (msg.is_array()) {
        if (msg.empty()) return dump(rpcError(nullptr, -32600, "Invalid Request"));
        json responses = json::array();
        for (const json& m : msg)
            if (d.one(m, out)) responses.push_back(out);
        return responses.empty() ? std::string() : dump(responses);
    }
    return d.one(msg, out) ? dump(out) : std::string();
}

bool McpServer::claimUpload(const std::string& ticket, std::string& destPath) {
    std::string fileName;
    {
        std::lock_guard<std::mutex> lock(ticketMutex_);
        auto it = tickets_.find(ticket);
        if (it == tickets_.end() || it->second.expires < time(nullptr)) return false;
        fileName = it->second.fileName;
        tickets_.erase(it);
    }
    if (!util::makeDirs(cfg_.uploadDir)) return false;
    destPath = util::uniquePath(cfg_.uploadDir, fileName);
    return true;
}
