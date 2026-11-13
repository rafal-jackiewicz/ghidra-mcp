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

#pragma once
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "mcp.hpp"

struct HttpConfig {
    std::string host = "127.0.0.1";
    int port = 8765;
    std::string endpoint = "/ghidra-mcp";  // URL path of the MCP endpoint; prefix of all others
    std::string token;                    // if set, required as "Authorization: Bearer <token>"
    uint64_t maxUploadBytes = 2048ull << 20;
};

// Minimal HTTP/1.1 server exposing MCP over Streamable HTTP (POST <endpoint>), the legacy
// HTTP+SSE transport (GET <endpoint>/sse, POST <endpoint>/messages) and ticketed binary uploads
// (PUT <endpoint>/upload/...).
class HttpServer {
public:
    HttpServer(HttpConfig cfg, McpServer& mcp);
    bool listen(std::string& err);
    void run(const std::atomic<bool>& stopFlag);  // returns when stopFlag becomes true

    struct SseSession {
        std::mutex mutex;
        int fd = -1;
        bool open = true;
    };

private:
    struct Request;
    class Conn;
    void serve(int fd);
    bool handle(Conn& c, Request& r);
    bool handleUpload(Conn& c, Request& r, const std::string& rest);
    bool handleSse(Conn& c, Request& r);
    bool handleSseMessage(Conn& c, Request& r);
    std::string baseUrl(const Request& r) const;

    HttpConfig cfg_;
    McpServer& mcp_;
    std::vector<int> listenFds_;
    std::mutex sseMutex_;
    std::map<std::string, std::shared_ptr<SseSession>> sse_;
};
