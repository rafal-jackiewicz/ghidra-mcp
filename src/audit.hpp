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
#include <nlohmann/json.hpp>

#include <cstdio>
#include <mutex>
#include <string>

// Who is calling: filled in by the transport, written into the audit log.
struct CallContext {
    std::string user = "local";  // name from the token file, "default" for --token, "stdio"
    std::string client;          // remote address, empty for stdio
};

// SHA-256 of data, as 64 lower-case hex digits.
std::string sha256Hex(const std::string& data);

// An append-only record of every tool call. Each line is a JSON object that contains the
// hash of the line before it, so that removing or altering a line breaks the chain and is
// detected by verify().
class AuditLog {
public:
    ~AuditLog();
    // Opens (or continues) the log. Returns false and fills err on failure.
    bool open(const std::string& path, std::string& err);
    bool enabled() const { return file_ != nullptr; }

    void start(const std::string& version, const std::string& project);
    // A request that presented no token, or one that is not on the list.
    void denied(const std::string& client);
    void toolCall(const CallContext& ctx, const std::string& tool, const nlohmann::json& arguments,
                  bool isError, const std::string& resultText);

    // Checks a log file. Prints a verdict and returns a process exit code.
    static int verify(const std::string& path);

private:
    void append(nlohmann::json record);

    std::mutex mutex_;
    FILE* file_ = nullptr;
    long long seq_ = 0;
    std::string prev_ = std::string(64, '0');
};
