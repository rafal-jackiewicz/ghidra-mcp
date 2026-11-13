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
#include <string>

// Registers / unregisters this MCP server in the user-level configuration of LLM harnesses.
struct RegisterOptions {
    std::string name = "ghidra";  // server name shown in the harness
    std::string url;              // e.g. http://127.0.0.1:8765/ghidra-mcp
    std::string token;            // optional bearer token to store with the entry
    bool dryRun = false;          // report what would change, write nothing
};

// list: comma-separated harness keys, or "all"/"" for every harness detected on this machine.
// Returns a process exit code.
int runRegistration(const std::string& list, bool unregister, const RegisterOptions& opt);

// Prints the supported harnesses, their config files and whether the server is registered.
int listHarnesses(const RegisterOptions& opt);

// Comma-separated keys of all supported harnesses (for --help).
std::string harnessKeys();
