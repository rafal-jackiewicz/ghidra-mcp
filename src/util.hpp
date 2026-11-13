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

namespace util {

extern bool verbose;

// Timestamped logging to stderr (stdout is reserved for the stdio transport).
void logInfo(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void logDebug(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

std::string homeDir();
bool isDir(const std::string& path);
bool isFile(const std::string& path);
bool makeDirs(const std::string& path, int mode = 0755);
bool readFile(const std::string& path, std::string& out);
bool writeFile(const std::string& path, const std::string& data, int mode = 0644);
std::string randomHex(size_t bytes);
std::string tailOfFile(const std::string& path, size_t maxBytes);

// Reduces an arbitrary client-supplied name to a safe file name (no directories).
std::string safeFileName(const std::string& name);
// Returns a path in dir for name that does not exist yet (adds -1, -2, ... if needed).
std::string uniquePath(const std::string& dir, const std::string& name);

bool base64Decode(const std::string& in, std::string& out);
std::string urlDecode(const std::string& in);
bool constantTimeEquals(const std::string& a, const std::string& b);

}  // namespace util
