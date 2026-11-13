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

#include "util.hpp"

#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <mutex>
#include <sstream>

namespace util {

bool verbose = false;
static std::mutex logMutex;

static void vlog(const char* level, const char* fmt, va_list ap) {
    char stamp[32];
    time_t now = time(nullptr);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(stamp, sizeof stamp, "%H:%M:%S", &tmv);
    std::lock_guard<std::mutex> lock(logMutex);
    fprintf(stderr, "[%s] %s", stamp, level);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
}

void logInfo(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog("", fmt, ap);
    va_end(ap);
}

void logDebug(const char* fmt, ...) {
    if (!verbose) return;
    va_list ap;
    va_start(ap, fmt);
    vlog("debug: ", fmt, ap);
    va_end(ap);
}

std::string homeDir() {
    const char* h = getenv("HOME");
    if (h && *h) return h;
    struct passwd* pw = getpwuid(getuid());
    return pw && pw->pw_dir ? pw->pw_dir : "/tmp";
}

bool isDir(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool isFile(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool makeDirs(const std::string& path, int mode) {
    if (path.empty()) return false;
    if (isDir(path)) return true;
    size_t slash = path.find_last_of('/');
    if (slash != std::string::npos && slash > 0 && !makeDirs(path.substr(0, slash), mode))
        return false;
    return mkdir(path.c_str(), mode) == 0 || errno == EEXIST;
}

bool readFile(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

bool writeFile(const std::string& path, const std::string& data, int mode) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = write(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return close(fd) == 0;
}

std::string randomHex(size_t bytes) {
    std::string raw(bytes, '\0');
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    size_t got = 0;
    if (fd >= 0) {
        while (got < bytes) {
            ssize_t n = read(fd, &raw[got], bytes - got);
            if (n <= 0) break;
            got += static_cast<size_t>(n);
        }
        close(fd);
    }
    if (got < bytes) {
        fprintf(stderr, "ghidra-mcp: cannot read /dev/urandom\n");
        exit(1);
    }
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (unsigned char c : raw) {
        out += digits[c >> 4];
        out += digits[c & 15];
    }
    return out;
}

std::string tailOfFile(const std::string& path, size_t maxBytes) {
    std::string all;
    if (!readFile(path, all)) return "";
    if (all.size() <= maxBytes) return all;
    size_t start = all.size() - maxBytes;
    size_t nl = all.find('\n', start);
    return all.substr(nl == std::string::npos ? start : nl + 1);
}

std::string safeFileName(const std::string& name) {
    size_t slash = name.find_last_of("/\\");
    std::string base = slash == std::string::npos ? name : name.substr(slash + 1);
    std::string out;
    for (unsigned char c : base) {
        if (isalnum(c) || c == '.' || c == '-' || c == '_' || c == '+')
            out += static_cast<char>(c);
        else
            out += '_';
    }
    while (!out.empty() && out[0] == '.') out.erase(0, 1);
    if (out.size() > 150) out.resize(150);
    return out.empty() ? "upload.bin" : out;
}

std::string uniquePath(const std::string& dir, const std::string& name) {
    std::string candidate = dir + "/" + name;
    struct stat st;
    for (int i = 1; lstat(candidate.c_str(), &st) == 0; i++) {
        size_t dot = name.find_last_of('.');
        if (dot == std::string::npos || dot == 0)
            candidate = dir + "/" + name + "-" + std::to_string(i);
        else
            candidate = dir + "/" + name.substr(0, dot) + "-" + std::to_string(i) + name.substr(dot);
    }
    return candidate;
}

bool base64Decode(const std::string& in, std::string& out) {
    out.clear();
    unsigned acc = 0;
    int bits = 0;
    for (unsigned char c : in) {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+' || c == '-') v = 62;
        else if (c == '/' || c == '_') v = 63;
        else if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        else return false;
        acc = (acc << 6) | static_cast<unsigned>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xff);
        }
    }
    return true;
}

std::string urlDecode(const std::string& in) {
    std::string out;
    for (size_t i = 0; i < in.size(); i++) {
        if (in[i] == '%' && i + 2 < in.size() && isxdigit(static_cast<unsigned char>(in[i + 1])) &&
            isxdigit(static_cast<unsigned char>(in[i + 2]))) {
            out += static_cast<char>(strtol(in.substr(i + 1, 2).c_str(), nullptr, 16));
            i += 2;
        } else if (in[i] == '+') {
            out += ' ';
        } else {
            out += in[i];
        }
    }
    return out;
}

bool constantTimeEquals(const std::string& a, const std::string& b) {
    unsigned char diff = a.size() == b.size() ? 0 : 1;
    for (size_t i = 0; i < a.size(); i++)
        diff |= static_cast<unsigned char>(a[i] ^ (b.empty() ? 0 : b[i % b.size()]));
    return diff == 0;
}

}  // namespace util
