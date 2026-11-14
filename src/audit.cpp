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

#include "audit.hpp"

#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>

using nlohmann::json;

// ---------------------------------------------------------------- SHA-256 (FIPS 180-4)

namespace {

const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void compress(uint32_t h[8], const unsigned char* block) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
               (uint32_t(block[i * 4 + 2]) << 8) | uint32_t(block[i * 4 + 3]);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

std::string nowUtc() {
    char buf[32];
    time_t now = time(nullptr);
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

// The text that is hashed: the record without its own "hash" field, keys in sorted order.
std::string canonical(json record) {
    record.erase("hash");
    return record.dump(-1, ' ', false, json::error_handler_t::replace);
}

// Long values (an uploaded file, for instance) are recorded by size and digest only.
json abbreviate(const json& arguments) {
    json out = json::object();
    if (!arguments.is_object()) return out;
    for (auto it = arguments.begin(); it != arguments.end(); ++it) {
        if (it.value().is_string() && it.value().get_ref<const std::string&>().size() > 300) {
            const std::string& text = it.value().get_ref<const std::string&>();
            out[it.key()] = {{"bytes", text.size()}, {"sha256", sha256Hex(text)}};
        } else {
            out[it.key()] = it.value();
        }
    }
    return out;
}

}  // namespace

std::string sha256Hex(const std::string& data) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::string msg = data;
    const uint64_t bits = uint64_t(data.size()) * 8;
    msg += char(0x80);
    while (msg.size() % 64 != 56) msg += char(0);
    for (int i = 7; i >= 0; i--) msg += char((bits >> (i * 8)) & 0xff);
    for (size_t off = 0; off < msg.size(); off += 64)
        compress(h, reinterpret_cast<const unsigned char*>(msg.data()) + off);
    char out[65];
    for (int i = 0; i < 8; i++) snprintf(out + i * 8, 9, "%08x", h[i]);
    return std::string(out, 64);
}

// ---------------------------------------------------------------- the log

AuditLog::~AuditLog() {
    if (file_) fclose(file_);
}

bool AuditLog::open(const std::string& path, std::string& err) {
    // Continue an existing chain: the last line supplies the sequence number and the hash.
    std::ifstream in(path);
    std::string line, last;
    while (std::getline(in, line))
        if (!line.empty()) last = line;
    if (!last.empty()) {
        json record = json::parse(last, nullptr, false);
        if (record.is_discarded() || !record.contains("hash") || !record.contains("seq")) {
            err = path + " does not end with a valid audit record; refusing to append to it";
            return false;
        }
        seq_ = record["seq"].get<long long>();
        prev_ = record["hash"].get<std::string>();
    }
    file_ = fopen(path.c_str(), "a");
    if (!file_) {
        err = "cannot open audit log " + path + ": " + strerror(errno);
        return false;
    }
    return true;
}

void AuditLog::append(json record) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!file_) return;
    record["seq"] = ++seq_;
    record["time"] = nowUtc();
    record["prev"] = prev_;
    prev_ = sha256Hex(canonical(record));
    record["hash"] = prev_;
    const std::string line = record.dump(-1, ' ', false, json::error_handler_t::replace) + "\n";
    fwrite(line.data(), 1, line.size(), file_);
    fflush(file_);
    fsync(fileno(file_));
}

void AuditLog::start(const std::string& version, const std::string& project) {
    append({{"event", "server_start"}, {"version", version}, {"project", project}});
}

void AuditLog::denied(const std::string& client) {
    if (!file_) return;
    append({{"event", "access_denied"}, {"client", client}});
}

void AuditLog::toolCall(const CallContext& ctx, const std::string& tool, const json& arguments,
                        bool isError, const std::string& resultText) {
    if (!file_) return;
    append({{"event", "tool_call"},
            {"user", ctx.user},
            {"client", ctx.client},
            {"tool", tool},
            {"arguments", abbreviate(arguments)},
            {"is_error", isError},
            {"result_bytes", resultText.size()},
            {"result_sha256", sha256Hex(resultText)}});
}

int AuditLog::verify(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        fprintf(stderr, "ghidra-mcp: cannot read %s\n", path.c_str());
        return 1;
    }
    std::string line, prev(64, '0'), firstTime, lastTime;
    long long expected = 0, lineNo = 0, calls = 0, denied = 0;
    std::map<std::string, long long> perUser;
    while (std::getline(in, line)) {
        lineNo++;
        if (line.empty()) continue;
        expected++;
        json record = json::parse(line, nullptr, false);
        const char* problem = nullptr;
        if (record.is_discarded() || !record.is_object()) problem = "is not a JSON record";
        else if (record.value("seq", -1LL) != expected) problem = "has the wrong sequence number (a record is missing or out of order)";
        else if (record.value("prev", std::string()) != prev) problem = "does not continue the chain (an earlier record was removed or changed)";
        else if (record.value("hash", std::string()) != sha256Hex(canonical(record))) problem = "was altered after it was written";
        if (problem) {
            printf("BROKEN at line %lld: the record %s.\n", lineNo, problem);
            printf("%lld record(s) before it are intact.\n", expected - 1);
            return 1;
        }
        prev = record["hash"].get<std::string>();
        lastTime = record.value("time", std::string());
        if (firstTime.empty()) firstTime = lastTime;
        if (record.value("event", std::string()) == "access_denied") denied++;
        if (record.value("event", std::string()) == "tool_call") {
            calls++;
            perUser[record.value("user", std::string("?"))]++;
        }
    }
    printf("INTACT: %lld records, %lld tool calls, %s to %s\n", expected, calls,
           firstTime.empty() ? "-" : firstTime.c_str(), lastTime.empty() ? "-" : lastTime.c_str());
    for (const auto& u : perUser) printf("  %-20s %lld tool calls\n", u.first.c_str(), u.second);
    if (denied) printf("  %-20s %lld request(s) refused\n", "(no valid token)", denied);
    printf("last hash: %s\n", prev.c_str());
    return 0;
}
