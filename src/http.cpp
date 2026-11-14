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

#include "http.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <thread>

#include "util.hpp"

using util::logDebug;
using util::logInfo;

namespace {

const size_t kMaxHeaderBytes = 64 * 1024;
const uint64_t kMaxJsonBytes = 64ull << 20;

std::string lowerCase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return tolower(c); });
    return s;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool sendAll(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

bool sendAll(int fd, const std::string& s) { return sendAll(fd, s.data(), s.size()); }

// Host part of "host:port", "[v6]:port" or a URL authority, lower-cased.
std::string hostOnly(std::string authority) {
    authority = lowerCase(trim(authority));
    if (!authority.empty() && authority[0] == '[') {
        size_t end = authority.find(']');
        return end == std::string::npos ? authority : authority.substr(0, end + 1);
    }
    size_t colon = authority.rfind(':');
    return colon == std::string::npos ? authority : authority.substr(0, colon);
}

bool isLoopbackName(const std::string& h) {
    return h == "localhost" || h == "127.0.0.1" || h == "[::1]";
}

}  // namespace

struct HttpServer::Request {
    std::string method, path, query, version;
    std::string user = "anonymous";  // name of the token that authorised the request
    std::string peer;                // remote address
    std::map<std::string, std::string> headers;  // lower-case names
    std::string body;
    bool keepAlive = true;

    std::string header(const std::string& name) const {
        auto it = headers.find(name);
        return it == headers.end() ? "" : it->second;
    }
    std::string queryParam(const std::string& key) const {
        size_t pos = 0;
        while (pos < query.size()) {
            size_t amp = query.find('&', pos);
            std::string kv = query.substr(pos, amp == std::string::npos ? amp : amp - pos);
            size_t eq = kv.find('=');
            if (kv.substr(0, eq) == key)
                return eq == std::string::npos ? "" : util::urlDecode(kv.substr(eq + 1));
            if (amp == std::string::npos) break;
            pos = amp + 1;
        }
        return "";
    }
};

class HttpServer::Conn {
public:
    explicit Conn(int fd) : fd_(fd) {}
    int fd() const { return fd_; }

    // Reads one request head. Returns false on EOF, timeout or malformed input.
    bool readHead(Request& r) {
        size_t end;
        while ((end = buf_.find("\r\n\r\n")) == std::string::npos) {
            if (buf_.size() > kMaxHeaderBytes || !fill()) return false;
        }
        std::string head = buf_.substr(0, end);
        buf_.erase(0, end + 4);

        size_t lineEnd = head.find("\r\n");
        std::string first = head.substr(0, lineEnd);
        size_t s1 = first.find(' ');
        size_t s2 = first.rfind(' ');
        if (s1 == std::string::npos || s2 == s1) return false;
        r.method = first.substr(0, s1);
        std::string target = first.substr(s1 + 1, s2 - s1 - 1);
        r.version = first.substr(s2 + 1);
        size_t q = target.find('?');
        r.path = target.substr(0, q);
        r.query = q == std::string::npos ? "" : target.substr(q + 1);

        while (lineEnd != std::string::npos) {
            size_t start = lineEnd + 2;
            lineEnd = head.find("\r\n", start);
            std::string line = head.substr(start, lineEnd == std::string::npos ? lineEnd
                                                                               : lineEnd - start);
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            r.headers[lowerCase(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
        }
        std::string conn = lowerCase(r.header("connection"));
        r.keepAlive = r.version == "HTTP/1.1" ? conn.find("close") == std::string::npos
                                              : conn.find("keep-alive") != std::string::npos;
        return true;
    }

    // Streams the request body into sink. Returns 0 on success, otherwise an HTTP status.
    int readBody(const Request& r, uint64_t limit,
                 const std::function<bool(const char*, size_t)>& sink) {
        if (lowerCase(r.header("expect")).find("100-continue") != std::string::npos)
            sendAll(fd_, "HTTP/1.1 100 Continue\r\n\r\n");

        if (lowerCase(r.header("transfer-encoding")).find("chunked") != std::string::npos) {
            uint64_t total = 0;
            for (;;) {
                std::string line;
                if (!readLine(line)) return 400;
                uint64_t size = strtoull(line.c_str(), nullptr, 16);
                if (size == 0) {
                    while (readLine(line) && !line.empty()) {}  // trailers
                    return 0;
                }
                total += size;
                if (total > limit) return 413;
                int rc = readExact(size, sink);
                if (rc) return rc;
                if (!readLine(line)) return 400;
            }
        }
        std::string cl = r.header("content-length");
        if (cl.empty()) return 0;
        uint64_t len = strtoull(cl.c_str(), nullptr, 10);
        if (len > limit) return 413;
        return readExact(len, sink);
    }

    bool respond(int code, const char* reason, const std::string& contentType,
                 const std::string& body, bool keepAlive, const std::string& extraHeaders = "") {
        std::string head = "HTTP/1.1 " + std::to_string(code) + " " + reason + "\r\n";
        if (!contentType.empty()) head += "Content-Type: " + contentType + "\r\n";
        head += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        head += extraHeaders;
        head += keepAlive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n";
        return sendAll(fd_, head + body) && keepAlive;
    }

    bool text(int code, const char* reason, const std::string& msg, bool keepAlive) {
        return respond(code, reason, "text/plain; charset=utf-8", msg + "\n", keepAlive);
    }

private:
    bool fill() {
        char tmp[16384];
        for (;;) {
            ssize_t n = recv(fd_, tmp, sizeof tmp, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return false;
            buf_.append(tmp, static_cast<size_t>(n));
            return true;
        }
    }

    bool readLine(std::string& line) {
        size_t end;
        while ((end = buf_.find("\r\n")) == std::string::npos) {
            if (buf_.size() > kMaxHeaderBytes || !fill()) return false;
        }
        line = buf_.substr(0, end);
        buf_.erase(0, end + 2);
        return true;
    }

    int readExact(uint64_t len, const std::function<bool(const char*, size_t)>& sink) {
        while (len > 0) {
            if (buf_.empty() && !fill()) return 400;
            size_t take = static_cast<size_t>(std::min<uint64_t>(len, buf_.size()));
            if (!sink(buf_.data(), take)) return 500;
            buf_.erase(0, take);
            len -= take;
        }
        return 0;
    }

    int fd_;
    std::string buf_;
};

HttpServer::HttpServer(HttpConfig cfg, McpServer& mcp) : cfg_(std::move(cfg)), mcp_(mcp) {}

bool HttpServer::listen(std::string& err) {
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo* res = nullptr;
    const std::string port = std::to_string(cfg_.port);
    int rc = getaddrinfo(cfg_.host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0) {
        err = "cannot resolve " + cfg_.host + ": " + gai_strerror(rc);
        return false;
    }
    std::string lastError = "no usable address";
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (ai->ai_family == AF_INET6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0 || ::listen(fd, 64) != 0) {
            lastError = strerror(errno);
            close(fd);
            continue;
        }
        listenFds_.push_back(fd);
    }
    freeaddrinfo(res);
    if (listenFds_.empty()) {
        err = "cannot listen on " + cfg_.host + ":" + port + ": " + lastError;
        return false;
    }
    return true;
}

void HttpServer::run(const std::atomic<bool>& stopFlag) {
    std::vector<struct pollfd> pfds;
    for (int fd : listenFds_) pfds.push_back({fd, POLLIN, 0});
    while (!stopFlag) {
        int n = poll(pfds.data(), pfds.size(), 500);
        if (n <= 0) continue;
        for (auto& p : pfds) {
            if (!(p.revents & POLLIN)) continue;
            int fd = accept4(p.fd, nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) continue;
            std::thread([this, fd] { serve(fd); }).detach();
        }
    }
    for (int fd : listenFds_) close(fd);
    listenFds_.clear();
}

void HttpServer::serve(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    struct timeval rcv = {300, 0}, snd = {60, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv, sizeof rcv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &snd, sizeof snd);

    char peer[NI_MAXHOST] = "";
    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof addr;
    if (getpeername(fd, reinterpret_cast<struct sockaddr*>(&addr), &addrLen) == 0)
        getnameinfo(reinterpret_cast<struct sockaddr*>(&addr), addrLen, peer, sizeof peer, nullptr, 0,
                    NI_NUMERICHOST);

    Conn c(fd);
    for (;;) {
        Request r;
        if (!c.readHead(r)) break;
        r.peer = peer;
        logDebug("http %s %s", r.method.c_str(), r.path.c_str());
        bool keep;
        try {
            keep = handle(c, r);
        } catch (const std::exception& e) {
            logInfo("request failed: %s", e.what());
            c.text(500, "Internal Server Error", e.what(), false);
            keep = false;
        }
        if (!keep) break;
    }
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

std::string HttpServer::baseUrl(const Request& r) const {
    std::string host = r.header("host");
    bool ok = !host.empty() && host.size() < 256;
    for (unsigned char ch : host)
        ok = ok && (isalnum(ch) || ch == '.' || ch == '-' || ch == ':' || ch == '[' || ch == ']');
    return ok ? "http://" + host : "";
}

bool HttpServer::handle(Conn& c, Request& r) {
    const bool keep = r.keepAlive;

    if (r.path == "/health" && r.method == "GET") return c.text(200, "OK", "ok", keep);

    // Everything else lives under the configured endpoint; sub is the part after it.
    const std::string& ep = cfg_.endpoint;
    const std::string notFound = "ghidra-mcp endpoints: POST " + ep + " (streamable HTTP), GET " +
                                 ep + "/sse (legacy SSE)";
    if (r.path.compare(0, ep.size(), ep) != 0) return c.text(404, "Not Found", notFound, false);
    const std::string sub = r.path.substr(ep.size());
    if (!sub.empty() && sub[0] != '/') return c.text(404, "Not Found", notFound, false);

    if (sub == "/health" && r.method == "GET") return c.text(200, "OK", "ok", keep);

    // Uploads are authorised by their single-use ticket (see prepare_upload).
    if (sub.compare(0, 8, "/upload/") == 0) return handleUpload(c, r, sub.substr(8));

    // Browsers send Origin; refuse cross-site requests so a web page cannot drive Ghidra
    // through the user's browser (DNS rebinding / CSRF).
    std::string origin = r.header("origin");
    if (!origin.empty() && origin != "null") {
        size_t scheme = origin.find("://");
        std::string oh = hostOnly(scheme == std::string::npos ? origin : origin.substr(scheme + 3));
        if (!isLoopbackName(oh) && oh != hostOnly(r.header("host")))
            return c.text(403, "Forbidden", "cross-origin requests are not allowed", false);
    }

    if (!cfg_.users.empty()) {
        std::string auth = r.header("authorization");
        std::string given = auth.size() > 7 && lowerCase(auth.substr(0, 7)) == "bearer "
                                ? trim(auth.substr(7))
                                : "";
        bool known = false;
        for (const auto& user : cfg_.users) {  // compare against every token: no early exit
            if (util::constantTimeEquals(given, user.second) && !known) {
                known = true;
                r.user = user.first;
            }
        }
        if (!known) mcp_.audit.denied(r.peer);
        if (!known)
            return c.respond(401, "Unauthorized", "text/plain", "missing or wrong bearer token\n",
                             false, "WWW-Authenticate: Bearer\r\n");
    }

    if (sub.empty() || sub == "/") {
        if (r.method != "POST") {
            // No server-initiated stream and no sessions: only POST is offered.
            c.readBody(r, kMaxJsonBytes, [](const char*, size_t) { return true; });
            return c.respond(405, "Method Not Allowed", "text/plain", "use POST\n", keep,
                             "Allow: POST\r\n");
        }
        int rc = c.readBody(r, kMaxJsonBytes, [&](const char* d, size_t n) {
            r.body.append(d, n);
            return true;
        });
        if (rc) return c.text(rc, rc == 413 ? "Payload Too Large" : "Bad Request",
                              "bad request body", false);
        std::string out = mcp_.handle(r.body, baseUrl(r), CallContext{r.user, r.peer});
        if (out.empty()) return c.respond(202, "Accepted", "", "", keep);
        return c.respond(200, "OK", "application/json", out, keep);
    }
    if (sub == "/sse" && r.method == "GET") return handleSse(c, r);
    if (sub == "/messages" && r.method == "POST") return handleSseMessage(c, r);

    return c.text(404, "Not Found", notFound, false);
}

bool HttpServer::handleUpload(Conn& c, Request& r, const std::string& rest) {
    if (r.method != "PUT" && r.method != "POST")
        return c.text(405, "Method Not Allowed", "use PUT", false);
    std::string ticket = rest.substr(0, rest.find('/'));
    std::string dest;
    if (!mcp_.claimUpload(ticket, dest))
        return c.text(403, "Forbidden",
                      "unknown, used or expired upload URL; call prepare_upload again", false);

    const std::string part = dest + ".part";
    int fd = open(part.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return c.text(500, "Internal Server Error",
                      "cannot create " + part + ": " + strerror(errno), false);
    uint64_t total = 0;
    int rc = c.readBody(r, cfg_.maxUploadBytes, [&](const char* d, size_t n) {
        size_t off = 0;
        while (off < n) {
            ssize_t w = write(fd, d + off, n - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            off += static_cast<size_t>(w);
        }
        total += n;
        return true;
    });
    bool closed = close(fd) == 0;
    if (rc || !closed || total == 0 || rename(part.c_str(), dest.c_str()) != 0) {
        unlink(part.c_str());
        if (rc == 413)
            return c.text(413, "Payload Too Large",
                          "file exceeds the server's --max-upload-mb limit", false);
        if (rc == 0 && total == 0)
            return c.text(400, "Bad Request", "empty upload; call prepare_upload again", false);
        return c.text(rc == 400 ? 400 : 500, rc == 400 ? "Bad Request" : "Internal Server Error",
                      "upload failed; call prepare_upload again", false);
    }
    logInfo("received upload %s (%llu bytes)", dest.c_str(),
            static_cast<unsigned long long>(total));
    return c.text(200, "OK",
                  "Uploaded " + std::to_string(total) + " bytes.\nServer path: " + dest +
                      "\nNow call the import_binary tool with path=\"" + dest + "\".",
                  r.keepAlive);
}

static bool sseEvent(HttpServer::SseSession& s, const std::string& payload) {
    std::lock_guard<std::mutex> lock(s.mutex);
    return s.open && sendAll(s.fd, payload);
}

bool HttpServer::handleSse(Conn& c, Request&) {
    auto session = std::make_shared<SseSession>();
    session->fd = c.fd();
    const std::string id = util::randomHex(16);
    {
        std::lock_guard<std::mutex> lock(sseMutex_);
        sse_[id] = session;
    }
    bool ok = sendAll(c.fd(), "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                              "Cache-Control: no-cache\r\nConnection: close\r\n\r\n") &&
              sseEvent(*session, "event: endpoint\ndata: " + cfg_.endpoint + "/messages?sessionId=" + id + "\n\n");
    while (ok) {
        struct pollfd p = {c.fd(), POLLIN, 0};
        int n = poll(&p, 1, 15000);
        if (n == 0) {
            ok = sseEvent(*session, ": keepalive\n\n");
        } else if (n > 0) {
            char tmp[256];
            ssize_t got = recv(c.fd(), tmp, sizeof tmp, MSG_DONTWAIT);
            if (got == 0 || (got < 0 && errno != EAGAIN && errno != EINTR)) ok = false;
        } else if (errno != EINTR) {
            ok = false;
        }
    }
    {
        std::lock_guard<std::mutex> lock(sseMutex_);
        sse_.erase(id);
    }
    std::lock_guard<std::mutex> lock(session->mutex);
    session->open = false;  // responses still in flight must not touch the closed socket
    return false;
}

bool HttpServer::handleSseMessage(Conn& c, Request& r) {
    std::shared_ptr<SseSession> session;
    {
        std::lock_guard<std::mutex> lock(sseMutex_);
        auto it = sse_.find(r.queryParam("sessionId"));
        if (it != sse_.end()) session = it->second;
    }
    int rc = c.readBody(r, kMaxJsonBytes, [&](const char* d, size_t n) {
        r.body.append(d, n);
        return true;
    });
    if (rc) return c.text(rc, "Bad Request", "bad request body", false);
    if (!session) return c.text(404, "Not Found", "unknown SSE session", r.keepAlive);

    bool keep = c.respond(202, "Accepted", "text/plain", "Accepted\n", r.keepAlive);
    std::string out = mcp_.handle(r.body, baseUrl(r), CallContext{r.user, r.peer});
    if (!out.empty()) sseEvent(*session, "event: message\ndata: " + out + "\n\n");
    return keep;
}
