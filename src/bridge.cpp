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

#include "bridge.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "bridge_script.hpp"
#include "util.hpp"

using util::logDebug;
using util::logInfo;

static const char* kScriptName = "GhidraMcpBridge.java";

Bridge::Bridge(BridgeConfig cfg) : cfg_(std::move(cfg)) {}

Bridge::~Bridge() { stop(); }

static std::string encodeValue(const std::string& v) {
    std::string out;
    for (unsigned char c : v) {
        if (c == '%' || c == '\t' || c == '\n' || c == '\r' || c == 0) {
            char buf[4];
            snprintf(buf, sizeof buf, "%%%02X", c);
            out += buf;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

static void sleepMs(int ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, nullptr);
}

bool Bridge::start(std::string& err) {
    std::lock_guard<std::mutex> lock(mutex_);
    return startLocked(err);
}

bool Bridge::startLocked(std::string& err) {
    if (child_ > 0 && sock_ >= 0) {
        int status;
        if (waitpid(child_, &status, WNOHANG) == 0) return true;
        child_ = -1;
        teardownLocked(false);
    } else if (child_ > 0 || sock_ >= 0) {
        teardownLocked(false);
    }

    const std::string launcher = cfg_.ghidraHome + "/support/analyzeHeadless";
    if (access(launcher.c_str(), X_OK) != 0) {
        err = "Ghidra launcher not found or not executable: " + launcher +
              " (set --ghidra-home or GHIDRA_INSTALL_DIR)";
        return false;
    }

    // The bridge script is embedded in this binary; keep an up-to-date copy on disk so
    // Ghidra can compile it (and reuse its compiled bundle between runs).
    const std::string scriptDir = cfg_.dataDir + "/scripts";
    const std::string scriptPath = scriptDir + "/" + kScriptName;
    std::string existing;
    if (!util::makeDirs(scriptDir) || !util::makeDirs(cfg_.projectDir)) {
        err = "Cannot create directory " + scriptDir + " or " + cfg_.projectDir + ": " +
              strerror(errno);
        return false;
    }
    if (!util::readFile(scriptPath, existing) || existing != kBridgeScript) {
        if (!util::writeFile(scriptPath, kBridgeScript)) {
            err = "Cannot write " + scriptPath + ": " + strerror(errno);
            return false;
        }
    }

    const char* xdg = getenv("XDG_RUNTIME_DIR");
    std::string tmpl = std::string(xdg && *xdg ? xdg : "/tmp") + "/ghidra-mcp-XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (!mkdtemp(buf.data())) {
        err = std::string("mkdtemp failed: ") + strerror(errno);
        return false;
    }
    runDir_ = buf.data();
    token_ = util::randomHex(24);
    if (!util::writeFile(runDir_ + "/token", token_, 0600)) {
        err = "Cannot write token file in " + runDir_;
        teardownLocked(false);
        return false;
    }

    const std::string log = logPath();
    logInfo("starting Ghidra headless (project %s/%s, log %s)", cfg_.projectDir.c_str(),
            cfg_.projectName.c_str(), log.c_str());

    pid_t pid = fork();
    if (pid < 0) {
        err = std::string("fork failed: ") + strerror(errno);
        teardownLocked(false);
        return false;
    }
    if (pid == 0) {
        setsid();  // own process group, so the launcher shell and the JVM can be stopped together
        int devnull = open("/dev/null", O_RDONLY);
        int logfd = open(log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (devnull >= 0) dup2(devnull, 0);
        if (logfd >= 0) {
            dup2(logfd, 1);
            dup2(logfd, 2);
        }
        for (int fd = 3; fd < 1024; fd++) close(fd);
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        if (!cfg_.javaHome.empty()) setenv("JAVA_HOME", cfg_.javaHome.c_str(), 1);
        execl(launcher.c_str(), launcher.c_str(), cfg_.projectDir.c_str(),
              cfg_.projectName.c_str(), "-scriptPath", scriptDir.c_str(), "-postScript",
              kScriptName, runDir_.c_str(), static_cast<char*>(nullptr));
        dprintf(2, "exec %s failed: %s\n", launcher.c_str(), strerror(errno));
        _exit(127);
    }
    child_ = pid;

    // Wait for the script to publish its port.
    const std::string portFile = runDir_ + "/port";
    std::string portText;
    time_t deadline = time(nullptr) + cfg_.startupTimeoutSec;
    unsigned polls = 0;
    for (;;) {
        if (util::readFile(portFile, portText) && !portText.empty()) break;
        int status;
        if (waitpid(child_, &status, WNOHANG) == child_.load()) {
            child_ = -1;
            std::string tail = util::tailOfFile(log, 6000);
            if (tail.find("Unable to lock project") != std::string::npos)
                err = "Ghidra exited during startup: the project " + cfg_.projectDir + "/" +
                      cfg_.projectName + " is in use by another process (the Ghidra window, or "
                      "another ghidra-mcp). Close it there, or choose another --project-name.";
            else
                err = "Ghidra exited during startup. Last lines of " + log + ":\n" +
                      util::tailOfFile(log, 3000);
            teardownLocked(false);
            return false;
        }
        if (stopping_) {
            err = "shutting down";
            teardownLocked(false);
            return false;
        }
        // A project that is open elsewhere makes Ghidra report a lock error and then sit there
        // instead of exiting. Do not wait out the whole timeout for that.
        if (++polls % 10 == 0) {
            std::string tail = util::tailOfFile(log, 6000);
            if (tail.find("LockException") != std::string::npos ||
                tail.find("Unable to lock project") != std::string::npos) {
                err = "The Ghidra project " + cfg_.projectDir + "/" + cfg_.projectName +
                      " is in use by another process (the Ghidra window, or another ghidra-mcp). "
                      "Close it there, or choose another --project-name.";
                teardownLocked(false);
                return false;
            }
        }
        if (time(nullptr) > deadline) {
            err = "Ghidra did not become ready within " +
                  std::to_string(cfg_.startupTimeoutSec) + " s. Last lines of " + log + ":\n" +
                  util::tailOfFile(log, 3000);
            teardownLocked(false);
            return false;
        }
        sleepMs(100);
    }

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in sa {};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(atoi(portText.c_str())));
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof sa) != 0) {
        err = std::string("Cannot connect to the Ghidra bridge: ") + strerror(errno);
        if (fd >= 0) close(fd);
        teardownLocked(false);
        return false;
    }
    sock_ = fd;

    Result pong;
    if (!exchange(token_ + "\tping\n", pong) || !pong.ok) {
        err = "Ghidra bridge did not answer the handshake: " + pong.text;
        teardownLocked(false);
        return false;
    }
    logInfo("Ghidra is ready");
    return true;
}

static bool sendAll(int fd, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

bool Bridge::exchange(const std::string& line, Result& out) {
    out = {false, "connection to Ghidra lost"};
    if (!sendAll(sock_, line)) return false;

    std::string header;
    char c;
    for (;;) {
        ssize_t n = recv(sock_, &c, 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        if (c == '\n') break;
        header += c;
        if (header.size() > 64) return false;
    }
    size_t sp = header.find(' ');
    if (sp == std::string::npos) return false;
    size_t len = strtoull(header.c_str() + sp + 1, nullptr, 10);
    std::string body(len, '\0');
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(sock_, &body[got], len - got, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    out.ok = header.compare(0, sp, "OK") == 0;
    out.text = std::move(body);
    return true;
}

Bridge::Result Bridge::call(const std::string& command, const Args& args) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string err;
    if (!startLocked(err)) return {false, "Ghidra is not available: " + err};

    std::string line = token_ + "\t" + command;
    for (const auto& kv : args) line += "\t" + kv.first + "=" + encodeValue(kv.second);
    line += "\n";
    logDebug("bridge <- %s (%zu args)", command.c_str(), args.size());

    Result res;
    if (!exchange(line, res)) {
        std::string tail = util::tailOfFile(logPath(), 2000);
        teardownLocked(false);
        return {false, "Lost the connection to Ghidra while running '" + command +
                           "'. Ghidra will be restarted on the next call. Last log lines:\n" +
                           tail};
    }
    logDebug("bridge -> %s, %zu bytes", res.ok ? "OK" : "ERR", res.text.size());
    return res;
}

void Bridge::teardownLocked(bool graceful) {
    if (sock_ >= 0) {
        if (graceful) {
            Result bye;
            exchange(token_ + "\tshutdown\n", bye);
        }
        close(sock_);  // the bridge script exits when its connection closes
        sock_ = -1;
    }
    if (child_ > 0) {
        int status;
        bool gone = false;
        for (int i = 0; i < (graceful ? 150 : 20) && !gone; i++) {
            gone = waitpid(child_, &status, WNOHANG) == child_.load();
            if (!gone) sleepMs(100);
        }
        if (!gone) {
            kill(-child_, SIGTERM);
            for (int i = 0; i < 30 && !gone; i++) {
                gone = waitpid(child_, &status, WNOHANG) == child_.load();
                if (!gone) sleepMs(100);
            }
        }
        if (!gone) {
            kill(-child_, SIGKILL);
            waitpid(child_, &status, 0);
        }
        child_ = -1;
    }
    if (!runDir_.empty()) {
        unlink((runDir_ + "/token").c_str());
        unlink((runDir_ + "/port").c_str());
        unlink((runDir_ + "/port.tmp").c_str());
        rmdir(runDir_.c_str());
        runDir_.clear();
    }
}

void Bridge::stop() {
    stopping_ = true;
    // A long analysis may be holding the lock; do not let it block shutdown forever.
    std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
    for (int i = 0; i < 30 && !lock.try_lock(); i++) sleepMs(100);
    if (!lock.owns_lock()) {
        pid_t c = child_;
        if (c > 0) {
            logInfo("stopping Ghidra (interrupting a running command)");
            kill(-c, SIGTERM);
            sleepMs(1500);
            kill(-c, SIGKILL);
        }
        return;
    }
    if (child_ > 0 || sock_ >= 0) {
        logInfo("stopping Ghidra");
        teardownLocked(true);
    }
    stopping_ = false;
}
