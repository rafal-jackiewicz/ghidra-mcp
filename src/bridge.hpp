#pragma once
#include <sys/types.h>

#include <atomic>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

struct BridgeConfig {
    std::string ghidraHome;   // Ghidra installation directory (contains support/analyzeHeadless)
    std::string javaHome;     // exported as JAVA_HOME for Ghidra; may be empty
    std::string projectDir;   // directory holding the Ghidra project
    std::string projectName;  // Ghidra project name
    std::string dataDir;      // where the bridge script and the Ghidra log are kept
    int startupTimeoutSec = 300;
};

// Owns one long-running headless Ghidra process and talks to the bridge script inside it.
class Bridge {
public:
    struct Result {
        bool ok;
        std::string text;
    };
    using Args = std::vector<std::pair<std::string, std::string>>;

    explicit Bridge(BridgeConfig cfg);
    ~Bridge();

    // Starts Ghidra if it is not running. Returns false and fills err on failure.
    bool start(std::string& err);
    // Sends one command; starts (or restarts) Ghidra on demand. Calls are serialized.
    Result call(const std::string& command, const Args& args);
    // Closes all programs and stops Ghidra.
    void stop();

    std::string logPath() const { return cfg_.dataDir + "/ghidra-headless.log"; }

private:
    bool startLocked(std::string& err);
    void teardownLocked(bool graceful);
    bool exchange(const std::string& line, Result& out);

    BridgeConfig cfg_;
    std::mutex mutex_;
    std::atomic<pid_t> child_{-1};
    std::atomic<bool> stopping_{false};  // set by stop(); aborts a startup in progress
    int sock_ = -1;
    std::string token_;
    std::string runDir_;
};
