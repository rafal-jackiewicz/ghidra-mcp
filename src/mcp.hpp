#pragma once
#include <ctime>
#include <map>
#include <mutex>
#include <string>

#include "bridge.hpp"

struct McpConfig {
    std::string uploadDir;       // where uploaded binaries are stored
    bool httpUploads = false;    // true when the HTTP transport (and /upload) is available
    std::string endpoint;        // URL path prefix of the HTTP endpoints, e.g. "/ghidra-mcp"
    std::string fallbackBaseUrl; // used for upload URLs when a request carries no Host header
};

// Implements the MCP JSON-RPC methods on top of the Ghidra bridge. Transport independent.
class McpServer {
public:
    McpServer(Bridge& bridge, McpConfig cfg);

    // Handles one JSON-RPC message (or batch). Returns the serialized response, or an empty
    // string when the message needs no response (notifications). baseUrl is the URL the
    // client used to reach this server (e.g. "http://10.0.2.2:8765"); may be empty.
    std::string handle(const std::string& body, const std::string& baseUrl);

    // Redeems an upload ticket created by the prepare_upload tool. On success fills
    // destPath with the file the upload must be written to.
    bool claimUpload(const std::string& ticket, std::string& destPath);

private:
    struct Ticket {
        std::string fileName;
        time_t expires;
    };

    Bridge& bridge_;
    McpConfig cfg_;
    std::mutex ticketMutex_;
    std::map<std::string, Ticket> tickets_;

    friend struct McpDispatch;
};
