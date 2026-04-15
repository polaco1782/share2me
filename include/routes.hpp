#pragma once

#include "config.hpp"
#include "store.hpp"

#include <httplib.h>

#include <mutex>
#include <string>
#include <unordered_map>

/// Register ACME-challenge and HTTP→HTTPS redirect routes.
void register_http_routes(
    httplib::Server& http_app,
    const AppConfig& cfg,
    std::mutex& acme_mutex,
    std::unordered_map<std::string, std::string>& acme_challenges);

/// Register all HTTPS application routes (upload, download, viewers, etc.).
void register_routes(httplib::SSLServer& app,
                     const AppConfig& cfg,
                     FileStore& store);
