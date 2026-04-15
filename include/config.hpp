#pragma once

#include <cstdint>
#include <string>

/// Holds every command-line option the application supports.
struct AppConfig {
    uint16_t    https_port   = 8443;
    uint16_t    http_port    = 8080;
    std::string cert_path    = "cert.pem";
    std::string key_path     = "key.pem";
    std::string domain       = "localhost";
    bool        use_acme     = false;
    bool        acme_staging = false;
    bool        acme_verbose = false;
    std::string acme_email;
    bool        sandbox_mode = false;
    std::string drop_user;
    bool        http_verbose = false;  ///< --http-log: log every HTTP(S) request/response
};

/// Parse argv into an AppConfig.
/// Throws std::runtime_error when a flag that expects a value is missing one.
AppConfig parse_args(int argc, char* argv[]);
