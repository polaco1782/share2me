#pragma once

#include <cstdint>
#include <stdexcept>
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
};

/// Parse argv into an AppConfig.
/// Throws std::runtime_error when a flag that expects a value is missing one.
AppConfig parse_args(int argc, char* argv[]) {
    AppConfig cfg;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next_arg = [&]() -> std::string {
            if (++i >= argc)
                throw std::runtime_error("Missing value for " + arg);
            return argv[i];
        };
        if      (arg == "--port")         cfg.https_port   = static_cast<uint16_t>(std::stoi(next_arg()));
        else if (arg == "--http-port")    cfg.http_port    = static_cast<uint16_t>(std::stoi(next_arg()));
        else if (arg == "--cert")         cfg.cert_path    = next_arg();
        else if (arg == "--key")          cfg.key_path     = next_arg();
        else if (arg == "--domain")       cfg.domain       = next_arg();
        else if (arg == "--acme")         cfg.use_acme     = true;
        else if (arg == "--email")        cfg.acme_email   = next_arg();
        else if (arg == "--staging")      cfg.acme_staging = true;
        else if (arg == "--acme-verbose") cfg.acme_verbose = true;
        else if (arg == "--sandbox")      cfg.sandbox_mode = true;
        else if (arg == "--user")         cfg.drop_user    = next_arg();
        else if (arg[0] != '-') {
            try { cfg.https_port = static_cast<uint16_t>(std::stoi(arg)); }
            catch (...) {}
        }
    }

    return cfg;
}
