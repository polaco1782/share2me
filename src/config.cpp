#include "config.hpp"

#include <stdexcept>
#include <string>

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
        else if (arg == "--http-log")     cfg.http_verbose = true;
        else if (arg[0] != '-') {
            try { cfg.https_port = static_cast<uint16_t>(std::stoi(arg)); }
            catch (...) {}
        }
    }

    return cfg;
}
