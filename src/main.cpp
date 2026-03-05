// Share2Me – lightweight file sharing server

#include "routes.hpp"
#include "sandbox.hpp"
#include "ssl_manager.hpp"
#ifdef HAVE_ACME_CLIENT
#  include "acme_client.hpp"
#endif

#include <crow.h>

#include <chrono>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {

    uint16_t    https_port   = 8443;
    uint16_t    http_port    = 8080;
    std::string cert_path    = "cert.pem";
    std::string key_path     = "key.pem";
    std::string domain       = "localhost";
    bool        use_acme     = false;
    bool        acme_staging = false;
    std::string acme_email;
    bool        sandbox_mode = false;
    std::string drop_user;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next_arg = [&]() -> std::string {
            if (++i >= argc)
                throw std::runtime_error("Missing value for " + arg);
            return argv[i];
        };
        if      (arg == "--port")       https_port   = static_cast<uint16_t>(std::stoi(next_arg()));
        else if (arg == "--http-port")  http_port    = static_cast<uint16_t>(std::stoi(next_arg()));
        else if (arg == "--cert")       cert_path    = next_arg();
        else if (arg == "--key")        key_path     = next_arg();
        else if (arg == "--domain")     domain       = next_arg();
        else if (arg == "--acme")       use_acme     = true;
        else if (arg == "--email")      acme_email   = next_arg();
        else if (arg == "--staging")    acme_staging = true;
        else if (arg == "--sandbox")    sandbox_mode = true;
        else if (arg == "--user")       drop_user    = next_arg();
        else if (arg[0] != '-') {
            try { https_port = static_cast<uint16_t>(std::stoi(arg)); }
            catch (...) {}
        }
    }

    fs::create_directories(DATA_DIR);

    std::mutex                                   acme_mutex;
    std::unordered_map<std::string, std::string> acme_challenges;

    crow::SimpleApp http_app;
    http_app.loglevel(crow::LogLevel::Warning);

    CROW_CATCHALL_ROUTE(http_app)
    ([&](const crow::request& req) {
        static const std::string CHALLENGE_PREFIX = "/.well-known/acme-challenge/";
        static const std::string WELL_KNOWN_PREFIX = "/.well-known/";

        // Only serve active ACME challenge tokens; everything else under
        // /.well-known/ (including stale/fake tokens and security.txt probes)
        // gets a silent 404 — no redirect, no info leakage.
        if (req.url.compare(0, WELL_KNOWN_PREFIX.size(), WELL_KNOWN_PREFIX) == 0) {
            if (req.url.compare(0, CHALLENGE_PREFIX.size(), CHALLENGE_PREFIX) == 0) {
                std::string token = req.url.substr(CHALLENGE_PREFIX.size());
                std::lock_guard lock(acme_mutex);
                if (auto it = acme_challenges.find(token); it != acme_challenges.end())
                    return crow::response(200, it->second);
            }
            return crow::response(404);
        }

        std::string host = req.get_header_value("Host");
        if (auto p = host.find(':'); p != std::string::npos)
            host = host.substr(0, p);
        if (host.empty()) host = domain;
        std::string location = "https://" + host;
        if (https_port != 443) location += ":" + std::to_string(https_port);
        location += req.url;
        crow::response r(301);
        r.set_header("Location", location);
        return r;
    });

    std::thread http_thread;
    if (http_port > 0) {
        http_thread = std::thread([&] {
            http_app.port(http_port).multithreaded().run();
        });
        // Give the HTTP server a moment to bind its port before ACME starts
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    if (use_acme) {
#ifdef HAVE_ACME_CLIENT
        if (acme_email.empty())
            throw std::runtime_error("--email is required with --acme");
        if (http_port == 0)
            throw std::runtime_error(
                "--acme requires an HTTP port (--http-port must be > 0)");

        CROW_LOG_INFO << "Requesting Let's Encrypt certificate for domain: " << domain
                      << (acme_staging ? " [staging]" : " [production]");
        try {
            acme::AcmeClient client("acme_work/", acme_staging);
            client.request_certificate(
                domain, acme_email,
                fs::path(cert_path), fs::path(key_path),
                [&](const std::string& token, const std::string& key_auth) {
                    std::lock_guard lock(acme_mutex);
                    acme_challenges[token] = key_auth;
                    CROW_LOG_INFO << "ACME: challenge token registered: " << token;
                },
                [&](const std::string& token) {
                    std::lock_guard lock(acme_mutex);
                    acme_challenges.erase(token);
                });
            CROW_LOG_INFO << "Let's Encrypt certificate obtained successfully";
        } catch (const std::exception& ex) {
            CROW_LOG_ERROR << "ACME failed: " << ex.what();
            CROW_LOG_WARNING << "Falling back to self-signed certificate";
            ssl_mgr::ensure_certificates(cert_path, key_path, domain);
        }
#else
        CROW_LOG_WARNING << "--acme flag given but ACME support was not compiled in "
                            "(libcurl was not found at build time). "
                            "Falling back to self-signed certificate.";
        ssl_mgr::ensure_certificates(cert_path, key_path, domain);
#endif
    } else {
        bool fresh = ssl_mgr::ensure_certificates(cert_path, key_path, domain);
        if (fresh) {
            CROW_LOG_INFO << "Generated self-signed TLS certificate (CN=" << domain
                          << ", 10 years)";
            CROW_LOG_INFO << "  cert -> " << cert_path;
            CROW_LOG_INFO << "  key  -> " << key_path;
        } else if (ssl_mgr::needs_renewal(cert_path, 30)) {
            CROW_LOG_WARNING << "TLS certificate expires in < 30 days – consider renewal";
        }
    }

    // Load TLS files into memory before entering the chroot jail.
    std::string tls_cert_pem, tls_key_pem;
    {
        auto slurp = [](const std::string& path) {
            std::ifstream f(path, std::ios::binary);
            if (!f) throw std::runtime_error("Cannot open TLS file: " + path);
            return std::string(std::istreambuf_iterator<char>(f), {});
        };
        tls_cert_pem = slurp(cert_path);
        tls_key_pem  = slurp(key_path);
        CROW_LOG_INFO << "TLS material loaded into memory (cert "
                      << tls_cert_pem.size() << " B, key "
                      << tls_key_pem.size()  << " B)";
    }

    if ((sandbox_mode || !drop_user.empty()) && ::geteuid() != 0) {
        CROW_LOG_ERROR << "--sandbox / --user require root privileges "
                          "(run with sudo or grant CAP_SYS_CHROOT + CAP_SETUID)";
        return 1;
    }

    std::optional<sandbox::UserInfo> jail_user;
    if (!drop_user.empty()) {
        try {
            jail_user = sandbox::lookup_user(drop_user);
        } catch (const std::exception& ex) {
            CROW_LOG_ERROR << "Cannot resolve --user '" << drop_user << "': " << ex.what();
            return 1;
        }
    }

    if (sandbox_mode) {
        const fs::path jail_abs = fs::absolute(DATA_DIR);

        try {
            if (jail_user)
                sandbox::chown_jail(jail_abs, *jail_user);

            CROW_LOG_INFO << "Entering chroot jail: " << jail_abs;
            sandbox::enter_chroot(jail_abs);
            DATA_DIR = "/";  // inside the jail all data lives at the root
            CROW_LOG_INFO << "Jailed; file root is now the jail root";
        } catch (const std::exception& ex) {
            CROW_LOG_ERROR << "Sandbox setup failed: " << ex.what();
            return 1;
        }
    }

    if (jail_user) {
        try {
            sandbox::drop_privileges(*jail_user);
            CROW_LOG_INFO << "Privileges dropped to " << drop_user
                          << " (uid=" << jail_user->uid
                          << ", gid=" << jail_user->gid << ")";
        } catch (const std::exception& ex) {
            CROW_LOG_ERROR << "Privilege drop failed: " << ex.what();
            return 1;
        }
    }

    crow::SimpleApp app;
    app.loglevel(crow::LogLevel::Info);

    register_routes(app);

    // Housekeeping thread: scan for expired files every minute.
    std::atomic<bool> stop_housekeep{false};
    std::thread housekeep_thread([&]() {
        while (!stop_housekeep.load()) {
            // Sleep 60 seconds but wake quickly on stop.
            for (int i = 0; i < 60 && !stop_housekeep.load(); ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));
            if (stop_housekeep.load()) break;

            try {
                long long now_sec = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                for (auto& entry : fs::directory_iterator(DATA_DIR)) {
                    if (entry.path().extension() != ".json") continue;
                    try {
                        nlohmann::json meta;
                        {
                            std::ifstream ifs(entry.path());
                            if (!ifs) continue;
                            ifs >> meta;
                        }
                        if (!meta.contains("expires_at")) continue;
                        long long expires_at = meta["expires_at"].get<long long>();
                        if (now_sec >= expires_at) {
                            std::string stored_as = meta.value("stored_as", "");
                            std::error_code ec;
                            if (!stored_as.empty())
                                fs::remove(DATA_DIR / stored_as, ec);
                            fs::remove(entry.path(), ec);
                            CROW_LOG_INFO << "Housekeep: expired file removed: "
                                          << meta.value("id", "?");
                        }
                    } catch (...) {}
                }
            } catch (...) {}
        }
    });

    asio::ssl::context ssl_ctx(asio::ssl::context::sslv23);
    ssl_ctx.set_verify_mode(asio::ssl::verify_peer);
    ssl_ctx.set_verify_mode(asio::ssl::verify_client_once);
    ssl_ctx.use_certificate_chain(asio::buffer(tls_cert_pem));
    ssl_ctx.use_private_key(asio::buffer(tls_key_pem), asio::ssl::context::pem);
    ssl_ctx.set_options(asio::ssl::context::default_workarounds |
                        asio::ssl::context::no_sslv2 |
                        asio::ssl::context::no_sslv3);
    OPENSSL_cleanse(tls_key_pem.data(), tls_key_pem.size());

    CROW_LOG_INFO << "Share2Me (HTTPS) listening on " << https_port
                  << "  |  HTTP redirect on " << http_port;
    app.port(https_port).ssl(std::move(ssl_ctx)).multithreaded().run();

    stop_housekeep = true;
    if (housekeep_thread.joinable()) housekeep_thread.join();

    if (http_port > 0) {
        http_app.stop();
        if (http_thread.joinable()) http_thread.join();
    }

    return 0;
}
