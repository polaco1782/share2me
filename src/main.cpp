#include "config.hpp"
#include "routes.hpp"
#include "cert_manager.hpp"
#include "housekeeper.hpp"
#include "sandbox.hpp"
#include "tls_util.hpp"

#include <crow.h>

#include <chrono>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {

    // ── 1. Parse command-line arguments ──────────────────────────────────
    AppConfig cfg = parse_args(argc, argv);

    fs::create_directories(DATA_DIR);

    // ── 2. HTTP redirect server (also serves ACME http-01 challenges) ───
    std::mutex                                   acme_mutex;
    std::unordered_map<std::string, std::string> acme_challenges;
    crow::SimpleApp http_app;
    std::thread     http_thread;

    http_app.loglevel(crow::LogLevel::Info);
    register_http_routes(http_app, cfg.domain, cfg.https_port,
                         acme_mutex, acme_challenges);

    if (cfg.http_port > 0) {
        http_thread = std::thread([&] {
            http_app.port(cfg.http_port).multithreaded().run();
        });
        // Give the HTTP server a moment to bind before ACME starts.
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    // ── 3. Certificate provisioning (ACME or self-signed) ────────────────
    if (cfg.use_acme && cfg.http_port == 0)
        throw std::runtime_error(
            "--acme requires an HTTP port (--http-port must be > 0)");

    cert_mgr::CertConfig cert_cfg{
        .cert_path    = cfg.cert_path,
        .key_path     = cfg.key_path,
        .domain       = cfg.domain,
        .use_acme     = cfg.use_acme,
        .acme_email   = cfg.acme_email,
        .acme_staging = cfg.acme_staging,
        .acme_verbose = cfg.acme_verbose,
    };

    cert_mgr::provision_certificates(cert_cfg, acme_mutex, acme_challenges);

    // ── 4. Load TLS material into memory before entering the jail ────────
    auto tls = tls_util::load_files(cfg.cert_path, cfg.key_path);

    // ── 5. Sandbox / privilege drop ──────────────────────────────────────
    if ((cfg.sandbox_mode || !cfg.drop_user.empty()) && ::geteuid() != 0) {
        CROW_LOG_ERROR << "--sandbox / --user require root privileges "
                          "(run with sudo or grant CAP_SYS_CHROOT + CAP_SETUID)";
        return 1;
    }

    std::optional<sandbox::UserInfo> jail_user;
    if (!cfg.drop_user.empty()) {
        try {
            jail_user = sandbox::lookup_user(cfg.drop_user);
        } catch (const std::exception& ex) {
            CROW_LOG_ERROR << "Cannot resolve --user '" << cfg.drop_user
                           << "': " << ex.what();
            return 1;
        }
    }

    if (cfg.sandbox_mode) {
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
            CROW_LOG_INFO << "Privileges dropped to " << cfg.drop_user
                          << " (uid=" << jail_user->uid
                          << ", gid=" << jail_user->gid << ")";
        } catch (const std::exception& ex) {
            CROW_LOG_ERROR << "Privilege drop failed: " << ex.what();
            return 1;
        }
    }

    // ── 6. Background tasks ─────────────────────────────────────────────
    housekeeper::start_housekeeper_thread();

    if (!cfg.sandbox_mode) {
        cert_mgr::start_renewal_thread(cert_cfg, acme_mutex, acme_challenges);
    } else {
        CROW_LOG_WARNING << "Cert renewal thread skipped in sandbox mode "
                            "(cert files are outside the chroot jail)";
    }

    // ── 7. HTTPS server ─────────────────────────────────────────────────
    crow::SimpleApp app;
    app.loglevel(crow::LogLevel::Info);
    register_routes(app);

    auto ssl_ctx = tls_util::create_ssl_context(tls);

    CROW_LOG_INFO << "Share2Me (HTTPS) listening on " << cfg.https_port
                  << "  |  HTTP redirect on " << cfg.http_port;
    app.port(cfg.https_port).ssl(std::move(ssl_ctx)).multithreaded().run();

    // ── 8. Shutdown ─────────────────────────────────────────────────────
    cert_mgr::stop_renewal_thread();
    housekeeper::stop_housekeeper_thread();

    if (cfg.http_port > 0) {
        http_app.stop();
        if (http_thread.joinable()) http_thread.join();
    }

    return 0;
}
