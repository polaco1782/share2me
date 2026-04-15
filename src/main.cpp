#include "cert_manager.hpp"
#include "config.hpp"
#include "housekeeper.hpp"
#include "logging.hpp"
#include "routes.hpp"
#include "sandbox.hpp"
#include "store.hpp"
#include "tls_util.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>

#include <chrono>
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

    AppConfig cfg = parse_args(argc, argv);

    FileStore store("data");
    store.create_directories();

    std::mutex acme_mutex;
    std::unordered_map<std::string, std::string> acme_challenges;

    // Restore any ACME challenges that were persisted before a restart.
    try {
        std::ifstream ifs("acme_work/challenges.json");
        if (ifs) {
            nlohmann::json j;
            ifs >> j;
            for (auto& [k, v] : j.items())
                acme_challenges[k] = v.get<std::string>();
            if (!acme_challenges.empty())
                LOG_INFO << "Restored " << acme_challenges.size()
                         << " persisted ACME challenge(s)";
        }
    } catch (...) {}

    httplib::Server http_app;
    std::thread http_thread;

    register_http_routes(http_app, cfg, acme_mutex, acme_challenges);

    if (cfg.http_port > 0) {
        http_thread = std::thread([&] {
            http_app.listen("::", cfg.http_port);
        });
        // Give the HTTP server a moment to bind before ACME starts.
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    if (cfg.use_acme && cfg.http_port == 0)
        throw std::runtime_error(
            "--acme requires an HTTP port (--http-port must be > 0)");

    CertManager cert_mgr({
        .cert_path    = cfg.cert_path,
        .key_path     = cfg.key_path,
        .domain       = cfg.domain,
        .use_acme     = cfg.use_acme,
        .acme_email   = cfg.acme_email,
        .acme_staging = cfg.acme_staging,
        .acme_verbose = cfg.acme_verbose,
    });

    cert_mgr.provision(acme_mutex, acme_challenges);

    auto tls = tls_util::load_files(cfg.cert_path, cfg.key_path);

    if ((cfg.sandbox_mode || !cfg.drop_user.empty()) && ::geteuid() != 0) {
        LOG_ERROR << "--sandbox / --user require root privileges "
                     "(run with sudo or grant CAP_SYS_CHROOT + CAP_SETUID)";
        return 1;
    }

    std::optional<sandbox::UserInfo> jail_user;
    if (!cfg.drop_user.empty()) {
        try {
            jail_user = sandbox::lookup_user(cfg.drop_user);
        } catch (const std::exception& ex) {
            LOG_ERROR << "Cannot resolve --user '" << cfg.drop_user
                      << "': " << ex.what();
            return 1;
        }
    }

    if (cfg.sandbox_mode) {
        const fs::path jail_abs = fs::absolute(store.data_dir());
        try {
            if (jail_user)
                sandbox::chown_jail(jail_abs, *jail_user);

            LOG_INFO << "Entering chroot jail: " << jail_abs;
            sandbox::enter_chroot(jail_abs);
            store.set_data_dir("/");
            LOG_INFO << "Jailed; file root is now the jail root";
        } catch (const std::exception& ex) {
            LOG_ERROR << "Sandbox setup failed: " << ex.what();
            return 1;
        }
    }

    if (jail_user) {
        try {
            sandbox::drop_privileges(*jail_user);
            LOG_INFO << "Privileges dropped to " << cfg.drop_user
                     << " (uid=" << jail_user->uid
                     << ", gid=" << jail_user->gid << ")";
        } catch (const std::exception& ex) {
            LOG_ERROR << "Privilege drop failed: " << ex.what();
            return 1;
        }
    }

    // Build the SSL context via httplib's callback.
    SSL_CTX* live_ssl_ctx = nullptr;

    httplib::SSLServer app(
        [&tls, &live_ssl_ctx](SSL_CTX& ctx) -> bool {
            try {
                BIO* cert_bio = BIO_new_mem_buf(tls.cert_pem.data(),
                    static_cast<int>(tls.cert_pem.size()));
                if (!cert_bio) return false;
                X509* cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
                if (!cert) { BIO_free(cert_bio); return false; }
                if (SSL_CTX_use_certificate(&ctx, cert) != 1) {
                    X509_free(cert); BIO_free(cert_bio); return false;
                }
                X509_free(cert);
                while (true) {
                    X509* chain_cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
                    if (!chain_cert) break;
                    SSL_CTX_add_extra_chain_cert(&ctx, chain_cert);
                }
                BIO_free(cert_bio);

                BIO* key_bio = BIO_new_mem_buf(tls.key_pem.data(),
                    static_cast<int>(tls.key_pem.size()));
                if (!key_bio) return false;
                EVP_PKEY* pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
                BIO_free(key_bio);
                if (!pkey) return false;
                if (SSL_CTX_use_PrivateKey(&ctx, pkey) != 1) {
                    EVP_PKEY_free(pkey); return false;
                }
                EVP_PKEY_free(pkey);

                if (SSL_CTX_check_private_key(&ctx) != 1) return false;

                OPENSSL_cleanse(tls.key_pem.data(), tls.key_pem.size());
                tls.key_pem.clear();

                SSL_CTX_set_min_proto_version(&ctx, TLS1_2_VERSION);

                live_ssl_ctx = &ctx;
                return true;
            } catch (...) {
                return false;
            }
        });

    register_routes(app, cfg, store);

    Housekeeper housekeeper(store);
    housekeeper.start();

    if (!cfg.sandbox_mode) {
        cert_mgr.start_renewal(acme_mutex, acme_challenges, live_ssl_ctx);
    } else {
        LOG_WARNING << "Cert renewal thread skipped in sandbox mode "
                       "(cert files are outside the chroot jail)";
    }

    LOG_INFO << "Share2Me (HTTPS) listening on " << cfg.https_port
             << "  |  HTTP redirect on " << cfg.http_port;

    app.listen("::", cfg.https_port);

    cert_mgr.stop_renewal();
    housekeeper.stop();

    if (cfg.http_port > 0) {
        http_app.stop();
        if (http_thread.joinable()) http_thread.join();
    }

    return 0;
}
