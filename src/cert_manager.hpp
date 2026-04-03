#pragma once

#include "acme_client.hpp"
#include "ssl_manager.hpp"
#include "tls_util.hpp"

#include <crow.h>
#include <openssl/ssl.h>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace cert_mgr {

namespace fs = std::filesystem;

// Periodic certificate renewal thread
std::atomic<bool> cert_stop{false};
std::thread       cert_thread;

/// Check every 12 hours (43 200 seconds) — runs at least twice per day.
constexpr int RENEWAL_CHECK_INTERVAL_SECS = 43200;

/// Renew if the certificate expires within this many days.
constexpr int RENEWAL_THRESHOLD_DAYS = 30;


/// Configuration subset needed for certificate management.
struct CertConfig {
    std::string cert_path;
    std::string key_path;
    std::string domain;
    bool        use_acme     = false;
    std::string acme_email;
    bool        acme_staging = false;
    bool        acme_verbose = false;
};

// Initial certificate provisioning

/// Perform initial certificate provisioning (ACME or self-signed).
/// Call this once at startup, before loading TLS material into memory.
void provision_certificates(
    const CertConfig& cfg,
    std::mutex& acme_mutex,
    std::unordered_map<std::string, std::string>& acme_challenges)
{
    if (cfg.use_acme) {
        if (cfg.acme_email.empty())
            throw std::runtime_error("--email is required with --acme");

        if (!ssl_mgr::needs_renewal(cfg.cert_path, 3)) {
            CROW_LOG_INFO << "Existing certificate is still valid (>3 days remaining)"
                             " - skipping ACME renewal";
        } else {
            CROW_LOG_INFO << "Requesting Let's Encrypt certificate for domain: "
                          << cfg.domain
                          << (cfg.acme_staging ? " [staging]" : " [production]");
            try {
                acme::AcmeClient client("acme_work/", cfg.acme_staging, cfg.acme_verbose);
                client.request_certificate(
                    cfg.domain, cfg.acme_email,
                    fs::path(cfg.cert_path), fs::path(cfg.key_path),
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
                ssl_mgr::ensure_certificates(cfg.cert_path, cfg.key_path, cfg.domain);
            }
        }
    } else {
        bool fresh = ssl_mgr::ensure_certificates(cfg.cert_path, cfg.key_path, cfg.domain);
        if (fresh) {
            CROW_LOG_INFO << "Generated self-signed TLS certificate (CN=" << cfg.domain
                          << ", 10 years)";
            CROW_LOG_INFO << "  cert -> " << cfg.cert_path;
            CROW_LOG_INFO << "  key  -> " << cfg.key_path;
        } else if (ssl_mgr::needs_renewal(cfg.cert_path, 30)) {
            CROW_LOG_WARNING << "TLS certificate expires in < 30 days - consider renewal";
        }
    }
}

/// Start a background thread that checks certificate validity every 12 hours.
/// If the certificate is close to expiry it will be renewed automatically,
/// using ACME or self-signed generation depending on the config.
/// After a successful renewal the live @p ssl_ctx is hot-reloaded so new
/// connections immediately use the fresh certificate.
///
/// @note Do NOT start this thread in sandbox/chroot mode — the cert files
///       on the real filesystem are inaccessible from inside the jail.
void start_renewal_thread(
    const CertConfig& cfg,
    std::mutex& acme_mutex,
    std::unordered_map<std::string, std::string>& acme_challenges,
    SSL_CTX* ssl_ctx)
{
    cert_stop = false;

    cert_thread = std::thread(
        [cfg, &acme_mutex, &acme_challenges, ssl_ctx]()
    {
        while (!cert_stop.load()) {
            // Sleep for 12 hours, waking every second to check the stop flag.
            for (int i = 0; i < RENEWAL_CHECK_INTERVAL_SECS
                             && !cert_stop.load(); ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (cert_stop.load()) break;

            try {
                if (!ssl_mgr::needs_renewal(cfg.cert_path,
                                            RENEWAL_THRESHOLD_DAYS)) {
                    CROW_LOG_INFO << "Cert renewal check: certificate still valid (>"
                                 << RENEWAL_THRESHOLD_DAYS
                                 << " days remaining)";
                    continue;
                }

                CROW_LOG_WARNING << "Cert renewal check: certificate expires within "
                                 << RENEWAL_THRESHOLD_DAYS
                                 << " days — initiating renewal";

                bool renewed = false;

                if (cfg.use_acme) {
                    try {
                        acme::AcmeClient client("acme_work/",
                                                cfg.acme_staging,
                                                cfg.acme_verbose);
                        client.request_certificate(
                            cfg.domain, cfg.acme_email,
                            fs::path(cfg.cert_path), fs::path(cfg.key_path),
                            [&](const std::string& token,
                                const std::string& key_auth) {
                                std::lock_guard lock(acme_mutex);
                                acme_challenges[token] = key_auth;
                                CROW_LOG_INFO << "ACME renewal: challenge token "
                                                 "registered: " << token;
                            },
                            [&](const std::string& token) {
                                std::lock_guard lock(acme_mutex);
                                acme_challenges.erase(token);
                            });

                        CROW_LOG_INFO << "Cert renewal: ACME certificate renewed "
                                         "successfully";
                        renewed = true;
                    } catch (const std::exception& ex) {
                        CROW_LOG_ERROR << "ACME renewal failed: " << ex.what();
                        CROW_LOG_WARNING << "Falling back to self-signed certificate";
                        ssl_mgr::generate_self_signed_cert(
                            cfg.cert_path, cfg.key_path, cfg.domain);
                        renewed = true;
                    }
                } else {
                    ssl_mgr::generate_self_signed_cert(
                        cfg.cert_path, cfg.key_path, cfg.domain);
                    CROW_LOG_INFO << "Cert renewal: self-signed certificate "
                                     "regenerated";
                    renewed = true;
                }

                // Hot-reload the live SSL context so new connections
                // immediately use the fresh certificate.
                if (renewed && ssl_ctx) {
                    try {
                        tls_util::reload_from_files(
                            ssl_ctx, cfg.cert_path, cfg.key_path);
                    } catch (const std::exception& ex) {
                        CROW_LOG_ERROR << "TLS hot-reload failed: " << ex.what();
                    }
                }
            } catch (const std::exception& ex) {
                CROW_LOG_ERROR << "Cert renewal check failed: " << ex.what();
            }
        }
    });
}

/// Stop the certificate renewal thread (blocks until it finishes).
void stop_renewal_thread() {
    cert_stop = true;
    if (cert_thread.joinable())
        cert_thread.join();
}

} // namespace cert_mgr
