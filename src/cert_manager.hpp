#pragma once

#include "acme_client.hpp"
#include "ssl_manager.hpp"

#include <crow.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace cert_mgr {

namespace fs = std::filesystem;

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

// ─────────────────────────────────────────────────────────────────────────────
// Initial certificate provisioning
// ─────────────────────────────────────────────────────────────────────────────

/// Perform initial certificate provisioning (ACME or self-signed).
/// Call this once at startup, before loading TLS material into memory.
inline void provision_certificates(
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

// ─────────────────────────────────────────────────────────────────────────────
// Periodic certificate renewal thread
// ─────────────────────────────────────────────────────────────────────────────

namespace detail {
    inline std::atomic<bool> cert_stop{false};
    inline std::thread       cert_thread;

    /// Check every 12 hours (43 200 seconds) — runs at least twice per day.
    inline constexpr int RENEWAL_CHECK_INTERVAL_SECS = 43200;

    /// Renew if the certificate expires within this many days.
    inline constexpr int RENEWAL_THRESHOLD_DAYS = 30;
} // namespace detail

/// Start a background thread that checks certificate validity every 12 hours.
/// If the certificate is close to expiry it will be renewed automatically,
/// using ACME or self-signed generation depending on the config.
///
/// @note Do NOT start this thread in sandbox/chroot mode — the cert files
///       on the real filesystem are inaccessible from inside the jail.
inline void start_renewal_thread(
    const CertConfig& cfg,
    std::mutex& acme_mutex,
    std::unordered_map<std::string, std::string>& acme_challenges)
{
    detail::cert_stop = false;

    detail::cert_thread = std::thread(
        [cfg, &acme_mutex, &acme_challenges]()
    {
        while (!detail::cert_stop.load()) {
            // Sleep for 12 hours, waking every second to check the stop flag.
            for (int i = 0; i < detail::RENEWAL_CHECK_INTERVAL_SECS
                             && !detail::cert_stop.load(); ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (detail::cert_stop.load()) break;

            try {
                if (!ssl_mgr::needs_renewal(cfg.cert_path,
                                            detail::RENEWAL_THRESHOLD_DAYS)) {
                    CROW_LOG_INFO << "Cert renewal check: certificate still valid (>"
                                 << detail::RENEWAL_THRESHOLD_DAYS
                                 << " days remaining)";
                    continue;
                }

                CROW_LOG_WARNING << "Cert renewal check: certificate expires within "
                                 << detail::RENEWAL_THRESHOLD_DAYS
                                 << " days — initiating renewal";

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
                                         "successfully — restart the server to "
                                         "load the new certificate";
                    } catch (const std::exception& ex) {
                        CROW_LOG_ERROR << "ACME renewal failed: " << ex.what();
                        CROW_LOG_WARNING << "Falling back to self-signed certificate";
                        ssl_mgr::generate_self_signed_cert(
                            cfg.cert_path, cfg.key_path, cfg.domain);
                        CROW_LOG_INFO << "Cert renewal: self-signed certificate "
                                         "regenerated — restart the server to "
                                         "load the new certificate";
                    }
                } else {
                    ssl_mgr::generate_self_signed_cert(
                        cfg.cert_path, cfg.key_path, cfg.domain);
                    CROW_LOG_INFO << "Cert renewal: self-signed certificate "
                                     "regenerated — restart the server to "
                                     "load the new certificate";
                }
            } catch (const std::exception& ex) {
                CROW_LOG_ERROR << "Cert renewal check failed: " << ex.what();
            }
        }
    });
}

/// Stop the certificate renewal thread (blocks until it finishes).
inline void stop_renewal_thread() {
    detail::cert_stop = true;
    if (detail::cert_thread.joinable())
        detail::cert_thread.join();
}

} // namespace cert_mgr
