#include "cert_manager.hpp"
#include "acme_client.hpp"
#include "logging.hpp"
#include "ssl_manager.hpp"
#include "tls_util.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace {
constexpr int RENEWAL_CHECK_INTERVAL_SECS = 43200;
constexpr int RENEWAL_THRESHOLD_DAYS      = 30;
} // anonymous namespace

CertManager::CertManager(Config cfg)
    : cfg_(std::move(cfg))
{}

CertManager::~CertManager() {
    stop_renewal();
}

void CertManager::save_challenges(
    const std::unordered_map<std::string, std::string>& challenges) {
    try {
        fs::create_directories("acme_work");
        nlohmann::json j;
        for (auto& [k, v] : challenges)
            j[k] = v;
        std::ofstream ofs("acme_work/challenges.json");
        if (ofs) ofs << j.dump(2);
    } catch (...) {}
}

void CertManager::provision(
    std::mutex& acme_mutex,
    std::unordered_map<std::string, std::string>& acme_challenges)
{
    if (cfg_.use_acme) {
        if (cfg_.acme_email.empty())
            throw std::runtime_error("--email is required with --acme");

        if (!ssl_mgr::needs_renewal(cfg_.cert_path, 3)) {
            LOG_INFO << "Existing certificate is still valid (>3 days remaining)"
                        " - skipping ACME renewal";
        } else {
            LOG_INFO << "Requesting Let's Encrypt certificate for domain: "
                     << cfg_.domain
                     << (cfg_.acme_staging ? " [staging]" : " [production]");
            try {
                acme::AcmeClient client("acme_work/",
                                        cfg_.acme_staging,
                                        cfg_.acme_verbose);
                client.request_certificate(
                    cfg_.domain, cfg_.acme_email,
                    fs::path(cfg_.cert_path), fs::path(cfg_.key_path),
                    [&](const std::string& token, const std::string& key_auth) {
                        std::lock_guard lock(acme_mutex);
                        acme_challenges[token] = key_auth;
                        save_challenges(acme_challenges);
                        LOG_INFO << "ACME: challenge token registered: " << token;
                    },
                    [&](const std::string& token) {
                        std::lock_guard lock(acme_mutex);
                        acme_challenges.erase(token);
                        save_challenges(acme_challenges);
                    });
                LOG_INFO << "Let's Encrypt certificate obtained successfully";
            } catch (const std::exception& ex) {
                LOG_ERROR << "ACME failed: " << ex.what();
                LOG_WARNING << "Falling back to self-signed certificate";
                ssl_mgr::ensure_certificates(cfg_.cert_path, cfg_.key_path,
                                             cfg_.domain);
            }
        }
    } else {
        bool fresh = ssl_mgr::ensure_certificates(cfg_.cert_path, cfg_.key_path,
                                                   cfg_.domain);
        if (fresh) {
            LOG_INFO << "Generated self-signed TLS certificate (CN="
                     << cfg_.domain << ", 10 years)";
            LOG_INFO << "  cert -> " << cfg_.cert_path;
            LOG_INFO << "  key  -> " << cfg_.key_path;
        } else if (ssl_mgr::needs_renewal(cfg_.cert_path, 30)) {
            LOG_WARNING << "TLS certificate expires in < 30 days"
                           " - consider renewal";
        }
    }
}

void CertManager::start_renewal(
    std::mutex& acme_mutex,
    std::unordered_map<std::string, std::string>& acme_challenges,
    SSL_CTX* ssl_ctx)
{
    stop_ = false;

    thread_ = std::thread(
        [this, &acme_mutex, &acme_challenges, ssl_ctx]()
    {
        while (!stop_.load()) {
            for (int i = 0; i < RENEWAL_CHECK_INTERVAL_SECS
                             && !stop_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (stop_.load()) break;

            try {
                if (!ssl_mgr::needs_renewal(cfg_.cert_path,
                                            RENEWAL_THRESHOLD_DAYS)) {
                    LOG_INFO << "Cert renewal check: certificate still valid (>"
                             << RENEWAL_THRESHOLD_DAYS
                             << " days remaining)";
                    continue;
                }

                LOG_WARNING << "Cert renewal check: certificate expires within "
                            << RENEWAL_THRESHOLD_DAYS
                            << " days - initiating renewal";

                bool renewed = false;

                if (cfg_.use_acme) {
                    try {
                        acme::AcmeClient client("acme_work/",
                                                cfg_.acme_staging,
                                                cfg_.acme_verbose);
                        client.request_certificate(
                            cfg_.domain, cfg_.acme_email,
                            fs::path(cfg_.cert_path), fs::path(cfg_.key_path),
                            [&](const std::string& token,
                                const std::string& key_auth) {
                                std::lock_guard lock(acme_mutex);
                                acme_challenges[token] = key_auth;
                                save_challenges(acme_challenges);
                                LOG_INFO << "ACME renewal: challenge token "
                                            "registered: " << token;
                            },
                            [&](const std::string& token) {
                                std::lock_guard lock(acme_mutex);
                                acme_challenges.erase(token);
                                save_challenges(acme_challenges);
                            });

                        LOG_INFO << "Cert renewal: ACME certificate renewed "
                                    "successfully";
                        renewed = true;
                    } catch (const std::exception& ex) {
                        LOG_ERROR << "ACME renewal failed: " << ex.what();
                        LOG_WARNING << "Falling back to self-signed certificate";
                        ssl_mgr::generate_self_signed_cert(
                            cfg_.cert_path, cfg_.key_path, cfg_.domain);
                        renewed = true;
                    }
                } else {
                    ssl_mgr::generate_self_signed_cert(
                        cfg_.cert_path, cfg_.key_path, cfg_.domain);
                    LOG_INFO << "Cert renewal: self-signed certificate "
                                "regenerated";
                    renewed = true;
                }

                if (renewed && ssl_ctx) {
                    try {
                        tls_util::reload_from_files(
                            ssl_ctx, cfg_.cert_path, cfg_.key_path);
                    } catch (const std::exception& ex) {
                        LOG_ERROR << "TLS hot-reload failed: " << ex.what();
                    }
                }
            } catch (const std::exception& ex) {
                LOG_ERROR << "Cert renewal check failed: " << ex.what();
            }
        }
    });
}

void CertManager::stop_renewal() {
    stop_ = true;
    if (thread_.joinable())
        thread_.join();
}
