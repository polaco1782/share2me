#pragma once

#include <openssl/ssl.h>

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

/// Manages TLS certificate provisioning and automatic renewal.
class CertManager {
public:
    struct Config {
        std::string cert_path;
        std::string key_path;
        std::string domain;
        bool        use_acme     = false;
        std::string acme_email;
        bool        acme_staging = false;
        bool        acme_verbose = false;
    };

    explicit CertManager(Config cfg);
    ~CertManager();

    CertManager(const CertManager&)            = delete;
    CertManager& operator=(const CertManager&) = delete;

    /// Obtain or verify certificates (blocking, run at startup).
    void provision(std::mutex& acme_mutex,
                   std::unordered_map<std::string, std::string>& acme_challenges);

    /// Start the background renewal thread.
    void start_renewal(std::mutex& acme_mutex,
                       std::unordered_map<std::string, std::string>& acme_challenges,
                       SSL_CTX* ssl_ctx);

    /// Stop the renewal thread and join.
    void stop_renewal();

    const Config& config() const { return cfg_; }

private:
    static void save_challenges(
        const std::unordered_map<std::string, std::string>& challenges);

    Config              cfg_;
    std::atomic<bool>   stop_{false};
    std::thread         thread_;
};
