#pragma once

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <filesystem>
#include <functional>
#include <map>
#include <string>

namespace acme {

namespace fs = std::filesystem;

struct HttpResponse {
    long        status = 0;
    std::string body;
    std::map<std::string, std::string> headers; // lowercase keys
};

struct Directory {
    std::string new_nonce;
    std::string new_account;
    std::string new_order;
};

class AcmeClient {
public:
    static constexpr const char* PRODUCTION =
        "https://acme-v02.api.letsencrypt.org/directory";
    static constexpr const char* STAGING =
        "https://acme-staging-v02.api.letsencrypt.org/directory";

    explicit AcmeClient(const fs::path& work_dir,
                        bool staging = false,
                        bool verbose = false);
    ~AcmeClient();

    AcmeClient(const AcmeClient&)            = delete;
    AcmeClient& operator=(const AcmeClient&) = delete;

    void request_certificate(
        const std::string& domain,
        const std::string& email,
        const fs::path&    cert_out,
        const fs::path&    key_out,
        std::function<void(const std::string&, const std::string&)> serve_challenge,
        std::function<void(const std::string&)> stop_challenge = {});

private:

    std::string  nonce();
    HttpResponse post_jws(const std::string& url,
                          const nlohmann::json& payload);
    HttpResponse post_as_get(const std::string& url);
    void         vlog(const std::string& msg) const;

    std::string register_account(const std::string& email);
    std::pair<std::string, nlohmann::json> new_order(const std::string& domain);
    std::pair<std::string, std::string> get_http01_challenge(
        const std::string& authz_url);
    void trigger_challenge(const std::string& challenge_url);
    void poll_order_ready(const std::string& order_url, int max_tries = 30);
    void finalize_order(const std::string& finalize_url,
                        const std::string& csr_b64);
    std::string poll_order_valid(const std::string& order_url,
                                 int max_tries = 60);
    void download_certificate(const std::string& cert_url,
                              const fs::path& cert_out);

    fs::path    work_dir_;
    std::string dir_url_;
    Directory   dir_;
    EVP_PKEY*   account_key_ = nullptr;
    std::string kid_;
    bool        verbose_     = false;
};

} // namespace acme
