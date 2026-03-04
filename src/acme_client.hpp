#pragma once
#ifdef HAVE_ACME_CLIENT

#include <nlohmann/json.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <curl/curl.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace acme {

namespace fs   = std::filesystem;
using     json = nlohmann::json;

// ===========================================================================
// Base64url (RFC 4648 §5, no padding)
// ===========================================================================
namespace detail {

static const char B64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

inline std::string b64url(const uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (std::size_t i = 0; i < len; i += 3) {
        uint32_t b = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) b |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) b |= static_cast<uint32_t>(data[i + 2]);
        out += B64URL_CHARS[(b >> 18) & 0x3F];
        out += B64URL_CHARS[(b >> 12) & 0x3F];
        if (i + 1 < len) out += B64URL_CHARS[(b >> 6) & 0x3F];
        if (i + 2 < len) out += B64URL_CHARS[ b       & 0x3F];
    }
    return out;
}

inline std::string b64url(const std::string& s) {
    return b64url(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// ===========================================================================
// Minimal HTTPS client via libcurl
// ===========================================================================
struct HttpResponse {
    long        status = 0;
    std::string body;
    std::map<std::string, std::string> headers; // lowercase keys
};

inline std::size_t curl_write(char* ptr, std::size_t sz, std::size_t n, void* ud) {
    static_cast<std::string*>(ud)->append(ptr, sz * n);
    return sz * n;
}

inline std::size_t curl_header(char* buf, std::size_t sz, std::size_t n, void* ud) {
    auto* hdrs = static_cast<std::map<std::string, std::string>*>(ud);
    std::string line(buf, sz * n);
    // strip trailing CRLF
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
        while (!val.empty() && val.front() == ' ') val.erase(val.begin());
        for (auto& c : key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        (*hdrs)[key] = val;
    }
    return sz * n;
}

struct CurlHandle {
    CURL* h;
    CurlHandle() : h(curl_easy_init()) {
        if (!h) throw std::runtime_error("curl_easy_init failed");
    }
    ~CurlHandle() { curl_easy_cleanup(h); }
};

struct CurlHeaders {
    curl_slist* list = nullptr;
    void add(const std::string& s) { list = curl_slist_append(list, s.c_str()); }
    ~CurlHeaders() { if (list) curl_slist_free_all(list); }
};

inline HttpResponse http_request(
    const std::string&              url,
    const std::string&              method,       // "GET", "HEAD", "POST"
    const std::string&              body = {},
    const std::vector<std::string>& extra_hdrs = {})
{
    CurlHandle   ch;
    CurlHeaders  ch_hdrs;
    HttpResponse resp;

    for (const auto& h : extra_hdrs) ch_hdrs.add(h);

    curl_easy_setopt(ch.h, CURLOPT_URL,        url.c_str());
    curl_easy_setopt(ch.h, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(ch.h, CURLOPT_USERAGENT,  "share2me-acme/1.0");
    curl_easy_setopt(ch.h, CURLOPT_FOLLOWLOCATION, 0L);

    if (!body.empty()) {
        curl_easy_setopt(ch.h, CURLOPT_POSTFIELDS,    body.c_str());
        curl_easy_setopt(ch.h, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    }
    if (ch_hdrs.list)
        curl_easy_setopt(ch.h, CURLOPT_HTTPHEADER, ch_hdrs.list);

    curl_easy_setopt(ch.h, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(ch.h, CURLOPT_WRITEDATA,     &resp.body);
    curl_easy_setopt(ch.h, CURLOPT_HEADERFUNCTION, curl_header);
    curl_easy_setopt(ch.h, CURLOPT_HEADERDATA,     &resp.headers);

    CURLcode rc = curl_easy_perform(ch.h);
    if (rc != CURLE_OK)
        throw std::runtime_error(std::string("curl: ") + curl_easy_strerror(rc));

    curl_easy_getinfo(ch.h, CURLINFO_RESPONSE_CODE, &resp.status);
    return resp;
}

// ===========================================================================
// OpenSSL crypto helpers (EC P-256, JWS ES256)
// ===========================================================================

/// Load or generate an EC P-256 account key stored at @p path (PEM).
inline EVP_PKEY* load_or_create_ec_key(const fs::path& path) {
    if (fs::exists(path)) {
        FILE* f = fopen(path.string().c_str(), "r");
        if (!f) throw std::runtime_error("Cannot open account key: " + path.string());
        EVP_PKEY* key = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
        fclose(f);
        if (!key) throw std::runtime_error("Failed to parse account key");
        return key;
    }

    EVP_PKEY* key = EVP_EC_gen("P-256");
    if (!key) throw std::runtime_error("EVP_EC_gen(P-256) failed");

    if (auto parent = path.parent_path(); !parent.empty())
        fs::create_directories(parent);

    FILE* f = fopen(path.string().c_str(), "wb");
    if (!f) { EVP_PKEY_free(key); throw std::runtime_error("Cannot create account key file"); }
    PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);
    fs::permissions(path,
        fs::perms::owner_read | fs::perms::owner_write,
        fs::perm_options::replace);
    return key;
}

/// Return base64url representation of the 32-byte big-endian BIGNUM @p bn.
inline std::string bn_b64url32(const BIGNUM* bn) {
    uint8_t buf[32] = {};
    BN_bn2binpad(bn, buf, 32);
    return b64url(buf, 32);
}

/// Build the JWK object for an EC P-256 public key.
inline json ec_jwk(EVP_PKEY* pkey) {
    BIGNUM* x = nullptr, *y = nullptr;
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
    json jwk = {
        {"kty", "EC"},
        {"crv", "P-256"},
        {"x",   bn_b64url32(x)},
        {"y",   bn_b64url32(y)},
    };
    BN_free(x); BN_free(y);
    return jwk;
}

/**
 * Compute the RFC 7638 JWK thumbprint (SHA-256 of canonical JSON, base64url).
 * Canonical member order for EC P-256: crv, kty, x, y.
 */
inline std::string jwk_thumbprint(EVP_PKEY* pkey) {
    auto jwk = ec_jwk(pkey);
    // Lexicographic order is required by RFC 7638
    std::string canonical =
        "{\"crv\":\"P-256\","
        "\"kty\":\"EC\","
        "\"x\":\"" + jwk["x"].get<std::string>() + "\","
        "\"y\":\"" + jwk["y"].get<std::string>() + "\"}";

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size(), hash);
    return b64url(hash, SHA256_DIGEST_LENGTH);
}

/**
 * Sign `data` using ECDSA/SHA-256 (ES256).
 * Returns base64url-encoded raw R||S (64 bytes, as required by JWS RFC 7518).
 */
inline std::string es256_sign(EVP_PKEY* pkey, const std::string& data) {
    // Digest-sign
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(mdctx,
        reinterpret_cast<const uint8_t*>(data.data()), data.size());

    std::size_t der_len = 0;
    EVP_DigestSignFinal(mdctx, nullptr, &der_len);
    std::vector<uint8_t> der(der_len);
    EVP_DigestSignFinal(mdctx, der.data(), &der_len);
    EVP_MD_CTX_free(mdctx);

    // Parse DER ECDSA signature → raw R||S (each 32 bytes, big-endian)
    const uint8_t* p = der.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der_len));
    if (!sig) throw std::runtime_error("Failed to parse ECDSA signature");

    const BIGNUM* r = nullptr, *s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);

    uint8_t raw[64] = {};
    BN_bn2binpad(r, raw,      32);
    BN_bn2binpad(s, raw + 32, 32);
    ECDSA_SIG_free(sig);

    return b64url(raw, 64);
}

/**
 * Build a JWS (JSON Web Signature) for an ACME POST request.
 *
 * @param payload   JSON body to sign. Pass json{} for POST-as-GET (empty payload).
 * @param url       The ACME endpoint URL (goes in "url" protected header).
 * @param nonce     Fresh replay nonce.
 * @param pkey      EC P-256 account key.
 * @param kid       Account URL (empty string → use JWK instead of kid).
 */
inline std::string make_jws(
    const json&        payload,
    const std::string& url,
    const std::string& nonce,
    EVP_PKEY*          pkey,
    const std::string& kid)
{
    json hdr;
    hdr["alg"]   = "ES256";
    hdr["nonce"] = nonce;
    hdr["url"]   = url;
    if (kid.empty())
        hdr["jwk"] = ec_jwk(pkey);
    else
        hdr["kid"] = kid;

    std::string protected_b64 = b64url(hdr.dump());
    // POST-as-GET: payload is null → base64url of empty string → ""
    std::string payload_b64   = payload.is_null() ? "" : b64url(payload.dump());

    std::string signing_input = protected_b64 + "." + payload_b64;
    std::string signature     = es256_sign(pkey, signing_input);

    return json{
        {"protected", protected_b64},
        {"payload",   payload_b64},
        {"signature", signature},
    }.dump();
}

// ===========================================================================
// ACME v2 directory + nonce
// ===========================================================================
struct Directory {
    std::string new_nonce;
    std::string new_account;
    std::string new_order;
};

inline Directory fetch_directory(const std::string& dir_url) {
    auto resp = http_request(dir_url, "GET", {}, {});
    if (resp.status != 200)
        throw std::runtime_error("ACME directory fetch failed: HTTP " + std::to_string(resp.status));
    auto j = json::parse(resp.body);
    return {
        j.at("newNonce").get<std::string>(),
        j.at("newAccount").get<std::string>(),
        j.at("newOrder").get<std::string>(),
    };
}

inline std::string fresh_nonce(const std::string& new_nonce_url) {
    auto resp = http_request(new_nonce_url, "HEAD", {}, {});
    auto it   = resp.headers.find("replay-nonce");
    if (it == resp.headers.end())
        throw std::runtime_error("ACME: no Replay-Nonce in newNonce response");
    return it->second;
}

// ---------------------------------------------------------------------------
// CSR generation
// ---------------------------------------------------------------------------

/**
 * Generate a fresh RSA-2048 domain key and a DER-encoded CSR for @p domain.
 * @p domain_key_out receives the new EVP_PKEY (caller must EVP_PKEY_free it).
 * Returns the base64url-encoded DER CSR.
 */
inline std::string generate_csr(const std::string& domain, EVP_PKEY*& domain_key_out) {
    domain_key_out = EVP_RSA_gen(2048);
    if (!domain_key_out) throw std::runtime_error("EVP_RSA_gen for domain key failed");

    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_version(req, 0); // v1

    X509_NAME* name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(domain.c_str()), -1, -1, 0);

    X509_REQ_set_pubkey(req, domain_key_out);

    // Add SAN extension to CSR
    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, req, nullptr, 0);
    std::string san_str = "DNS:" + domain;
    X509_EXTENSION* san = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, san_str.c_str());
    if (san) sk_X509_EXTENSION_push(exts, san);
    X509_REQ_add_extensions(req, exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    X509_REQ_sign(req, domain_key_out, EVP_sha256());

    // Convert to DER
    int   der_len = i2d_X509_REQ(req, nullptr);
    std::vector<uint8_t> der(static_cast<std::size_t>(der_len));
    uint8_t* dp = der.data();
    i2d_X509_REQ(req, &dp);
    X509_REQ_free(req);

    return b64url(der.data(), der.size());
}

} // namespace detail

// ===========================================================================
// AcmeClient – public interface
// ===========================================================================

/**
 * Minimal ACME v2 (RFC 8555) client for Let's Encrypt.
 *
 * Supports the HTTP-01 challenge only.  The caller supplies callbacks to
 * register / unregister the ephemeral challenge token with the HTTP server.
 */
class AcmeClient {
public:
    /// Let's Encrypt production and staging directory URLs.
    static constexpr const char* PRODUCTION =
        "https://acme-v02.api.letsencrypt.org/directory";
    static constexpr const char* STAGING =
        "https://acme-staging-v02.api.letsencrypt.org/directory";

    /**
     * @param work_dir  Directory used to persist the account key.
     * @param staging   Use Let's Encrypt staging (safe for testing).
     */
    explicit AcmeClient(const fs::path& work_dir, bool staging = false)
        : work_dir_(work_dir)
        , dir_url_(staging ? STAGING : PRODUCTION)
    {
        fs::create_directories(work_dir_);
        account_key_ = detail::load_or_create_ec_key(work_dir_ / "acme_account.pem");
        dir_          = detail::fetch_directory(dir_url_);
    }

    ~AcmeClient() {
        if (account_key_) EVP_PKEY_free(account_key_);
    }

    AcmeClient(const AcmeClient&)            = delete;
    AcmeClient& operator=(const AcmeClient&) = delete;

    /**
     * Obtain a certificate for @p domain via the HTTP-01 challenge.
     *
     * @param domain            The fully-qualified domain name.
     * @param email             Contact email for the ACME account.
     * @param cert_out          Where to write the PEM certificate chain.
     * @param key_out           Where to write the PEM private key.
     * @param serve_challenge   Called with (token, key_authorization) before
     *                          challenge validation is triggered.  The HTTP
     *                          server must respond to
     *                          GET /.well-known/acme-challenge/<token>
     *                          with <key_authorization>.
     * @param stop_challenge    Called with (token) after validation succeeds or
     *                          fails so the HTTP server can remove the route.
     *
     * Throws std::runtime_error on any ACME protocol error.
     */
    void request_certificate(
        const std::string& domain,
        const std::string& email,
        const fs::path&    cert_out,
        const fs::path&    key_out,
        std::function<void(const std::string& /*token*/,
                           const std::string& /*key_auth*/)> serve_challenge,
        std::function<void(const std::string& /*token*/)>    stop_challenge = {})
    {
        using namespace detail;

        // 1. Register / find account -----------------------------------------
        kid_ = register_account(email);

        // 2. Create order -----------------------------------------------------
        auto [order_url, order_json] = new_order(domain);

        // 3. Process the first authorization (HTTP-01) -------------------------
        std::string authz_url = order_json.at("authorizations").at(0).get<std::string>();
        auto [challenge_url, token] = get_http01_challenge(authz_url);

        // Key authorization = token + "." + JWK thumbprint
        std::string key_auth = token + "." + jwk_thumbprint(account_key_);

        // 4. Register challenge with HTTP server --------------------------------
        serve_challenge(token, key_auth);

        // 5. Trigger validation ------------------------------------------------
        trigger_challenge(challenge_url);

        // 6. Poll until order status is "ready" ---------------------------------
        poll_order_ready(order_url);
        if (stop_challenge) stop_challenge(token);

        // 7. Generate domain key + CSR -----------------------------------------
        EVP_PKEY* domain_key = nullptr;
        std::string csr_b64  = generate_csr(domain, domain_key);

        // Save domain private key
        {
            if (auto parent = key_out.parent_path(); !parent.empty())
                fs::create_directories(parent);
            FILE* f = fopen(key_out.string().c_str(), "wb");
            if (!f) { EVP_PKEY_free(domain_key);
                throw std::runtime_error("Cannot write domain key"); }
            PEM_write_PrivateKey(f, domain_key, nullptr, nullptr, 0, nullptr, nullptr);
            fclose(f);
            fs::permissions(key_out,
                fs::perms::owner_read | fs::perms::owner_write,
                fs::perm_options::replace);
            EVP_PKEY_free(domain_key);
        }

        // 8. Finalize order ----------------------------------------------------
        std::string finalize_url = order_json.at("finalize").get<std::string>();
        finalize_order(finalize_url, csr_b64);

        // 9. Poll until certificate is ready ------------------------------------
        std::string cert_url = poll_order_valid(order_url);

        // 10. Download certificate chain ---------------------------------------
        download_certificate(cert_url, cert_out);
    }

private:
    // ---- helpers -----------------------------------------------------------

    std::string nonce() { return detail::fresh_nonce(dir_.new_nonce); }

    detail::HttpResponse post_jws(const std::string& url, const json& payload) {
        std::string body = detail::make_jws(payload, url, nonce(), account_key_, kid_);
        auto resp = detail::http_request(url, "POST", body,
            {"Content-Type: application/jose+json"});
        // Refresh nonce from response if available
        if (auto it = resp.headers.find("replay-nonce"); it != resp.headers.end())
            ; // curl_header callback already stored it; we re-fetch per request
        return resp;
    }

    // POST-as-GET: fetch a resource authenticated with our account key
    detail::HttpResponse post_as_get(const std::string& url) {
        // In JWS POST-as-GET the payload is null (serialises to empty string "")
        std::string body = detail::make_jws(json(nullptr), url, nonce(), account_key_, kid_);
        return detail::http_request(url, "POST", body,
            {"Content-Type: application/jose+json"});
    }

    std::string register_account(const std::string& email) {
        json payload = {
            {"termsOfServiceAgreed", true},
            {"contact", {"mailto:" + email}},
        };
        auto resp = post_jws(dir_.new_account, payload);
        if (resp.status != 200 && resp.status != 201)
            throw std::runtime_error("ACME newAccount failed: HTTP " +
                std::to_string(resp.status) + "\n" + resp.body);

        auto it = resp.headers.find("location");
        if (it == resp.headers.end())
            throw std::runtime_error("ACME newAccount: no Location header");
        return it->second; // account URL (kid)
    }

    std::pair<std::string, json> new_order(const std::string& domain) {
        json payload = {
            {"identifiers", {{{"type", "dns"}, {"value", domain}}}},
        };
        auto resp = post_jws(dir_.new_order, payload);
        if (resp.status != 201)
            throw std::runtime_error("ACME newOrder failed: HTTP " +
                std::to_string(resp.status) + "\n" + resp.body);

        auto it = resp.headers.find("location");
        if (it == resp.headers.end())
            throw std::runtime_error("ACME newOrder: no Location header");

        return {it->second, json::parse(resp.body)};
    }

    // Returns {challenge_url, token}
    std::pair<std::string, std::string> get_http01_challenge(const std::string& authz_url) {
        auto resp = post_as_get(authz_url);
        if (resp.status != 200)
            throw std::runtime_error("ACME authorization fetch failed: HTTP " +
                std::to_string(resp.status));

        auto authz = json::parse(resp.body);
        for (const auto& ch : authz.at("challenges")) {
            if (ch.at("type").get<std::string>() == "http-01") {
                return {
                    ch.at("url").get<std::string>(),
                    ch.at("token").get<std::string>(),
                };
            }
        }
        throw std::runtime_error("ACME: no HTTP-01 challenge found in authorization");
    }

    void trigger_challenge(const std::string& challenge_url) {
        auto resp = post_jws(challenge_url, json::object()); // payload = {}
        if (resp.status != 200)
            throw std::runtime_error("ACME challenge trigger failed: HTTP " +
                std::to_string(resp.status) + "\n" + resp.body);
    }

    void poll_order_ready(const std::string& order_url, int max_tries = 30) {
        for (int i = 0; i < max_tries; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            auto resp = post_as_get(order_url);
            if (resp.status != 200)
                throw std::runtime_error("ACME poll failed: HTTP " + std::to_string(resp.status));
            auto j      = json::parse(resp.body);
            auto status = j.value("status", "");
            if (status == "ready") return;
            if (status == "invalid")
                throw std::runtime_error("ACME order became invalid: " + resp.body);
        }
        throw std::runtime_error("ACME order did not become ready in time");
    }

    void finalize_order(const std::string& finalize_url, const std::string& csr_b64) {
        json payload = {{"csr", csr_b64}};
        auto resp    = post_jws(finalize_url, payload);
        if (resp.status != 200)
            throw std::runtime_error("ACME finalize failed: HTTP " +
                std::to_string(resp.status) + "\n" + resp.body);
    }

    // Returns the certificate URL from the order
    std::string poll_order_valid(const std::string& order_url, int max_tries = 60) {
        for (int i = 0; i < max_tries; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            auto resp = post_as_get(order_url);
            if (resp.status != 200)
                throw std::runtime_error("ACME poll (valid) failed: HTTP " +
                    std::to_string(resp.status));
            auto j      = json::parse(resp.body);
            auto status = j.value("status", "");
            if (status == "valid") {
                if (!j.contains("certificate"))
                    throw std::runtime_error("ACME order valid but no certificate URL");
                return j.at("certificate").get<std::string>();
            }
            if (status == "invalid")
                throw std::runtime_error("ACME order became invalid during finalization: " + resp.body);
        }
        throw std::runtime_error("ACME order did not become valid in time");
    }

    void download_certificate(const std::string& cert_url, const fs::path& cert_out) {
        auto resp = post_as_get(cert_url);
        if (resp.status != 200)
            throw std::runtime_error("ACME certificate download failed: HTTP " +
                std::to_string(resp.status));

        if (auto parent = cert_out.parent_path(); !parent.empty())
            fs::create_directories(parent);

        std::ofstream ofs(cert_out);
        if (!ofs)
            throw std::runtime_error("Cannot write certificate to " + cert_out.string());
        ofs << resp.body;
    }

    // ---- state -------------------------------------------------------------
    fs::path         work_dir_;
    std::string      dir_url_;
    detail::Directory dir_;
    EVP_PKEY*        account_key_ = nullptr;
    std::string      kid_;          // account URL, populated after registration
};

} // namespace acme
#endif // HAVE_ACME_CLIENT
