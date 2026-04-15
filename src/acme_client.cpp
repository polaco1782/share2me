#include "acme_client.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <httplib.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <thread>
#include <vector>

namespace acme {

namespace fs   = std::filesystem;
using     json = nlohmann::json;

// ===========================================================================
// Anonymous namespace — internal helpers (previously in detail::)
// ===========================================================================
namespace {

const char B64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64url(const uint8_t* data, std::size_t len) {
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

std::string b64url(const std::string& s) {
    return b64url(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

bool is_ip_address(const std::string& s) {
    struct in_addr  v4;
    struct in6_addr v6;
    return inet_pton(AF_INET,  s.c_str(), &v4) == 1 ||
           inet_pton(AF_INET6, s.c_str(), &v6) == 1;
}

// ---------------------------------------------------------------------------
// URL parsing + HTTP client
// ---------------------------------------------------------------------------
struct ParsedUrl {
    std::string scheme;
    std::string host;
    int         port = 443;
    std::string path;
};

ParsedUrl parse_url(const std::string& url) {
    ParsedUrl u;
    std::string rest;
    if (url.compare(0, 8, "https://") == 0) {
        u.scheme = "https"; u.port = 443; rest = url.substr(8);
    } else if (url.compare(0, 7, "http://") == 0) {
        u.scheme = "http"; u.port = 80; rest = url.substr(7);
    } else {
        throw std::runtime_error("Unsupported URL scheme: " + url);
    }

    auto slash = rest.find('/');
    std::string authority;
    if (slash != std::string::npos) {
        authority = rest.substr(0, slash);
        u.path = rest.substr(slash);
    } else {
        authority = rest;
        u.path = "/";
    }

    if (!authority.empty() && authority[0] == '[') {
        auto bracket = authority.find(']');
        if (bracket != std::string::npos) {
            u.host = authority.substr(0, bracket + 1);
            if (bracket + 1 < authority.size() && authority[bracket + 1] == ':')
                u.port = std::stoi(authority.substr(bracket + 2));
        } else {
            u.host = authority;
        }
    } else {
        auto colon = authority.rfind(':');
        if (colon != std::string::npos) {
            u.host = authority.substr(0, colon);
            u.port = std::stoi(authority.substr(colon + 1));
        } else {
            u.host = authority;
        }
    }

    return u;
}

HttpResponse http_request(
    const std::string&              url,
    const std::string&              method,
    const std::string&              body = {},
    const std::vector<std::string>& extra_hdrs = {},
    bool                            verbose = false)
{
    (void)verbose;
    auto parsed = parse_url(url);
    std::string base = parsed.scheme + "://" + parsed.host + ":"
                     + std::to_string(parsed.port);

    httplib::Client cli(base);
    cli.set_connection_timeout(30, 0);
    cli.set_read_timeout(60, 0);
    cli.set_write_timeout(60, 0);
    cli.set_follow_location(false);

    httplib::Headers hdrs;
    hdrs.emplace("User-Agent", "share2me-acme/1.0");
    for (const auto& h : extra_hdrs) {
        auto colon = h.find(':');
        if (colon != std::string::npos) {
            std::string key = h.substr(0, colon);
            std::string val = h.substr(colon + 1);
            while (!val.empty() && val.front() == ' ') val.erase(val.begin());
            hdrs.emplace(key, val);
        }
    }

    httplib::Result res(nullptr, httplib::Error::Unknown);
    if (method == "GET") {
        res = cli.Get(parsed.path, hdrs);
    } else if (method == "HEAD") {
        res = cli.Head(parsed.path, hdrs);
    } else if (method == "POST") {
        std::string content_type = "application/octet-stream";
        for (auto& [k, v] : hdrs) {
            std::string lk = k;
            for (auto& c : lk)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lk == "content-type") { content_type = v; break; }
        }
        res = cli.Post(parsed.path, hdrs, body, content_type);
    } else {
        throw std::runtime_error("Unsupported HTTP method: " + method);
    }

    if (!res) {
        auto err = res.error();
        throw std::runtime_error(
            std::string("HTTP request failed: ") + httplib::to_string(err));
    }

    HttpResponse resp;
    resp.status = res->status;
    resp.body   = res->body;
    for (auto& [k, v] : res->headers) {
        std::string lk = k;
        for (auto& c : lk)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        resp.headers[lk] = v;
    }

    return resp;
}

// ---------------------------------------------------------------------------
// OpenSSL crypto helpers
// ---------------------------------------------------------------------------
EVP_PKEY* load_or_create_ec_key(const fs::path& path) {
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

std::string bn_b64url32(const BIGNUM* bn) {
    uint8_t buf[32] = {};
    BN_bn2binpad(bn, buf, 32);
    return b64url(buf, 32);
}

json ec_jwk(EVP_PKEY* pkey) {
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

std::string jwk_thumbprint(EVP_PKEY* pkey) {
    auto jwk = ec_jwk(pkey);
    std::string canonical =
        "{\"crv\":\"P-256\","
        "\"kty\":\"EC\","
        "\"x\":\"" + jwk["x"].get<std::string>() + "\","
        "\"y\":\"" + jwk["y"].get<std::string>() + "\"}";

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(canonical.data()),
           canonical.size(), hash);
    return b64url(hash, SHA256_DIGEST_LENGTH);
}

std::string es256_sign(EVP_PKEY* pkey, const std::string& data) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(mdctx,
        reinterpret_cast<const uint8_t*>(data.data()), data.size());

    std::size_t der_len = 0;
    EVP_DigestSignFinal(mdctx, nullptr, &der_len);
    std::vector<uint8_t> der(der_len);
    EVP_DigestSignFinal(mdctx, der.data(), &der_len);
    EVP_MD_CTX_free(mdctx);

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

std::string make_jws(
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
    std::string payload_b64   = payload.is_null() ? "" : b64url(payload.dump());

    std::string signing_input = protected_b64 + "." + payload_b64;
    std::string signature     = es256_sign(pkey, signing_input);

    return json{
        {"protected", protected_b64},
        {"payload",   payload_b64},
        {"signature", signature},
    }.dump();
}

Directory fetch_directory(const std::string& dir_url,
                                      bool verbose = false) {
    auto resp = http_request(dir_url, "GET", {}, {}, verbose);
    if (resp.status != 200)
        throw std::runtime_error("ACME directory fetch failed: HTTP "
                                 + std::to_string(resp.status));
    auto j = json::parse(resp.body);
    return {
        j.at("newNonce").get<std::string>(),
        j.at("newAccount").get<std::string>(),
        j.at("newOrder").get<std::string>(),
    };
}

std::string fresh_nonce(const std::string& new_nonce_url,
                        bool verbose = false) {
    auto resp = http_request(new_nonce_url, "HEAD", {}, {}, verbose);
    auto it   = resp.headers.find("replay-nonce");
    if (it == resp.headers.end())
        throw std::runtime_error("ACME: no Replay-Nonce in newNonce response");
    return it->second;
}

std::string generate_csr(const std::string& domain,
                         EVP_PKEY*& domain_key_out) {
    domain_key_out = EVP_RSA_gen(2048);
    if (!domain_key_out)
        throw std::runtime_error("EVP_RSA_gen for domain key failed");

    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_version(req, 0);

    if (!is_ip_address(domain)) {
        X509_NAME* name = X509_REQ_get_subject_name(req);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(domain.c_str()), -1, -1, 0);
    }

    X509_REQ_set_pubkey(req, domain_key_out);

    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, req, nullptr, 0);
    std::string san_str = (is_ip_address(domain) ? "IP:" : "DNS:") + domain;
    X509_EXTENSION* san = X509V3_EXT_conf_nid(nullptr, &ctx,
        NID_subject_alt_name, san_str.c_str());
    if (san) sk_X509_EXTENSION_push(exts, san);
    X509_REQ_add_extensions(req, exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    X509_REQ_sign(req, domain_key_out, EVP_sha256());

    int der_len = i2d_X509_REQ(req, nullptr);
    std::vector<uint8_t> der(static_cast<std::size_t>(der_len));
    uint8_t* dp = der.data();
    i2d_X509_REQ(req, &dp);
    X509_REQ_free(req);

    return b64url(der.data(), der.size());
}

} // anonymous namespace

// ===========================================================================
// AcmeClient implementation
// ===========================================================================

AcmeClient::AcmeClient(const fs::path& work_dir, bool staging, bool verbose)
    : work_dir_(work_dir)
    , dir_url_(staging ? STAGING : PRODUCTION)
    , verbose_(verbose)
{
    fs::create_directories(work_dir_);
    account_key_ = load_or_create_ec_key(work_dir_ / "acme_account.pem");
    dir_         = fetch_directory(dir_url_, verbose_);
}

AcmeClient::~AcmeClient() {
    if (account_key_) EVP_PKEY_free(account_key_);
}

void AcmeClient::request_certificate(
    const std::string& domain,
    const std::string& email,
    const fs::path&    cert_out,
    const fs::path&    key_out,
    std::function<void(const std::string&, const std::string&)> serve_challenge,
    std::function<void(const std::string&)> stop_challenge)
{
    vlog("1/10 registering account for " + email);
    kid_ = register_account(email);
    vlog("     kid: " + kid_);

    vlog("2/10 creating order for " + domain);
    auto [order_url, order_json] = new_order(domain);
    vlog("     order: " + order_url);

    vlog("3/10 fetching HTTP-01 authorization");
    std::string authz_url =
        order_json.at("authorizations").at(0).get<std::string>();
    auto [challenge_url, token] = get_http01_challenge(authz_url);
    vlog("     token: " + token);

    std::string key_auth = token + "." + jwk_thumbprint(account_key_);

    vlog("4/10 registering challenge token with local HTTP server");
    serve_challenge(token, key_auth);

    vlog("5/10 triggering ACME validation");
    trigger_challenge(challenge_url);

    vlog("6/10 polling order for 'ready' status (max 60 s)...");
    poll_order_ready(order_url);
    vlog("     order is ready");
    if (stop_challenge) stop_challenge(token);

    vlog("7/10 generating domain key and CSR");
    EVP_PKEY* domain_key = nullptr;
    std::string csr_b64 = generate_csr(domain, domain_key);

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

    vlog("8/10 finalizing order");
    std::string finalize_url = order_json.at("finalize").get<std::string>();
    finalize_order(finalize_url, csr_b64);

    vlog("9/10 polling order for 'valid' status (max 120 s)...");
    std::string cert_url = poll_order_valid(order_url);
    vlog("     cert url: " + cert_url);

    vlog("10/10 downloading certificate chain");
    download_certificate(cert_url, cert_out);
    vlog("      certificate saved to " + cert_out.string());
}

std::string AcmeClient::nonce() {
    return fresh_nonce(dir_.new_nonce, verbose_);
}

HttpResponse AcmeClient::post_jws(
    const std::string& url, const json& payload) {
    vlog("POST-JWS -> " + url);
    std::string body = make_jws(payload, url, nonce(), account_key_, kid_);
    vlog("         signing done, sending request...");
    auto resp = http_request(url, "POST", body,
        {"Content-Type: application/jose+json"}, verbose_);
    vlog("         <- HTTP " + std::to_string(resp.status));
    return resp;
}

HttpResponse AcmeClient::post_as_get(const std::string& url) {
    vlog("POST-as-GET -> " + url);
    std::string body = make_jws(json(nullptr), url, nonce(), account_key_, kid_);
    auto resp = http_request(url, "POST", body,
        {"Content-Type: application/jose+json"}, verbose_);
    vlog("             <- HTTP " + std::to_string(resp.status));
    return resp;
}

void AcmeClient::vlog(const std::string& msg) const {
    fprintf(stderr, "[ACME] %s\n", msg.c_str());
    fflush(stderr);
}

std::string AcmeClient::register_account(const std::string& email) {
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
    return it->second;
}

std::pair<std::string, json> AcmeClient::new_order(const std::string& domain) {
    const bool        is_ip   = is_ip_address(domain);
    const std::string id_type = is_ip ? "ip" : "dns";
    const std::string profile = is_ip ? "shortlived" : "classic";
    json payload = {
        {"identifiers", {{{"type", id_type}, {"value", domain}}}},
        {"profile",     profile},
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

std::pair<std::string, std::string> AcmeClient::get_http01_challenge(
    const std::string& authz_url) {
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

void AcmeClient::trigger_challenge(const std::string& challenge_url) {
    auto resp = post_jws(challenge_url, json::object());
    if (resp.status != 200)
        throw std::runtime_error("ACME challenge trigger failed: HTTP " +
            std::to_string(resp.status) + "\n" + resp.body);
}

void AcmeClient::poll_order_ready(const std::string& order_url,
                                  int max_tries) {
    for (int i = 0; i < max_tries; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        auto resp = post_as_get(order_url);
        if (resp.status != 200)
            throw std::runtime_error("ACME poll failed: HTTP "
                                     + std::to_string(resp.status));
        auto j      = json::parse(resp.body);
        auto status = j.value("status", "");
        if (status == "ready") return;
        if (status == "invalid")
            throw std::runtime_error("ACME order became invalid: " + resp.body);
    }
    throw std::runtime_error("ACME order did not become ready in time");
}

void AcmeClient::finalize_order(const std::string& finalize_url,
                                const std::string& csr_b64) {
    json payload = {{"csr", csr_b64}};
    auto resp    = post_jws(finalize_url, payload);
    if (resp.status != 200)
        throw std::runtime_error("ACME finalize failed: HTTP " +
            std::to_string(resp.status) + "\n" + resp.body);
}

std::string AcmeClient::poll_order_valid(const std::string& order_url,
                                         int max_tries) {
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
                throw std::runtime_error(
                    "ACME order valid but no certificate URL");
            return j.at("certificate").get<std::string>();
        }
        if (status == "invalid")
            throw std::runtime_error(
                "ACME order became invalid during finalization: " + resp.body);
    }
    throw std::runtime_error("ACME order did not become valid in time");
}

void AcmeClient::download_certificate(const std::string& cert_url,
                                      const fs::path& cert_out) {
    auto resp = post_as_get(cert_url);
    if (resp.status != 200)
        throw std::runtime_error("ACME certificate download failed: HTTP " +
            std::to_string(resp.status));
    if (auto parent = cert_out.parent_path(); !parent.empty())
        fs::create_directories(parent);
    std::ofstream ofs(cert_out);
    if (!ofs)
        throw std::runtime_error("Cannot write certificate to "
                                 + cert_out.string());
    ofs << resp.body;
}

} // namespace acme
