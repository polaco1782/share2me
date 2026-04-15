#include "tls_util.hpp"
#include "logging.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <fstream>
#include <mutex>
#include <stdexcept>

namespace tls_util {

namespace {
/// Mutex that serialises SSL_CTX reload operations.
std::mutex reload_mutex;
} // anonymous namespace

TlsMaterial load_files(const std::string& cert_path,
                       const std::string& key_path)
{
    auto slurp = [](const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) throw std::runtime_error("Cannot open TLS file: " + path);
        return std::string(std::istreambuf_iterator<char>(f), {});
    };

    TlsMaterial tls;
    tls.cert_pem = slurp(cert_path);
    tls.key_pem  = slurp(key_path);

    LOG_INFO << "TLS material loaded into memory (cert "
             << tls.cert_pem.size() << " B, key "
             << tls.key_pem.size()  << " B)";
    return tls;
}

SSL_CTX* create_ssl_context(TlsMaterial& tls) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx)
        throw std::runtime_error("SSL_CTX_new failed");

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // Load certificate chain from memory
    BIO* cert_bio = BIO_new_mem_buf(tls.cert_pem.data(), static_cast<int>(tls.cert_pem.size()));
    if (!cert_bio) { SSL_CTX_free(ctx); throw std::runtime_error("BIO_new_mem_buf for cert failed"); }
    X509* cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    if (!cert) { BIO_free(cert_bio); SSL_CTX_free(ctx); throw std::runtime_error("PEM_read_bio_X509 failed"); }
    if (SSL_CTX_use_certificate(ctx, cert) != 1) {
        X509_free(cert); BIO_free(cert_bio); SSL_CTX_free(ctx);
        throw std::runtime_error("SSL_CTX_use_certificate failed");
    }
    X509_free(cert);
    while (true) {
        X509* chain_cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
        if (!chain_cert) break;
        SSL_CTX_add_extra_chain_cert(ctx, chain_cert);
    }
    BIO_free(cert_bio);

    BIO* key_bio = BIO_new_mem_buf(tls.key_pem.data(), static_cast<int>(tls.key_pem.size()));
    if (!key_bio) { SSL_CTX_free(ctx); throw std::runtime_error("BIO_new_mem_buf for key failed"); }
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(key_bio);
    if (!pkey) { SSL_CTX_free(ctx); throw std::runtime_error("PEM_read_bio_PrivateKey failed"); }
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        EVP_PKEY_free(pkey); SSL_CTX_free(ctx);
        throw std::runtime_error("SSL_CTX_use_PrivateKey failed");
    }
    EVP_PKEY_free(pkey);

    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error("SSL_CTX_check_private_key failed");
    }

    OPENSSL_cleanse(tls.key_pem.data(), tls.key_pem.size());
    tls.key_pem.clear();

    return ctx;
}

void reload_from_files(SSL_CTX* ctx,
                       const std::string& cert_path,
                       const std::string& key_path)
{
    std::lock_guard lock(reload_mutex);

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path.c_str()) != 1) {
        unsigned long e = ERR_get_error();
        char buf[256] = {};
        ERR_error_string_n(e, buf, sizeof(buf));
        throw std::runtime_error(
            std::string("SSL_CTX reload cert failed: ") + buf);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        unsigned long e = ERR_get_error();
        char buf[256] = {};
        ERR_error_string_n(e, buf, sizeof(buf));
        throw std::runtime_error(
            std::string("SSL_CTX reload key failed: ") + buf);
    }

    if (SSL_CTX_check_private_key(ctx) != 1)
        throw std::runtime_error("SSL_CTX reload: private key does not match certificate");

    LOG_INFO << "TLS context hot-reloaded from disk "
                "(new connections will use the updated certificate)";
}

} // namespace tls_util
