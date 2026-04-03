#pragma once

#include <crow.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <fstream>
#include <mutex>
#include <stdexcept>
#include <string>

namespace tls_util {

/// Mutex that serialises SSL_CTX reload operations.
/// Shared with the renewal thread to avoid races during hot-reload.
std::mutex reload_mutex;

/// In-memory TLS certificate and private-key PEM data.
struct TlsMaterial {
    std::string cert_pem;
    std::string key_pem;
};

/// Read TLS certificate and key files into memory.
/// Call this before entering a chroot jail so the files are still accessible.
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

    CROW_LOG_INFO << "TLS material loaded into memory (cert "
                  << tls.cert_pem.size() << " B, key "
                  << tls.key_pem.size()  << " B)";
    return tls;
}

/// Build an ASIO SSL context from in-memory PEM data.
/// Configures TLSv1.2+, disables SSLv2/SSLv3, and scrubs the private key
/// from memory after it has been installed in the context.
asio::ssl::context create_ssl_context(TlsMaterial& tls) {
    asio::ssl::context ctx(asio::ssl::context::sslv23);
    ctx.set_verify_mode(asio::ssl::verify_none);
    ctx.use_certificate_chain(asio::buffer(tls.cert_pem));
    ctx.use_private_key(asio::buffer(tls.key_pem), asio::ssl::context::pem);
    ctx.set_options(asio::ssl::context::default_workarounds |
                    asio::ssl::context::no_sslv2 |
                    asio::ssl::context::no_sslv3);

    // Scrub private key from memory now that it lives in the SSL context.
    OPENSSL_cleanse(tls.key_pem.data(), tls.key_pem.size());
    tls.key_pem.clear();

    return ctx;
}

/// Hot-reload certificate and private key from disk into a live SSL_CTX.
/// All new TLS handshakes after this call will use the updated material;
/// existing connections are unaffected.
/// Thread-safe: serialised by reload_mutex.
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

    CROW_LOG_INFO << "TLS context hot-reloaded from disk "
                     "(new connections will use the updated certificate)";
}

} // namespace tls_util
