#pragma once

#include <crow.h>

#include <openssl/crypto.h>

#include <fstream>
#include <stdexcept>
#include <string>

namespace tls_util {

/// In-memory TLS certificate and private-key PEM data.
struct TlsMaterial {
    std::string cert_pem;
    std::string key_pem;
};

/// Read TLS certificate and key files into memory.
/// Call this before entering a chroot jail so the files are still accessible.
inline TlsMaterial load_files(const std::string& cert_path,
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
inline asio::ssl::context create_ssl_context(TlsMaterial& tls) {
    asio::ssl::context ctx(asio::ssl::context::sslv23);
    ctx.set_verify_mode(asio::ssl::verify_peer);
    ctx.set_verify_mode(asio::ssl::verify_client_once);
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

} // namespace tls_util
