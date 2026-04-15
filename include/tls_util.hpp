#pragma once

#include <openssl/ssl.h>

#include <string>

namespace tls_util {

struct TlsMaterial {
    std::string cert_pem;
    std::string key_pem;
};

/// Read cert + key from disk into memory strings.
TlsMaterial load_files(const std::string& cert_path, const std::string& key_path);

/// Create a fresh SSL_CTX from in-memory PEM.  Scrubs the key material.
/// Caller owns the returned context.
SSL_CTX* create_ssl_context(TlsMaterial& tls);

/// Hot-reload cert + key from disk into an existing SSL_CTX.
void reload_from_files(SSL_CTX* ctx,
                       const std::string& cert_path,
                       const std::string& key_path);

} // namespace tls_util
