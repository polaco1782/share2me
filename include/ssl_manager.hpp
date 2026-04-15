#pragma once

#include <filesystem>
#include <string>

namespace ssl_mgr {

/// Generate a self-signed X.509 v3 certificate and RSA-2048 private key.
void generate_self_signed_cert(
    const std::filesystem::path& cert_path,
    const std::filesystem::path& key_path,
    const std::string& cn = "localhost",
    int days = 3650);

/// Returns true when the certificate at @cert_path expires within @threshold_days.
bool needs_renewal(const std::filesystem::path& cert_path, int threshold_days = 30);

/// Generate a fresh self-signed certificate only if needed.
/// Returns true if a new certificate was created.
bool ensure_certificates(
    const std::filesystem::path& cert_path,
    const std::filesystem::path& key_path,
    const std::string& cn = "localhost",
    int renewal_threshold_days = 30);

} // namespace ssl_mgr
