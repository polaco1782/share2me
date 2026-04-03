#pragma once

#include <openssl/evp.h>

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

/// Compute SHA-256 of a memory buffer.
/// Returns a 64-character lowercase hex string.
std::string sha256_bytes(const void* data, std::size_t len) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  dlen = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < dlen; ++i)
        oss << std::setw(2) << static_cast<int>(digest[i]);
    return oss.str();
}

/// Compute SHA-256 of a file, streamed in 64 KiB chunks.
/// Returns an empty string if the file cannot be opened.
std::string sha256_file(const fs::path& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    constexpr std::size_t BUF_SIZE = 65536; // 64 KiB
    std::vector<char> buf(BUF_SIZE);
    while (ifs) {
        ifs.read(buf.data(), static_cast<std::streamsize>(BUF_SIZE));
        auto n = ifs.gcount();
        if (n > 0) EVP_DigestUpdate(ctx, buf.data(), static_cast<std::size_t>(n));
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  dlen = 0;
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < dlen; ++i)
        oss << std::setw(2) << static_cast<int>(digest[i]);
    return oss.str();
}
