#pragma once

#include "hash.hpp"
#include "mime.hpp"

#include <nlohmann/json.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

// Mutated to "/" after chroot(2) when --sandbox is active.
fs::path DATA_DIR = "data";

struct UploadResult {
    bool        ok      = false;
    std::string token;
    std::string sha256;
    std::string error;
};

/// Generate a random 16-character lowercase hex token used as the URL identifier.
/// Uses the full 64-bit mt19937_64 output (2^64 space) to resist brute-force.
std::string generate_token() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    std::uint64_t value = dist(rng);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << value;
    return oss.str();
}

/// Check if a path is safe for file operations (no symlink attacks).
/// Returns false if the path contains symlinks or is outside DATA_DIR.
bool is_path_safe(const fs::path& path, const fs::path& base_dir) {
    std::error_code ec;

    // Resolve to canonical path (follows symlinks)
    fs::path resolved = fs::canonical(path, ec);
    if (ec) {
        // File doesn't exist yet - check parent directory
        fs::path parent = path.parent_path();
        if (parent.empty() || parent == ".") {
            parent = base_dir;
        }
        resolved = fs::canonical(parent, ec);
        if (ec) return false;
        resolved /= path.filename();
    }

    // Get canonical base directory
    fs::path canonical_base = fs::canonical(base_dir, ec);
    if (ec) return false;

    // Ensure resolved path starts with base directory
    auto resolved_str = resolved.string();
    auto base_str = canonical_base.string();

    if (resolved_str.compare(0, base_str.size(), base_str) != 0) {
        return false;
    }

    // Ensure it's exactly under base (not just a prefix match)
    if (resolved_str.size() > base_str.size() &&
        resolved_str[base_str.size()] != '/') {
        return false;
    }

    return true;
}

/// Validate filename doesn't contain dangerous patterns for storage.
bool is_filename_safe_for_storage(const std::string& filename) {
    // Reject null bytes
    if (filename.find('\0') != std::string::npos) {
        return false;
    }

    // Reject path separators
    if (filename.find('/') != std::string::npos ||
        filename.find('\\') != std::string::npos) {
        return false;
    }

    // Reject parent directory references
    if (filename == ".." || filename == "." ||
        filename.find("../") != std::string::npos ||
        filename.find("..\\") != std::string::npos) {
        return false;
    }

    // Limit length
    if (filename.length() > 255) {
        return false;
    }

    return true;
}

UploadResult store_file(const std::string& body,
                                const std::string& filename,
                                bool single_download,
                                long long expire_seconds = 0,
                                bool encrypted = false,
                                const std::string& content_type = "") {
    UploadResult res;

    if (body.empty() || filename.empty()) {
        res.error = "No file provided";
        return res;
    }

    // Validate filename for storage safety
    if (!is_filename_safe_for_storage(filename)) {
        res.error = "Invalid filename";
        return res;
    }

    res.sha256 = sha256_bytes(body.data(), body.size());

    for (int attempts = 0; attempts < 20; ++attempts) {
        res.token = generate_token();
        if (!fs::exists(DATA_DIR / (res.token + ".json"))) break;
    }

    const std::string stored_as = res.token + "_" + filename;

    // Verify the final storage path is safe (no symlink attacks)
    fs::path full_path = DATA_DIR / stored_as;
    if (!is_path_safe(full_path, DATA_DIR)) {
        res.error = "Invalid storage path";
        return res;
    }

    {
        std::ofstream ofs(full_path, std::ios::binary);
        if (!ofs) {
            res.error = "Failed to open file for writing";
            return res;
        }
        ofs.write(body.data(), static_cast<std::streamsize>(body.size()));
        if (!ofs) {
            res.error = "Failed to write file";
            std::error_code ec;
            fs::remove(full_path, ec);
            return res;
        }
    }

    nlohmann::json meta;
    meta["id"]              = res.token;
    meta["hash"]            = res.sha256;
    meta["filename"]        = filename;
    meta["stored_as"]       = stored_as;
    meta["single_download"] = single_download;
    meta["encrypted"]       = encrypted;
    meta["content_type"]    = content_type.empty() ? mime_for(filename) : content_type;
    if (expire_seconds > 0) {
        long long now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        meta["expires_at"] = now_sec + expire_seconds;
    }
    {
        std::ofstream ofs(DATA_DIR / (res.token + ".json"));
        if (!ofs) {
            res.error = "Failed to write metadata";
            std::error_code ec;
            fs::remove(full_path, ec);
            return res;
        }
        ofs << meta.dump(2);
    }

    res.ok = true;
    return res;
}