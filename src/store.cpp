#include "store.hpp"
#include "hash.hpp"
#include "mime.hpp"
#include "logging.hpp"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>

namespace fs = std::filesystem;

FileStore::FileStore(fs::path data_dir)
    : data_dir_(std::move(data_dir))
{}

void FileStore::create_directories() const {
    fs::create_directories(data_dir_);
}

const fs::path& FileStore::data_dir() const {
    return data_dir_;
}

void FileStore::set_data_dir(const fs::path& dir) {
    data_dir_ = dir;
}

std::string FileStore::generate_token() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    std::uint64_t value = dist(rng);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << value;
    return oss.str();
}

bool FileStore::is_path_safe(const fs::path& path) const {
    std::error_code ec;

    // Resolve to canonical path (follows symlinks)
    fs::path resolved = fs::canonical(path, ec);
    if (ec) {
        // File doesn't exist yet - check parent directory
        fs::path parent = path.parent_path();
        if (parent.empty() || parent == ".")
            parent = data_dir_;
        resolved = fs::canonical(parent, ec);
        if (ec) return false;
        resolved /= path.filename();
    }

    // Get canonical base directory
    fs::path canonical_base = fs::canonical(data_dir_, ec);
    if (ec) return false;

    // Ensure resolved path starts with base directory
    auto resolved_str = resolved.string();
    auto base_str = canonical_base.string();

    if (resolved_str.compare(0, base_str.size(), base_str) != 0)
        return false;

    // Ensure it's exactly under base (not just a prefix match)
    if (resolved_str.size() > base_str.size() &&
        resolved_str[base_str.size()] != '/')
        return false;

    return true;
}

bool FileStore::is_filename_safe_for_storage(const std::string& filename) {
    if (filename.find('\0') != std::string::npos) return false;
    if (filename.find('/') != std::string::npos ||
        filename.find('\\') != std::string::npos) return false;
    if (filename == ".." || filename == "." ||
        filename.find("../") != std::string::npos ||
        filename.find("..\\") != std::string::npos) return false;
    if (filename.length() > 255) return false;
    return true;
}

UploadResult FileStore::store_file(const std::string& body,
                                   const std::string& filename,
                                   bool single_download,
                                   long long expire_seconds,
                                   bool encrypted,
                                   const std::string& content_type) {
    UploadResult res;

    if (body.empty() || filename.empty()) {
        res.error = "No file provided";
        return res;
    }

    if (!is_filename_safe_for_storage(filename)) {
        res.error = "Invalid filename";
        return res;
    }

    res.sha256 = sha256_bytes(body.data(), body.size());

    for (int attempts = 0; attempts < 20; ++attempts) {
        res.token = generate_token();
        if (!fs::exists(data_dir_ / (res.token + ".json"))) break;
    }

    const std::string stored_as = res.token + "_" + filename;
    fs::path full_path = data_dir_ / stored_as;

    if (!is_path_safe(full_path)) {
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
        std::ofstream ofs(data_dir_ / (res.token + ".json"));
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

std::optional<nlohmann::json> FileStore::load_meta(const std::string& token) const {
    fs::path meta_path = data_dir_ / (token + ".json");
    std::ifstream ifs(meta_path);
    if (!ifs) return std::nullopt;
    nlohmann::json meta;
    try { ifs >> meta; } catch (...) { return std::nullopt; }
    return meta;
}

bool FileStore::check_and_remove_expired(const std::string& token,
                                         const nlohmann::json& meta) const {
    if (!meta.contains("expires_at")) return false;
    long long expires_at = meta["expires_at"].get<long long>();
    long long now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (now_sec < expires_at) return false;

    fs::path meta_path = data_dir_ / (token + ".json");
    std::string stored_as = meta.value("stored_as", "");
    std::error_code ec;
    fs::remove(meta_path, ec);
    if (!stored_as.empty()) fs::remove(data_dir_ / stored_as, ec);
    LOG_INFO << "Expired on access: " << token;
    return true;
}
