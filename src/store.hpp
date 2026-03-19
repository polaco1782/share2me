#pragma once

#include "hash.hpp"
#include "token.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

// Mutated to "/" after chroot(2) when --sandbox is active.
inline fs::path DATA_DIR = "data";

struct UploadResult {
    bool        ok      = false;
    std::string token;
    std::string sha256;
    std::string error;
};

inline UploadResult store_file(const std::string& body,
                                const std::string& filename,
                                bool single_download,
                                long long expire_seconds = 0,
                                bool encrypted = false) {
    UploadResult res;

    if (body.empty() || filename.empty()) {
        res.error = "No file provided";
        return res;
    }

    res.sha256 = sha256_bytes(body.data(), body.size());

    for (int attempts = 0; attempts < 20; ++attempts) {
        res.token = generate_token();
        if (!fs::exists(DATA_DIR / (res.token + ".json"))) break;
    }

    const std::string stored_as = res.token + "_" + filename;

    {
        std::ofstream ofs(DATA_DIR / stored_as, std::ios::binary);
        ofs.write(body.data(), static_cast<std::streamsize>(body.size()));
    }

    nlohmann::json meta;
    meta["id"]              = res.token;
    meta["hash"]            = res.sha256;
    meta["filename"]        = filename;
    meta["stored_as"]       = stored_as;
    meta["single_download"] = single_download;
    meta["encrypted"]       = encrypted;
    if (expire_seconds > 0) {
        long long now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        meta["expires_at"] = now_sec + expire_seconds;
    }
    {
        std::ofstream ofs(DATA_DIR / (res.token + ".json"));
        ofs << meta.dump(2);
    }

    res.ok = true;
    return res;
}
