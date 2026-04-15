#pragma once

#include <nlohmann/json.hpp>

#include <filesystem>
#include <optional>
#include <string>

/// Result of a store_file() operation.
struct UploadResult {
    bool        ok      = false;
    std::string token;
    std::string sha256;
    std::string error;
};

/// Owns the data directory and provides all file-storage operations.
class FileStore {
public:
    explicit FileStore(std::filesystem::path data_dir = "data");

    /// Create the data directory on disk (idempotent).
    void create_directories() const;

    /// Current data directory path.
    const std::filesystem::path& data_dir() const;

    /// Change the data directory (e.g. after chroot).
    void set_data_dir(const std::filesystem::path& dir);

    /// Generate a random 16-character lowercase hex token.
    static std::string generate_token();

    /// Check if a path is safely within the data directory.
    bool is_path_safe(const std::filesystem::path& path) const;

    /// Validate filename for dangerous patterns.
    static bool is_filename_safe_for_storage(const std::string& filename);

    /// Write an uploaded file and its JSON metadata to the data directory.
    UploadResult store_file(const std::string& body,
                            const std::string& filename,
                            bool single_download,
                            long long expire_seconds = 0,
                            bool encrypted = false,
                            const std::string& content_type = "");

    /// Load the JSON metadata for the given token, or std::nullopt.
    std::optional<nlohmann::json> load_meta(const std::string& token) const;

    /// Returns true (and removes files) when the token has expired.
    bool check_and_remove_expired(const std::string& token,
                                  const nlohmann::json& meta) const;

private:
    std::filesystem::path data_dir_;
};
