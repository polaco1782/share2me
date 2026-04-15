#pragma once

#include <cstddef>
#include <filesystem>
#include <string>

/// Compute SHA-256 of a memory buffer.
/// Returns a 64-character lowercase hex string.
std::string sha256_bytes(const void* data, std::size_t len);

/// Compute SHA-256 of a file, streamed in 64 KiB chunks.
/// Returns an empty string if the file cannot be opened.
std::string sha256_file(const std::filesystem::path& path);
