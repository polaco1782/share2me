// mime.hpp – MIME type lookup by file extension
#pragma once

#include <filesystem>
#include <string>
#include <unordered_map>

/// Guess a Content-Type from the file extension.
/// Falls back to application/octet-stream for unknown types.
inline std::string mime_for(const std::string& filename) {
    static const std::unordered_map<std::string, std::string> mimes = {
        {".html", "text/html"},
        {".htm",  "text/html"},
        {".css",  "text/css"},
        {".js",   "application/javascript"},
        {".json", "application/json"},
        {".png",  "image/png"},
        {".jpg",  "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".gif",  "image/gif"},
        {".svg",  "image/svg+xml"},
        {".pdf",  "application/pdf"},
        {".zip",  "application/zip"},
        {".gz",   "application/gzip"},
        {".tar",  "application/x-tar"},
        {".txt",  "text/plain"},
        {".csv",  "text/csv"},
        {".xml",  "application/xml"},
        {".mp3",  "audio/mpeg"},
        {".mp4",  "video/mp4"},
        {".webm", "video/webm"},
        {".wasm", "application/wasm"},
    };

    auto ext = std::filesystem::path(filename).extension().string();
    for (auto& c : ext)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (auto it = mimes.find(ext); it != mimes.end()) return it->second;
    return "application/octet-stream";
}
