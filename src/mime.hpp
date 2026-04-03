#pragma once

#include <filesystem>
#include <string>
#include <unordered_map>

/// Guess a Content-Type from the file extension.
/// Falls back to application/octet-stream for unknown types.
std::string mime_for(const std::string& filename) {
    static const std::unordered_map<std::string, std::string> mimes = {
        // Text / web
        {".html",  "text/html"},
        {".htm",   "text/html"},
        {".css",   "text/css"},
        {".js",    "application/javascript"},
        {".mjs",   "application/javascript"},
        {".json",  "application/json"},
        {".xml",   "application/xml"},
        {".txt",   "text/plain"},
        {".csv",   "text/csv"},
        {".tsv",   "text/tab-separated-values"},
        {".md",    "text/markdown"},
        {".rtf",   "application/rtf"},
        {".yaml",  "text/yaml"},
        {".yml",   "text/yaml"},
        {".toml",  "application/toml"},
        {".ini",   "text/plain"},
        {".log",   "text/plain"},
        {".conf",  "text/plain"},
        {".cfg",   "text/plain"},

        // Images
        {".png",   "image/png"},
        {".jpg",   "image/jpeg"},
        {".jpeg",  "image/jpeg"},
        {".gif",   "image/gif"},
        {".svg",   "image/svg+xml"},
        {".webp",  "image/webp"},
        {".avif",  "image/avif"},
        {".bmp",   "image/bmp"},
        {".ico",   "image/x-icon"},
        {".tif",   "image/tiff"},
        {".tiff",  "image/tiff"},
        {".heic",  "image/heic"},
        {".heif",  "image/heif"},
        {".jxl",   "image/jxl"},
        {".psd",   "image/vnd.adobe.photoshop"},
        {".raw",   "image/x-raw"},

        // Audio
        {".mp3",   "audio/mpeg"},
        {".ogg",   "audio/ogg"},
        {".wav",   "audio/wav"},
        {".flac",  "audio/flac"},
        {".aac",   "audio/aac"},
        {".m4a",   "audio/mp4"},
        {".wma",   "audio/x-ms-wma"},
        {".opus",  "audio/opus"},
        {".mid",   "audio/midi"},
        {".midi",  "audio/midi"},
        {".aiff",  "audio/aiff"},

        // Video
        {".mp4",   "video/mp4"},
        {".webm",  "video/webm"},
        {".mkv",   "video/x-matroska"},
        {".avi",   "video/x-msvideo"},
        {".mov",   "video/quicktime"},
        {".wmv",   "video/x-ms-wmv"},
        {".flv",   "video/x-flv"},
        {".m4v",   "video/mp4"},
        {".mpeg",  "video/mpeg"},
        {".mpg",   "video/mpeg"},
        {".3gp",   "video/3gpp"},
        {".ts",    "video/mp2t"},

        // Archives / compressed
        {".zip",   "application/zip"},
        {".gz",    "application/gzip"},
        {".tar",   "application/x-tar"},
        {".bz2",   "application/x-bzip2"},
        {".xz",    "application/x-xz"},
        {".zst",   "application/zstd"},
        {".7z",    "application/x-7z-compressed"},
        {".rar",   "application/vnd.rar"},
        {".lz4",   "application/x-lz4"},
        {".tgz",   "application/gzip"},
        {".tbz2",  "application/x-bzip2"},

        // Documents
        {".pdf",   "application/pdf"},
        {".doc",   "application/msword"},
        {".docx",  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {".xls",   "application/vnd.ms-excel"},
        {".xlsx",  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {".ppt",   "application/vnd.ms-powerpoint"},
        {".pptx",  "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {".odt",   "application/vnd.oasis.opendocument.text"},
        {".ods",   "application/vnd.oasis.opendocument.spreadsheet"},
        {".odp",   "application/vnd.oasis.opendocument.presentation"},
        {".epub",  "application/epub+zip"},

        // Fonts
        {".woff",  "font/woff"},
        {".woff2", "font/woff2"},
        {".ttf",   "font/ttf"},
        {".otf",   "font/otf"},
        {".eot",   "application/vnd.ms-fontobject"},

        // Executables / packages
        {".exe",   "application/vnd.microsoft.portable-executable"},
        {".msi",   "application/x-msi"},
        {".dmg",   "application/x-apple-diskimage"},
        {".deb",   "application/vnd.debian.binary-package"},
        {".rpm",   "application/x-rpm"},
        {".apk",   "application/vnd.android.package-archive"},
        {".appimage", "application/x-executable"},
        {".jar",   "application/java-archive"},

        // Disk images / ISOs
        {".iso",   "application/x-iso9660-image"},
        {".img",   "application/octet-stream"},

        // Source code / dev
        {".wasm",  "application/wasm"},
        {".sh",    "application/x-sh"},
        {".py",    "text/x-python"},
        {".c",     "text/x-c"},
        {".cpp",   "text/x-c++src"},
        {".h",     "text/x-c"},
        {".hpp",   "text/x-c++hdr"},
        {".java",  "text/x-java-source"},
        {".rs",    "text/x-rust"},
        {".go",    "text/x-go"},
        {".rb",    "text/x-ruby"},
        {".php",   "text/x-php"},
        {".sql",   "application/sql"},
        {".diff",  "text/x-diff"},
        {".patch", "text/x-diff"},

        // Misc / data
        {".ics",   "text/calendar"},
        {".vcf",   "text/vcard"},
        {".gpx",   "application/gpx+xml"},
        {".kml",   "application/vnd.google-earth.kml+xml"},
        {".sqlite","application/vnd.sqlite3"},
        {".db",    "application/octet-stream"},
    };

    auto ext = std::filesystem::path(filename).extension().string();
    for (auto& c : ext)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (auto it = mimes.find(ext); it != mimes.end()) return it->second;
    return "application/octet-stream";
}
