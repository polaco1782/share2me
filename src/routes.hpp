#pragma once

#include "config.hpp"
#include "hash.hpp"
#include "mime.hpp"
#include "page.hpp"
#include "store.hpp"

#include <crow.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>

/// Maximum upload body size enforced at route entry (512 MiB).
static constexpr std::size_t MAX_UPLOAD_BYTES = 512ULL * 1024 * 1024;

/// Guard against concurrent double-claim of single-download tokens.
static std::mutex                      s_single_dl_mutex;
static std::unordered_set<std::string> s_single_dl_claimed;

// Convert an expiry string like "5m", "1h", "3d", "1y" into seconds.
// Returns 0 when the input is empty or unrecognised.
long long parse_expire_seconds(const std::string& s) {
    if (s.size() < 2) return 0;
    size_t i = 0;
    long long num = 0;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])))
        num = num * 10 + (s[i++] - '0');
    if (i == 0 || i >= s.size()) return 0;
    std::string unit = s.substr(i);
    if (unit == "m") return num * 60LL;
    if (unit == "h") return num * 3600LL;
    if (unit == "d") return num * 86400LL;
    if (unit == "y") return num * 31536000LL;
    return 0;
}

/// Validate that a token is a 16-character lowercase hex string.
bool is_valid_token(const std::string& token) {
    return token.size() == 16 &&
           token.find_first_not_of("0123456789abcdef") == std::string::npos;
}

/// Sanitize filename to prevent path traversal and other attacks.
std::string sanitize_filename(const std::string& filename) {
    if (filename.empty() || filename == "." || filename == "..") {
        return "";
    }

    std::string safe_name = fs::path(filename).filename().string();

    if (safe_name.empty() || safe_name == "." || safe_name == "..") {
        return "";
    }

    if (safe_name[0] == '.') {
        return "";
    }

    if (safe_name.find('\0') != std::string::npos ||
        safe_name.find('/') != std::string::npos ||
        safe_name.find('\\') != std::string::npos ||
        safe_name.find('"') != std::string::npos) {
        return "";
    }

    if (safe_name.length() > 255) {
        return "";
    }

    return safe_name;
}

/// Load file metadata JSON from disk. Returns std::nullopt on failure.
std::optional<nlohmann::json> load_meta(const std::string& token) {
    fs::path meta_path = DATA_DIR / (token + ".json");
    std::ifstream ifs(meta_path);
    if (!ifs) return std::nullopt;
    nlohmann::json meta;
    try {
        ifs >> meta;
    } catch (...) {
        return std::nullopt;
    }
    return meta;
}

/// Check whether a file has expired.  If it has, clean up the metadata
/// and stored file from disk, log the event, and return true.
bool check_and_remove_expired(const std::string& token,
                                      const nlohmann::json& meta) {
    if (!meta.contains("expires_at")) return false;
    long long expires_at = meta["expires_at"].get<long long>();
    long long now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (now_sec < expires_at) return false;

    fs::path meta_path = DATA_DIR / (token + ".json");
    std::string stored_as = meta.value("stored_as", "");
    std::error_code ec;
    fs::remove(meta_path, ec);
    if (!stored_as.empty()) fs::remove(DATA_DIR / stored_as, ec);
    CROW_LOG_INFO << "Expired on access: " << token;
    return true;
}

/// Check if a filename likely represents a text file (by extension).
bool is_likely_text_file(const std::string& filename) {
    std::string ext = fs::path(filename).extension().string();
    for (auto& c : ext)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    
    static const std::unordered_set<std::string> text_extensions = {
        ".txt", ".md", ".json", ".xml", ".html", ".htm", ".css",
        ".js", ".mjs", ".ts", ".tsx", ".yaml", ".yml", ".toml",
        ".ini", ".cfg", ".conf", ".log", ".csv", ".tsv",
        ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",
        ".java", ".py", ".rb", ".go", ".rs", ".php", ".sh",
        ".bash", ".zsh", ".fish", ".pl", ".lua", ".r",
        ".sql", ".diff", ".patch", ".tex", ".latex", ".svg",
    };
    
    return text_extensions.count(ext) > 0;
}

/// Check if a filename likely represents an image file (by extension).
bool is_likely_image_file(const std::string& filename) {
    std::string ext = fs::path(filename).extension().string();
    for (auto& c : ext)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    static const std::unordered_set<std::string> image_extensions = {
        ".jpg", ".jpeg", ".png", ".gif", ".webp",
        ".svg", ".ico", ".bmp", ".tiff", ".tif", ".avif",
    };

    return image_extensions.count(ext) > 0;
}

// Register all routes on the plain-HTTP app:
//   - ACME http-01 challenge responses
//   - HTTP → HTTPS permanent redirect for everything else
void register_http_routes(
    crow::SimpleApp& http_app,
    std::string domain,
    uint16_t https_port,
    std::mutex& acme_mutex,
    std::unordered_map<std::string, std::string>& acme_challenges)
{
    auto* mutex_ptr      = &acme_mutex;
    auto* challenges_ptr = &acme_challenges;

    CROW_CATCHALL_ROUTE(http_app)
    ([domain = std::move(domain), https_port, mutex_ptr, challenges_ptr]
     (const crow::request& req) {
        static const std::string CHALLENGE_PREFIX = "/.well-known/acme-challenge/";
        static const std::string WELL_KNOWN_PREFIX = "/.well-known/";

        if (req.url.compare(0, WELL_KNOWN_PREFIX.size(), WELL_KNOWN_PREFIX) == 0) {
            if (req.url.compare(0, CHALLENGE_PREFIX.size(), CHALLENGE_PREFIX) == 0) {
                std::string token = req.url.substr(CHALLENGE_PREFIX.size());
                std::lock_guard lock(*mutex_ptr);
                if (auto it = challenges_ptr->find(token); it != challenges_ptr->end())
                    return crow::response(200, it->second);
            }
            return crow::response(404);
        }

        std::string host = req.get_header_value("Host");
        if (auto p = host.find(':'); p != std::string::npos)
            host = host.substr(0, p);
        if (host.empty()) host = domain;
        std::string location = "https://" + host;
        if (https_port != 443) location += ":" + std::to_string(https_port);
        location += req.url;
        crow::response r(301);
        r.set_header("Location", location);
        return r;
    });
}

void register_routes(crow::SimpleApp& app, const AppConfig& cfg) {
    // Build the base URL once; used for Open Graph absolute URLs.
    std::string base_url = "https://" + cfg.domain;
    if (cfg.https_port != 443)
        base_url += ":" + std::to_string(cfg.https_port);

    CROW_ROUTE(app, "/")
    ([]() {
        crow::response res(200);
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.body = INDEX_HTML;
        return res;
    });

    CROW_ROUTE(app, "/healthz")
    ([]() {
        return crow::response(200, "OK");
    });

    // robots.txt — inform search engines not to crawl temporary links.
    CROW_ROUTE(app, "/robots.txt")
    ([](const crow::request& req) {
        std::string host = req.get_header_value("Host");
        if (host.empty()) host = "localhost";
        crow::response res(200);
        res.set_header("Content-Type", "text/plain; charset=utf-8");
        res.body = "User-agent: *\n"
                   "Disallow: /\n"
                   "Allow: /$\n"
                   "Sitemap: https://" + host + "/sitemap.xml\n";
        return res;
    });

    // sitemap.xml — expose only the root page to search engines.
    CROW_ROUTE(app, "/sitemap.xml")
    ([](const crow::request& req) {
        std::string host = req.get_header_value("Host");
        if (host.empty()) host = "localhost";
        crow::response res(200);
        res.set_header("Content-Type", "application/xml; charset=utf-8");
        res.body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                   "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
                   "  <url>\n"
                   "    <loc>https://" + host + "/</loc>\n"
                   "    <changefreq>monthly</changefreq>\n"
                   "    <priority>1.0</priority>\n"
                   "  </url>\n"
                   "</urlset>\n";
        return res;
    });

    // POST /upload - multipart upload from HTML form.
    CROW_ROUTE(app, "/upload").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req) {
        if (req.body.size() > MAX_UPLOAD_BYTES)
            return crow::response(413, "File too large\n");

        // CSRF: reject cross-origin browser POSTs by validating the Origin header.
        {
            std::string origin = req.get_header_value("Origin");
            if (!origin.empty()) {
                std::string host = req.get_header_value("Host");
                if (origin != "https://" + host && origin != "http://" + host)
                    return crow::response(403, "Forbidden\n");
            }
        }

        crow::multipart::message msg(req);

        std::string file_body;
        std::string file_name;
        std::string content_type;
        bool single_download = false;
        long long expire_secs = 0;
        bool is_encrypted = false;

        for (auto& [name, part] : msg.part_map) {
            if (name == "file") {
                file_body = part.body;
                auto cdh = part.headers.find("Content-Disposition");
                if (cdh != part.headers.end()) {
                    if (auto fn = cdh->second.params.find("filename");
                        fn != cdh->second.params.end())
                        file_name = fn->second;
                }
                auto cth = part.headers.find("Content-Type");
                if (cth != part.headers.end())
                    content_type = cth->second.value;
            } else if (name == "single_download") {
                single_download = (part.body == "1");
            } else if (name == "expire_after") {
                expire_secs = parse_expire_seconds(part.body);
            } else if (name == "encrypted") {
                is_encrypted = (part.body == "1");
            }
        }

        std::string safe_name = sanitize_filename(file_name);
        if (safe_name.empty())
            return crow::response(400, "Invalid filename\n");

        auto result = store_file(file_body, safe_name, single_download, expire_secs, is_encrypted, content_type);
        if (!result.ok) {
            nlohmann::json j;
            j["ok"]    = false;
            j["error"] = result.error;
            return crow::response(400, j.dump());
        }

        CROW_LOG_INFO << "POST Upload: " << safe_name
                      << " [sha256: " << result.sha256.substr(0, 12) << "]"
                      << " -> " << result.token
                      << (single_download ? " [single-dl]" : "")
                      << (expire_secs > 0 ? " [expires in " + std::to_string(expire_secs) + "s]" : "");

        nlohmann::json resp;
        resp["ok"]           = true;
        resp["hash"]         = result.token; // keep key name for JS compatibility
        resp["content_type"] = content_type.empty() ? mime_for(safe_name) : content_type;
        crow::response r(200);
        r.set_header("Content-Type", "application/json");
        r.body = resp.dump();
        return r;
    });

    // PUT /<filename> - curl/CLI upload.
    //   curl -kT <file> https://<host>:<port>/<filename>
    //   curl -kT <file> "https://<host>:<port>/<filename>?single"
    CROW_ROUTE(app, "/<string>").methods(crow::HTTPMethod::PUT)
    ([](const crow::request& req, const std::string& filename) {
        if (req.body.empty())
            return crow::response(400, "Empty body\n");

        if (req.body.size() > MAX_UPLOAD_BYTES)
            return crow::response(413, "File too large\n");

        std::string safe_name = sanitize_filename(filename);
        if (safe_name.empty())
            return crow::response(400, "Invalid filename\n");

        bool single_download = req.url_params.get("single") != nullptr;
        if (!single_download) {
            auto* sd = req.url_params.get("single_download");
            single_download = (sd != nullptr && std::string(sd) == "1");
        }

        long long expire_secs = 0;
        if (auto* ev = req.url_params.get("expire"))
            expire_secs = parse_expire_seconds(std::string(ev));

        std::string content_type = req.get_header_value("Content-Type");

        auto result = store_file(req.body, safe_name, single_download, expire_secs, false, content_type);
        if (!result.ok)
            return crow::response(500, result.error + "\n");

        CROW_LOG_INFO << "PUT Upload: " << safe_name
                      << " [sha256: " << result.sha256.substr(0, 12) << "]"
                      << " -> " << result.token
                      << (single_download ? " [single-dl]" : "")
                      << (expire_secs > 0 ? " [expires in " + std::to_string(expire_secs) + "s]" : "");

        std::string host = req.get_header_value("Host");
        if (host.empty()) host = "localhost";

        crow::response r(201);
        r.set_header("Content-Type", "text/plain; charset=utf-8");
        r.body = "https://" + host + "/" + result.token + "\n";
        return r;
    });

    // GET /d/<token> - serve the client-side decrypt page for E2EE files.
    // The decryption key lives only in the URL fragment and is never seen by the server.
    CROW_ROUTE(app, "/d/<string>")
    ([base_url](const std::string& token) {
        if (!is_valid_token(token))
            return crow::response(404, "Not found");
        crow::response res(200);
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.body = DECRYPT_PAGE_HTML;
        return res;
    });

    // GET /v/<token> - viewer for images and text; E2EE files use URL fragment for key+name.
    CROW_ROUTE(app, "/v/<string>")
    ([base_url](const std::string& token) {
        if (!is_valid_token(token))
            return crow::response(404, "Not found");

        auto opt = load_meta(token);
        if (!opt) return crow::response(404, "Not found");
        auto& meta = *opt;

        // Expiry check first — clean up before doing anything else.
        if (check_and_remove_expired(token, meta))
            return crow::response(404, "Not found");

        bool        encrypted  = meta.value("encrypted", false);
        bool        single_dl  = meta.value("single_download", false);
        std::string filename   = meta.value("filename", "");

        crow::response res(200);
        res.set_header("Content-Type", "text/html; charset=utf-8");

        if (encrypted) {
            // For E2EE files content_type is always application/octet-stream;
            // infer viewability from the original filename stored in metadata.
            if (is_likely_text_file(filename)) {
                res.body = encrypted_text_viewer_html(token, single_dl, base_url);
            } else if (is_likely_image_file(filename)) {
                res.body = encrypted_image_viewer_html(token, single_dl, base_url);
            } else {
                // Non-viewable E2EE type — redirect to the decrypt/download page.
                crow::response r(302);
                r.set_header("Location", "/d/" + token);
                return r;
            }
        } else {
            std::string content_type = meta.value("content_type", "");
            bool is_image = content_type.compare(0, 6, "image/") == 0;
            bool is_text  = content_type.compare(0, 5, "text/") == 0 ||
                            content_type == "application/json"         ||
                            content_type == "application/xml"          ||
                            content_type == "application/javascript";

            if (!is_image && !is_text)
                return crow::response(404, "Not found");

            if (is_image) {
                res.body = image_viewer_html(token,
                               filename.empty() ? "image" : filename, single_dl, base_url);
            } else {
                res.body = text_viewer_html(token,
                               filename.empty() ? "text"  : filename, single_dl, base_url);
            }
        }
        return res;
    });

    // GET /<token> - file download.
    CROW_ROUTE(app, "/<string>")
    ([](const std::string& token) {
        if (!is_valid_token(token))
            return crow::response(404, "Not found");

        auto opt = load_meta(token);
        if (!opt) return crow::response(404, "Not found");
        auto& meta = *opt;

        std::string stored_sha256 = meta.value("hash", "");
        std::string stored_as     = meta.value("stored_as", "");
        std::string filename      = meta.value("filename", "download");
        bool        single_dl     = meta.value("single_download", false);

        if (check_and_remove_expired(token, meta))
            return crow::response(404, "Not found");

        fs::path file_path = DATA_DIR / stored_as;

        std::error_code ec;
        if (!fs::exists(file_path, ec) || ec)
            return crow::response(404, "Not found");

        if (fs::is_symlink(file_path, ec)) {
            CROW_LOG_ERROR << "Security: symlink detected for token " << token;
            return crow::response(404, "Not found");
        }

        // Strictly verify the resolved path is within DATA_DIR (guards prefix-match attacks).
        if (!is_path_safe(file_path, DATA_DIR)) {
            CROW_LOG_ERROR << "Security: path traversal attempt for token " << token;
            return crow::response(404, "Not found");
        }

        if (!stored_sha256.empty()) {
            std::string actual = sha256_file(file_path);
            if (actual != stored_sha256) {
                CROW_LOG_ERROR << "Integrity FAILED for " << token
                               << ": expected " << stored_sha256
                               << ", got " << actual;
                return crow::response(500, "Internal server error");
            }
        }

        CROW_LOG_INFO << "Download: " << filename
                      << " [sha256: " << stored_sha256.substr(0, 12) << "]"
                      << " <- " << token;
        crow::response res(200);

        if (single_dl) {
            // Atomically claim this token to prevent concurrent double-downloads.
            {
                std::lock_guard lock(s_single_dl_mutex);
                if (!s_single_dl_claimed.insert(token).second)
                    return crow::response(404, "Not found");
            }

            std::error_code ec;
            fs::remove(DATA_DIR / (token + ".json"), ec); // expire the link immediately

            const auto file_size = fs::file_size(file_path);
            std::string body(file_size, '\0');
            {
                std::ifstream ifs(file_path, std::ios::binary);
                ifs.read(body.data(), static_cast<std::streamsize>(file_size));
            }
            fs::remove(file_path, ec);

            // Release the claim slot — disk is now clean.
            {
                std::lock_guard lock(s_single_dl_mutex);
                s_single_dl_claimed.erase(token);
            }

            CROW_LOG_INFO << "Single-download consumed: " << token;

            res.set_header("Content-Type", mime_for(filename));
            res.set_header("Content-Disposition",
                           "attachment; filename=\"" + filename + "\"");
            res.body = std::move(body);
        } else {
            res.set_static_file_info_unsafe(file_path.string());
            res.set_header("Content-Type", mime_for(filename));
            res.set_header("Content-Disposition",
                           "attachment; filename=\"" + filename + "\"");
        }

        return res;
    });

    CROW_CATCHALL_ROUTE(app)
    ([](const crow::request& req) {
        return crow::response(404, "Not found");
    });
}