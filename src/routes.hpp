#pragma once

#include "hash.hpp"
#include "mime.hpp"
#include "page.hpp"
#include "store.hpp"

#include <crow.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>

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

/// Validate that a token is a 10-character lowercase hex string.
bool is_valid_token(const std::string& token) {
    return token.size() == 10 &&
           token.find_first_not_of("0123456789abcdef") == std::string::npos;
}

/// Load file metadata JSON from disk. Returns std::nullopt on failure.
std::optional<nlohmann::json> load_meta(const std::string& token) {
    fs::path meta_path = DATA_DIR / (token + ".json");
    if (!fs::exists(meta_path)) return std::nullopt;
    std::ifstream ifs(meta_path);
    if (!ifs) return std::nullopt;
    nlohmann::json meta;
    ifs >> meta;
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

void register_routes(crow::SimpleApp& app) {

    // GET / - serve the main HTML page with the upload form and client-side JS.
    CROW_ROUTE(app, "/")
    ([]() {
        crow::response res(200);
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.body = INDEX_HTML;
        return res;
    });

    // Health check endpoint for load balancers and uptime monitoring.
    CROW_ROUTE(app, "/healthz")
    ([]() {
        return crow::response(200, "OK");
    });

    // robots.txt — inform search engines not to crawl temporary links.
    CROW_ROUTE(app, "/robots.txt")
    ([]() {
        crow::response res(200);
        res.set_header("Content-Type", "text/plain; charset=utf-8");
        res.body = "User-agent: *\n"
                   "Disallow: /\n"
                   "Allow: /$\n";
        return res;
    });

    // POST /upload - multipart upload from HTML form.
    CROW_ROUTE(app, "/upload").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req) {
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

        std::string safe_name = fs::path(file_name).filename().string();
        if (safe_name.empty() || safe_name == "." || safe_name == "..")
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

        std::string safe_name = fs::path(filename).filename().string();
        if (safe_name.empty() || safe_name == "." || safe_name == "..")
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
    ([](const std::string& token) {
        if (!is_valid_token(token))
            return crow::response(404, "Not found");
        crow::response res(200);
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.body = DECRYPT_PAGE_HTML;
        return res;
    });

    // GET /v/<token> - image viewer (displays the image in an HTML page).
    CROW_ROUTE(app, "/v/<string>")
    ([](const std::string& token) {
        if (!is_valid_token(token))
            return crow::response(404, "Not found");

        auto opt = load_meta(token);
        if (!opt) return crow::response(404, "Not found");
        auto& meta = *opt;

        // Only allow viewing for non-encrypted image types
        if (meta.value("encrypted", false) ||
            meta.value("content_type", "").compare(0, 6, "image/") != 0)
            return crow::response(404, "Not found");

        if (check_and_remove_expired(token, meta))
            return crow::response(404, "Not found");

        crow::response res(200);
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.body = image_viewer_html(token,
                                     meta.value("filename", "image"),
                                     meta.value("single_download", false));
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
        if (!fs::exists(file_path))
            return crow::response(404, "File missing");

        // -- Integrity check: stream through file; never loads it fully -----
        if (!stored_sha256.empty()) {
            std::string actual = sha256_file(file_path);
            if (actual != stored_sha256) {
                CROW_LOG_ERROR << "Integrity FAILED for " << token
                               << ": expected " << stored_sha256
                               << ", got " << actual;
                return crow::response(500, "File integrity check failed");
            }
        }

        CROW_LOG_INFO << "Download: " << filename
                      << " [sha256: " << stored_sha256.substr(0, 12) << "]"
                      << " <- " << token;
        crow::response res(200);

        if (single_dl) {
            std::error_code ec;
            fs::remove(DATA_DIR / (token + ".json"), ec); // expire the link immediately

            const auto file_size = fs::file_size(file_path);
            std::string body(file_size, '\0');
            {
                std::ifstream ifs(file_path, std::ios::binary);
                ifs.read(body.data(), static_cast<std::streamsize>(file_size));
            }
            fs::remove(file_path, ec);
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

    // Catch-all route to return 404 for any other paths.
    CROW_CATCHALL_ROUTE(app)
    ([](const crow::request& req) {
        return crow::response(404);
    });
}
