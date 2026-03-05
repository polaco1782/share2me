#pragma once
// Crow route registration for Share2Me.

#include "hash.hpp"
#include "mime.hpp"
#include "page.hpp"
#include "store.hpp"

#include <crow.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

// Convert an expiry string like "5m", "1h", "3d", "1y" into seconds.
// Returns 0 when the input is empty or unrecognised.
inline long long parse_expire_seconds(const std::string& s) {
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

inline void register_routes(crow::SimpleApp& app) {

    CROW_ROUTE(app, "/")
    ([]() {
        crow::response res(200);
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.body = INDEX_HTML;
        return res;
    });

    CROW_ROUTE(app, "/upload").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req) {
        crow::multipart::message msg(req);

        std::string file_body;
        std::string file_name;
        bool single_download = false;
        long long expire_secs = 0;

        for (auto& [name, part] : msg.part_map) {
            if (name == "file") {
                file_body = part.body;
                auto cdh = part.headers.find("Content-Disposition");
                if (cdh != part.headers.end()) {
                    if (auto fn = cdh->second.params.find("filename");
                        fn != cdh->second.params.end())
                        file_name = fn->second;
                }
            } else if (name == "single_download") {
                single_download = (part.body == "1");
            } else if (name == "expire_after") {
                expire_secs = parse_expire_seconds(part.body);
            }
        }

        auto result = store_file(file_body, file_name, single_download, expire_secs);
        if (!result.ok) {
            nlohmann::json j;
            j["ok"]    = false;
            j["error"] = result.error;
            return crow::response(400, j.dump());
        }

        CROW_LOG_INFO << "Uploaded: " << file_name
                      << " [sha256: " << result.sha256.substr(0, 12) << "…]"
                      << " -> " << result.token
                      << (single_download ? " [single-dl]" : "")
                      << (expire_secs > 0 ? " [expires in " + std::to_string(expire_secs) + "s]" : "");

        nlohmann::json resp;
        resp["ok"]   = true;
        resp["hash"] = result.token; // keep key name for JS compatibility
        crow::response r(200);
        r.set_header("Content-Type", "application/json");
        r.body = resp.dump();
        return r;
    });

    // PUT /<filename> – curl/CLI upload.
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

        auto result = store_file(req.body, safe_name, single_download, expire_secs);
        if (!result.ok)
            return crow::response(500, result.error + "\n");

        CROW_LOG_INFO << "PUT upload: " << safe_name
                      << " [sha256: " << result.sha256.substr(0, 12) << "…]"
                      << " -> " << result.token
                      << (single_download ? " [single-dl]" : "");

        std::string host = req.get_header_value("Host");
        if (host.empty()) host = "localhost";

        crow::response r(201);
        r.set_header("Content-Type", "text/plain; charset=utf-8");
        r.body = "https://" + host + "/" + result.token + "\n";
        return r;
    });

    CROW_ROUTE(app, "/<string>")
    ([](const std::string& token) {
        // Validate: only hex characters, exactly 10 chars
        if (token.size() != 10 ||
            token.find_first_not_of("0123456789abcdef") != std::string::npos)
            return crow::response(404, "Not found");

        fs::path meta_path = DATA_DIR / (token + ".json");
        if (!fs::exists(meta_path))
            return crow::response(404, "Not found");

        nlohmann::json meta;
        {
            std::ifstream ifs(meta_path);
            if (!ifs) return crow::response(404, "Not found");
            ifs >> meta;
        }

        std::string stored_sha256 = meta.value("hash", "");
        std::string stored_as     = meta.value("stored_as", "");
        std::string filename      = meta.value("filename", "download");
        bool        single_dl     = meta.value("single_download", false);

        // Check expiry
        if (meta.contains("expires_at")) {
            long long expires_at = meta["expires_at"].get<long long>();
            long long now_sec = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if (now_sec >= expires_at) {
                std::error_code ec;
                fs::remove(meta_path, ec);
                if (!stored_as.empty()) fs::remove(DATA_DIR / stored_as, ec);
                CROW_LOG_INFO << "Expired on access: " << token;
                return crow::response(404, "Not found");
            }
        }

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

        crow::response res(200);

        if (single_dl) {
            std::error_code ec;
            fs::remove(meta_path, ec); // expire the link immediately

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

    CROW_CATCHALL_ROUTE(app)
    ([](const crow::request& req) {
        // /.well-known/* probes (security.txt, acme-challenge, etc.) get a
        // silent 404 — there is nothing here and we don't want to confirm
        // the presence of an access-controlled resource with a 403.
        static const std::string WELL_KNOWN_PREFIX = "/.well-known/";
        if (req.url.compare(0, WELL_KNOWN_PREFIX.size(), WELL_KNOWN_PREFIX) == 0)
            return crow::response(404);
        return crow::response(403, "Forbidden");
    });
}
