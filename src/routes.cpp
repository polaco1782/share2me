#include "routes.hpp"
#include "hash.hpp"
#include "logging.hpp"
#include "mime.hpp"
#include "page.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <regex>
#include <string>
#include <system_error>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

// ===========================================================================
// File-local helpers (anonymous namespace)
// ===========================================================================
namespace {

/// Maximum upload body size enforced at route entry (512 MiB).
constexpr std::size_t MAX_UPLOAD_BYTES = 512ULL * 1024 * 1024;

/// Guard against concurrent double-claim of single-download tokens.
std::mutex                      s_single_dl_mutex;
std::unordered_set<std::string> s_single_dl_claimed;

void not_found(httplib::Response& res) {
    res.status = 404;
    res.set_content("Not found", "text/plain");
}

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

bool is_valid_token(const std::string& token) {
    return token.size() == 16 &&
           token.find_first_not_of("0123456789abcdef") == std::string::npos;
}

std::string sanitize_filename(const std::string& filename) {
    if (filename.empty() || filename == "." || filename == "..") return "";
    std::string safe_name = fs::path(filename).filename().string();
    if (safe_name.empty() || safe_name == "." || safe_name == "..") return "";
    if (safe_name[0] == '.') return "";
    if (safe_name.find('\0') != std::string::npos ||
        safe_name.find('/') != std::string::npos ||
        safe_name.find('\\') != std::string::npos ||
        safe_name.find('"') != std::string::npos) return "";
    if (safe_name.length() > 255) return "";
    return safe_name;
}

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

std::string get_query_param(const std::string& query, const std::string& name) {
    std::string search = name + "=";
    auto pos = query.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    auto end = query.find('&', pos);
    return query.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
}

bool has_query_param(const std::string& query, const std::string& name) {
    if (query.find(name + "=") != std::string::npos) return true;
    if (query.find(name + "&") != std::string::npos) return true;
    if (query == name) return true;
    if (query.size() >= name.size() &&
        query.compare(query.size() - name.size(), name.size(), name) == 0) return true;
    return false;
}

} // anonymous namespace

// ===========================================================================
// Public API
// ===========================================================================

void register_http_routes(
    httplib::Server& http_app,
    const AppConfig& cfg,
    std::mutex& acme_mutex,
    std::unordered_map<std::string, std::string>& acme_challenges)
{
    auto* mutex_ptr      = &acme_mutex;
    auto* challenges_ptr = &acme_challenges;

    if (cfg.http_verbose) {
        http_app.set_logger([](const httplib::Request& req, const httplib::Response& res) {
            LOG_INFO << "[HTTP ] " << req.method << " " << req.path
                     << " -> " << res.status;
        });
    }

    http_app.Get(R"(/.well-known/acme-challenge/(.+))",
        [mutex_ptr, challenges_ptr](const httplib::Request& req, httplib::Response& res) {
            std::string token = req.matches[1];
            std::lock_guard lock(*mutex_ptr);
            if (auto it = challenges_ptr->find(token); it != challenges_ptr->end()) {
                res.status = 200;
                res.set_content(it->second, "text/plain");
            } else {
                res.status = 404;
            }
        });

    http_app.Get(R"(/.well-known/.*)",
        [](const httplib::Request&, httplib::Response& res) {
            res.status = 404;
        });

    http_app.set_default_headers({});
    http_app.set_error_handler(
        [domain = cfg.domain, https_port = cfg.https_port](
            const httplib::Request& req, httplib::Response& res) {
            if (req.path.compare(0, 12, "/.well-known/") == 0) {
                res.status = 404;
                return;
            }
            std::string host = domain;
            if (req.has_header("Host")) {
                host = req.get_header_value("Host");
                if (auto p = host.find(':'); p != std::string::npos)
                    host = host.substr(0, p);
            }
            std::string location = "https://" + host;
            if (https_port != 443) location += ":" + std::to_string(https_port);
            location += req.path;
            res.status = 301;
            res.set_header("Location", location);
        });
}

void register_routes(httplib::SSLServer& app,
                     const AppConfig& cfg,
                     FileStore& store)
{
    std::string base_url = "https://" + cfg.domain;
    if (cfg.https_port != 443)
        base_url += ":" + std::to_string(cfg.https_port);

    if (cfg.http_verbose) {
        app.set_logger([](const httplib::Request& req, const httplib::Response& res) {
            LOG_INFO << "[HTTPS] " << req.method << " " << req.path
                     << " -> " << res.status;
        });
    }

    app.set_payload_max_length(MAX_UPLOAD_BYTES);

    app.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(INDEX_HTML, "text/html; charset=utf-8");
    });

    app.Get("/healthz", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("OK", "text/plain");
    });

    app.Get("/robots.txt", [](const httplib::Request& req, httplib::Response& res) {
        std::string host = req.has_header("Host")
            ? req.get_header_value("Host") : "localhost";
        res.set_content(
            "User-agent: *\n"
            "Disallow: /\n"
            "Allow: /$\n"
            "Sitemap: https://" + host + "/sitemap.xml\n",
            "text/plain; charset=utf-8");
    });

    app.Get("/sitemap.xml", [](const httplib::Request& req, httplib::Response& res) {
        std::string host = req.has_header("Host")
            ? req.get_header_value("Host") : "localhost";
        res.set_content(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
            "  <url>\n"
            "    <loc>https://" + host + "/</loc>\n"
            "    <changefreq>monthly</changefreq>\n"
            "    <priority>1.0</priority>\n"
            "  </url>\n"
            "</urlset>\n",
            "application/xml; charset=utf-8");
    });

    // POST /upload — multipart upload from HTML form.
    app.Post("/upload", [&store](const httplib::Request& req, httplib::Response& res) {
        if (req.body.size() > MAX_UPLOAD_BYTES) {
            res.status = 413;
            res.set_content("File too large\n", "text/plain");
            return;
        }

        if (req.has_header("Origin")) {
            std::string origin = req.get_header_value("Origin");
            std::string host = req.has_header("Host")
                ? req.get_header_value("Host") : "";
            if (!origin.empty() && origin != "https://" + host
                                && origin != "http://" + host) {
                res.status = 403;
                res.set_content("Forbidden\n", "text/plain");
                return;
            }
        }

        std::string file_body;
        std::string file_name;
        std::string content_type;
        bool single_download = false;
        long long expire_secs = 0;
        bool is_encrypted = false;

        if (req.has_file("file")) {
            const auto& file = req.get_file_value("file");
            file_body    = file.content;
            file_name    = file.filename;
            content_type = file.content_type;
        }
        if (req.has_file("single_download"))
            single_download = (req.get_file_value("single_download").content == "1");
        if (req.has_file("expire_after"))
            expire_secs = parse_expire_seconds(
                req.get_file_value("expire_after").content);
        if (req.has_file("encrypted"))
            is_encrypted = (req.get_file_value("encrypted").content == "1");

        std::string safe_name = sanitize_filename(file_name);
        if (safe_name.empty()) {
            res.status = 400;
            res.set_content("Invalid filename\n", "text/plain");
            return;
        }

        auto result = store.store_file(file_body, safe_name, single_download,
                                       expire_secs, is_encrypted, content_type);
        if (!result.ok) {
            nlohmann::json j;
            j["ok"]    = false;
            j["error"] = result.error;
            res.status = 400;
            res.set_content(j.dump(), "application/json");
            return;
        }

        LOG_INFO << "POST Upload: " << safe_name
                 << " [sha256: " << result.sha256.substr(0, 12) << "]"
                 << " -> " << result.token
                 << (single_download ? " [single-dl]" : "")
                 << (expire_secs > 0
                     ? " [expires in " + std::to_string(expire_secs) + "s]"
                     : "");

        nlohmann::json resp_json;
        resp_json["ok"]           = true;
        resp_json["hash"]         = result.token;
        resp_json["content_type"] = content_type.empty()
            ? mime_for(safe_name) : content_type;
        res.set_content(resp_json.dump(), "application/json");
    });

    // GET /d/<token> — client-side decrypt page for E2EE files.
    app.Get(R"(/d/([0-9a-f]{16}))",
        [base_url](const httplib::Request& req, httplib::Response& res) {
            std::string token = req.matches[1];
            if (!is_valid_token(token)) return not_found(res);
            res.set_content(DECRYPT_PAGE_HTML, "text/html; charset=utf-8");
        });

    // GET /v/<token> — viewer for images and text.
    app.Get(R"(/v/([0-9a-f]{16}))",
        [base_url, &store](const httplib::Request& req, httplib::Response& res) {
            std::string token = req.matches[1];
            if (!is_valid_token(token)) return not_found(res);

            auto opt = store.load_meta(token);
            if (!opt) return not_found(res);
            auto& meta = *opt;

            if (store.check_and_remove_expired(token, meta))
                return not_found(res);

            bool        encrypted = meta.value("encrypted", false);
            bool        single_dl = meta.value("single_download", false);
            std::string filename  = meta.value("filename", "");

            if (encrypted) {
                if (is_likely_text_file(filename)) {
                    res.set_content(
                        encrypted_text_viewer_html(token, single_dl, base_url),
                        "text/html; charset=utf-8");
                } else if (is_likely_image_file(filename)) {
                    res.set_content(
                        encrypted_image_viewer_html(token, single_dl, base_url),
                        "text/html; charset=utf-8");
                } else {
                    res.status = 302;
                    res.set_header("Location", "/d/" + token);
                }
            } else {
                std::string ct = meta.value("content_type", "");
                bool is_image = ct.compare(0, 6, "image/") == 0;
                bool is_text  = ct.compare(0, 5, "text/") == 0 ||
                                ct == "application/json" ||
                                ct == "application/xml" ||
                                ct == "application/javascript";

                if (!is_image && !is_text) return not_found(res);

                if (is_image) {
                    res.set_content(
                        image_viewer_html(token,
                            filename.empty() ? "image" : filename,
                            single_dl, base_url),
                        "text/html; charset=utf-8");
                } else {
                    res.set_content(
                        text_viewer_html(token,
                            filename.empty() ? "text" : filename,
                            single_dl, base_url),
                        "text/html; charset=utf-8");
                }
            }
        });

    // PUT /<filename> — curl/CLI upload.
    app.Put(R"(/([^/]+))",
        [&store](const httplib::Request& req, httplib::Response& res) {
            std::string filename = req.matches[1];

            if (req.body.empty()) {
                res.status = 400;
                res.set_content("Empty body\n", "text/plain");
                return;
            }

            if (req.body.size() > MAX_UPLOAD_BYTES) {
                res.status = 413;
                res.set_content("File too large\n", "text/plain");
                return;
            }

            std::string safe_name = sanitize_filename(filename);
            if (safe_name.empty()) {
                res.status = 400;
                res.set_content("Invalid filename\n", "text/plain");
                return;
            }

            bool single_download = has_query_param(req.target, "single") ||
                (has_query_param(req.target, "single_download") &&
                 get_query_param(req.target, "single_download") == "1");

            long long expire_secs = 0;
            std::string ev = get_query_param(req.target, "expire");
            if (!ev.empty()) expire_secs = parse_expire_seconds(ev);

            std::string content_type = req.has_header("Content-Type")
                ? req.get_header_value("Content-Type") : "";

            auto result = store.store_file(req.body, safe_name,
                single_download, expire_secs, false, content_type);
            if (!result.ok) {
                res.status = 500;
                res.set_content(result.error + "\n", "text/plain");
                return;
            }

            LOG_INFO << "PUT Upload: " << safe_name
                     << " [sha256: " << result.sha256.substr(0, 12) << "]"
                     << " -> " << result.token
                     << (single_download ? " [single-dl]" : "")
                     << (expire_secs > 0
                         ? " [expires in " + std::to_string(expire_secs) + "s]"
                         : "");

            std::string host = req.has_header("Host")
                ? req.get_header_value("Host") : "localhost";

            res.status = 201;
            res.set_content("https://" + host + "/" + result.token + "\n",
                            "text/plain; charset=utf-8");
        });

    // GET /<token> — file download.
    app.Get(R"(/([0-9a-f]{16}))",
        [&store](const httplib::Request& req, httplib::Response& res) {
            std::string token = req.matches[1];
            if (!is_valid_token(token)) return not_found(res);

            auto opt = store.load_meta(token);
            if (!opt) return not_found(res);
            auto& meta = *opt;

            std::string stored_sha256 = meta.value("hash", "");
            std::string stored_as     = meta.value("stored_as", "");
            std::string filename      = meta.value("filename", "download");
            bool        single_dl     = meta.value("single_download", false);

            if (store.check_and_remove_expired(token, meta))
                return not_found(res);

            const auto& data_dir = store.data_dir();
            fs::path file_path = data_dir / stored_as;

            std::error_code ec;
            if (!fs::exists(file_path, ec) || ec) return not_found(res);

            if (fs::is_symlink(file_path, ec)) {
                LOG_ERROR << "Security: symlink detected for token " << token;
                return not_found(res);
            }

            if (!store.is_path_safe(file_path)) {
                LOG_ERROR << "Security: path traversal attempt for token "
                          << token;
                return not_found(res);
            }

            if (!stored_sha256.empty()) {
                std::string actual = sha256_file(file_path);
                if (actual != stored_sha256) {
                    LOG_ERROR << "Integrity FAILED for " << token
                              << ": expected " << stored_sha256
                              << ", got " << actual;
                    res.status = 500;
                    res.set_content("Internal server error", "text/plain");
                    return;
                }
            }

            LOG_INFO << "Download: " << filename
                     << " [sha256: " << stored_sha256.substr(0, 12) << "]"
                     << " <- " << token;

            if (single_dl) {
                {
                    std::lock_guard lock(s_single_dl_mutex);
                    if (!s_single_dl_claimed.insert(token).second)
                        return not_found(res);
                }

                fs::remove(data_dir / (token + ".json"), ec);

                const auto file_size = fs::file_size(file_path);
                std::string body(file_size, '\0');
                {
                    std::ifstream ifs(file_path, std::ios::binary);
                    ifs.read(body.data(),
                             static_cast<std::streamsize>(file_size));
                }
                fs::remove(file_path, ec);

                {
                    std::lock_guard lock(s_single_dl_mutex);
                    s_single_dl_claimed.erase(token);
                }

                LOG_INFO << "Single-download consumed: " << token;

                res.set_header("Content-Disposition",
                    "attachment; filename=\"" + filename + "\"");
                res.set_content(std::move(body), mime_for(filename));
            } else {
                const auto file_size = fs::file_size(file_path);
                std::string body(file_size, '\0');
                {
                    std::ifstream ifs(file_path, std::ios::binary);
                    ifs.read(body.data(),
                             static_cast<std::streamsize>(file_size));
                }
                res.set_header("Content-Disposition",
                    "attachment; filename=\"" + filename + "\"");
                res.set_content(std::move(body), mime_for(filename));
            }
        });
}
