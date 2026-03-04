// Share2Me – lightweight file sharing server
// C++20 · Crow · nlohmann/json

#include <crow.h>
#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using json   = nlohmann::json;

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
static const fs::path DATA_DIR = "data";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a random 10-character hex token used as the URL identifier.
static std::string generate_token() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    std::uint64_t value = dist(rng);

    std::ostringstream oss;
    oss << std::hex << (value & 0xFF'FFFF'FFFF); // 10 hex chars
    std::string h = oss.str();
    // Pad to 10 chars if leading zeros were dropped
    while (h.size() < 10) h.insert(h.begin(), '0');
    return h;
}

/// Guess a Content-Type from the file extension (covers the most common
/// types; falls back to application/octet-stream).
static std::string mime_for(const std::string& filename) {
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

    auto ext = fs::path(filename).extension().string();
    for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (auto it = mimes.find(ext); it != mimes.end()) return it->second;
    return "application/octet-stream";
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4, streaming – no external dependency)
// ---------------------------------------------------------------------------
struct SHA256 {
    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };

    uint32_t state_[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint8_t  chunk_[64] = {};
    uint32_t clen_      = 0;
    uint64_t total_     = 0; // bytes processed

    static constexpr uint32_t rotr(uint32_t x, uint32_t n) noexcept {
        return (x >> n) | (x << (32u - n));
    }

    void compress(const uint8_t* blk) noexcept {
        uint32_t w[64];
        for (uint32_t i = 0; i < 16; ++i)
            w[i] = (uint32_t(blk[i*4  ]) << 24) | (uint32_t(blk[i*4+1]) << 16) |
                   (uint32_t(blk[i*4+2]) <<  8) |  uint32_t(blk[i*4+3]);
        for (uint32_t i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15],  7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>  3);
            uint32_t s1 = rotr(w[i- 2], 17) ^ rotr(w[i- 2], 19) ^ (w[i- 2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=state_[0], b=state_[1], c=state_[2], d=state_[3],
                 e=state_[4], f=state_[5], g=state_[6], h=state_[7];
        for (uint32_t i = 0; i < 64; ++i) {
            uint32_t S1  = rotr(e,  6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch  = (e & f) ^ (~e & g);
            uint32_t t1  = h + S1 + ch + K[i] + w[i];
            uint32_t S0  = rotr(a,  2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2  = S0 + maj;
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
        state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    }

    void update(const uint8_t* data, std::size_t len) noexcept {
        total_ += len;
        while (len > 0) {
            std::size_t take = std::min<std::size_t>(len, 64u - clen_);
            std::memcpy(chunk_ + clen_, data, take);
            clen_ += static_cast<uint32_t>(take);
            data  += take;
            len   -= take;
            if (clen_ == 64) { compress(chunk_); clen_ = 0; }
        }
    }

    /// Finalise and return the 64-character lowercase hex digest.
    /// Non-destructive: works on a copy, the object can still be reused.
    std::string hex_digest() const {
        SHA256 ctx = *this;                     // work on a copy
        ctx.chunk_[ctx.clen_++] = 0x80u;        // append the mandatory 1-bit
        if (ctx.clen_ > 56) {                   // need an extra padding block
            while (ctx.clen_ < 64) ctx.chunk_[ctx.clen_++] = 0u;
            ctx.compress(ctx.chunk_);
            ctx.clen_ = 0;
        }
        while (ctx.clen_ < 56) ctx.chunk_[ctx.clen_++] = 0u;  // zero padding
        const uint64_t bits = ctx.total_ * 8u;  // original length in bits
        for (int i = 7; i >= 0; --i)
            ctx.chunk_[56 + (7 - i)] = static_cast<uint8_t>(bits >> (i * 8));
        ctx.compress(ctx.chunk_);

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto v : ctx.state_) oss << std::setw(8) << v;
        return oss.str();
    }
};

/// Hash a file by streaming it in 64 KiB chunks – no full-file memory load.
static std::string sha256_file(const fs::path& path) {
    SHA256 ctx;
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    constexpr std::size_t BUF_SIZE = 65536; // 64 KiB
    std::vector<uint8_t> buf(BUF_SIZE);
    while (ifs) {
        ifs.read(reinterpret_cast<char*>(buf.data()), BUF_SIZE);
        std::streamsize n = ifs.gcount();
        if (n > 0) ctx.update(buf.data(), static_cast<std::size_t>(n));
    }
    return ctx.hex_digest();
}

// ---------------------------------------------------------------------------
// HTML page (embedded so the binary is fully standalone)
// ---------------------------------------------------------------------------
static constexpr const char* INDEX_HTML = R"html(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Share2Me</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --accent: #38bdf8; --accent-hover: #7dd3fc;
    --danger: #f87171; --radius: 12px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: var(--bg); color: var(--text);
    display: flex; justify-content: center; align-items: center;
    min-height: 100vh; padding: 1rem;
  }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 2.5rem;
    width: 100%; max-width: 460px;
    box-shadow: 0 8px 30px rgba(0,0,0,.35);
  }
  h1 { font-size: 1.6rem; margin-bottom: .25rem; }
  .sub { color: #94a3b8; font-size: .9rem; margin-bottom: 1.8rem; }
  label.file-label {
    display: flex; align-items: center; justify-content: center;
    gap: .5rem; padding: 1.2rem;
    border: 2px dashed var(--border); border-radius: var(--radius);
    cursor: pointer; transition: border-color .2s;
    font-size: .95rem; color: #94a3b8;
  }
  label.file-label:hover { border-color: var(--accent); color: var(--accent); }
  label.file-label.has-file { border-color: var(--accent); color: var(--accent); border-style: solid; }
  input[type=file] { display: none; }
  .option {
    display: flex; align-items: center; gap: .6rem;
    margin: 1.2rem 0 1.6rem; font-size: .92rem; color: #94a3b8;
    cursor: pointer; user-select: none;
  }
  .option input { accent-color: var(--accent); width: 18px; height: 18px; cursor: pointer; }
  button {
    width: 100%; padding: .85rem; border: none; border-radius: var(--radius);
    background: var(--accent); color: #0f172a; font-weight: 600;
    font-size: 1rem; cursor: pointer; transition: background .2s;
  }
  button:hover { background: var(--accent-hover); }
  button:disabled { opacity: .5; cursor: not-allowed; }
  .result {
    margin-top: 1.4rem; padding: 1rem; border-radius: var(--radius);
    background: #0f172a; font-size: .92rem; word-break: break-all;
    display: none;
  }
  .result a { color: var(--accent); text-decoration: none; }
  .result a:hover { text-decoration: underline; }
  .error { color: var(--danger); }
  .spinner { display: none; margin-left: .4rem; }
</style>
</head>
<body>
<div class="card">
  <h1>&#128228; Share2Me</h1>
  <p class="sub">Quick &amp; simple file sharing</p>

  <form id="uploadForm" enctype="multipart/form-data">
    <label class="file-label" id="fileLabel">
      &#128193; Choose a file or drag it here
      <input type="file" name="file" id="fileInput" required />
    </label>

    <label class="option">
      <input type="checkbox" name="single_download" id="singleDl" />
      Single-time download (file deleted after first download)
    </label>

    <button type="submit" id="btn">Upload</button>
  </form>

  <div class="result" id="result"></div>
</div>

<script>
  const fileInput  = document.getElementById('fileInput');
  const fileLabel  = document.getElementById('fileLabel');
  const form       = document.getElementById('uploadForm');
  const resultDiv  = document.getElementById('result');
  const btn        = document.getElementById('btn');

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
      fileLabel.textContent = fileInput.files[0].name;
      fileLabel.classList.add('has-file');
    }
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!fileInput.files.length) return;

    btn.disabled = true;
    btn.textContent = 'Uploading…';
    resultDiv.style.display = 'none';

    const fd = new FormData();
    fd.append('file', fileInput.files[0]);
    fd.append('single_download', document.getElementById('singleDl').checked ? '1' : '0');

    try {
      const res  = await fetch('/upload', { method: 'POST', body: fd });
      const data = await res.json();
      if (data.ok) {
        const link = location.origin + '/' + data.hash;
        resultDiv.innerHTML = '&#9989; Uploaded!<br><br>Link to file: <a href="' + link + '">' + link + '</a>';
      } else {
        resultDiv.innerHTML = '<span class="error">&#10060; ' + (data.error || 'Upload failed') + '</span>';
      }
    } catch (err) {
      resultDiv.innerHTML = '<span class="error">&#10060; Network error</span>';
    }

    resultDiv.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Upload';
  });
</script>
</body>
</html>
)html";

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    // Ensure data directory exists
    fs::create_directories(DATA_DIR);

    uint16_t port = 8080;
    if (argc > 1) {
        try { port = static_cast<uint16_t>(std::stoi(argv[1])); }
        catch (...) { /* keep default */ }
    }

    crow::SimpleApp app;

    // ---- Landing page -----------------------------------------------------
    CROW_ROUTE(app, "/")
    ([]() {
        crow::response res(200);
        res.set_header("Content-Type", "text/html; charset=utf-8");
        res.body = INDEX_HTML;
        return res;
    });

    // ---- File upload (multipart/form-data) --------------------------------
    CROW_ROUTE(app, "/upload").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req) {
        crow::multipart::message msg(req);

        // -- Find the "file" part -------------------------------------------
        std::string file_body;
        std::string file_name;
        bool single_download = false;

        for (auto& [name, part] : msg.part_map) {
            if (name == "file") {
                file_body = part.body;
                // Extract original filename from Content-Disposition header
                auto cdh = part.headers.find("Content-Disposition");
                if (cdh != part.headers.end()) {
                    auto& params = cdh->second.params;
                    if (auto fn = params.find("filename"); fn != params.end()) {
                        file_name = fn->second;
                    }
                }
            } else if (name == "single_download") {
                single_download = (part.body == "1");
            }
        }

        if (file_body.empty() || file_name.empty()) {
            json j;
            j["ok"]    = false;
            j["error"] = "No file provided";
            return crow::response(400, j.dump());
        }

        // -- Compute SHA-256 of the uploaded content -----------------------
        SHA256 hasher;
        hasher.update(reinterpret_cast<const uint8_t*>(file_body.data()),
                      file_body.size());
        std::string file_sha256 = hasher.hex_digest();

        // -- Generate a unique URL token -----------------------------------
        std::string token;
        for (int attempts = 0; attempts < 20; ++attempts) {
            token = generate_token();
            if (!fs::exists(DATA_DIR / (token + ".json"))) break;
        }

        // -- Write the file ------------------------------------------------
        {
            std::ofstream ofs(DATA_DIR / (token + "_" + file_name),
                              std::ios::binary);
            ofs.write(file_body.data(),
                      static_cast<std::streamsize>(file_body.size()));
        }

        // -- Write the JSON metadata ---------------------------------------
        json meta;
        meta["id"]              = token;       // random URL token
        meta["hash"]            = file_sha256; // SHA-256 of file content
        meta["filename"]        = file_name;
        meta["stored_as"]       = token + "_" + file_name;
        meta["single_download"] = single_download;

        {
            std::ofstream ofs(DATA_DIR / (token + ".json"));
            ofs << meta.dump(2);
        }

        CROW_LOG_INFO << "Uploaded: " << file_name
                      << " [sha256: " << file_sha256.substr(0, 12) << "…]"
                      << " -> " << token
                      << (single_download ? " [single-dl]" : "");

        json resp;
        resp["ok"]   = true;
        resp["hash"] = token;  // keep key name for JS compatibility
        crow::response r(200);
        r.set_header("Content-Type", "application/json");
        r.body = resp.dump();
        return r;
    });

    // ---- Download by token (hash code in URL) ----------------------------
    CROW_ROUTE(app, "/<string>")
    ([](const std::string& token) {
        // Validate: only hex characters, exactly 10 chars
        if (token.size() != 10 ||
            token.find_first_not_of("0123456789abcdef") != std::string::npos) {
            return crow::response(404, "Not found");
        }

        fs::path meta_path = DATA_DIR / (token + ".json");
        if (!fs::exists(meta_path)) {
            return crow::response(404, "Not found");
        }

        // Read metadata
        json meta;
        {
            std::ifstream ifs(meta_path);
            if (!ifs) return crow::response(404, "Not found");
            ifs >> meta;
        }

        std::string stored_sha256 = meta.value("hash", "");
        std::string stored_as     = meta.value("stored_as", "");
        std::string filename      = meta.value("filename", "download");
        bool        single_dl     = meta.value("single_download", false);

        fs::path file_path = DATA_DIR / stored_as;
        if (!fs::exists(file_path)) {
            return crow::response(404, "File missing");
        }

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
            // Single-download path: we must read the file into memory so we
            // can delete it atomically before the response is sent.
            // Pre-allocate the exact size and use a single read() call –
            // much faster than istreambuf_iterator and avoids reallocation.
            std::error_code ec;
            fs::remove(meta_path, ec);  // expire the link immediately

            const auto file_size = fs::file_size(file_path);
            std::string body(file_size, '\0');
            {
                std::ifstream ifs(file_path, std::ios::binary);
                ifs.read(body.data(),
                         static_cast<std::streamsize>(file_size));
            }
            fs::remove(file_path, ec);
            CROW_LOG_INFO << "Single-download consumed: " << token;

            res.set_header("Content-Type", mime_for(filename));
            res.set_header("Content-Disposition",
                           "attachment; filename=\"" + filename + "\"");
            res.body = std::move(body);
        } else {
            // Normal download: Crow's static-file path reads the file in
            // 16 KiB chunks and writes directly to the socket – the full
            // file is never held in process memory.
            // set_static_file_info_unsafe uses add_header for Content-Type;
            // our subsequent set_header calls replace those values.
            res.set_static_file_info_unsafe(file_path.string());
            res.set_header("Content-Type", mime_for(filename));
            res.set_header("Content-Disposition",
                           "attachment; filename=\"" + filename + "\"");
        }

        return res;
    });

    // ---- Catch-all: reject anything else ---------------------------------
    CROW_CATCHALL_ROUTE(app)
    ([]() {
        return crow::response(403, "Forbidden");
    });

    CROW_LOG_INFO << "Share2Me listening on port " << port;
    app.port(port).multithreaded().run();

    return 0;
}
