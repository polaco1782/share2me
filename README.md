# Share2Me

Lightweight, single-binary HTTPS file sharing server built with C++20.

## Features

- **Upload** any file via a clean web UI or directly from the command line with `curl`
- **Single-time download** option — file is auto-deleted after the first download
- **Unique share links** — e.g. `https://yourhost:8443/a1b2c3d4e5`
- **TLS out of the box** — auto-generates a self-signed certificate on first run
- **Let's Encrypt support** — optional ACME v2 HTTP-01 challenge (requires libcurl at build time)
- **HTTP → HTTPS redirect** — a background HTTP server redirects plain-HTTP traffic
- **Integrity checking** — every download is SHA-256 verified before delivery
- **Standalone binary** — no runtime dependencies beyond OpenSSL

## Building

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

The binary is placed at `build/share2me`.

> **Note:** libcurl is an optional dependency. When found at build time, Let's Encrypt
> ACME support is compiled in. Without it the server still works fully with
> self-signed or manually supplied certificates.

## Running

```bash
# Defaults: HTTPS on 8443, HTTP redirect on 8080, self-signed cert for localhost
./build/share2me

# Custom ports
./build/share2me --port 443 --http-port 80

# Custom domain + pre-existing certificate
./build/share2me --domain example.com --cert /etc/ssl/example.crt --key /etc/ssl/example.key

# Automatic Let's Encrypt certificate (requires libcurl, port 80 reachable)
./build/share2me --domain example.com --email admin@example.com --acme

# Let's Encrypt staging (safe for testing, cert is not trusted by browsers)
./build/share2me --domain example.com --email admin@example.com --acme --staging

# Disable the HTTP redirect/ACME server entirely
./build/share2me --http-port 0
```

Then open `https://localhost:8443` in your browser.

### Command-line reference

| Flag | Default | Description |
|------|---------|-------------|
| `--port PORT` | `8443` | HTTPS listening port |
| `--http-port PORT` | `8080` | HTTP port for redirect & ACME challenges (`0` = disabled) |
| `--cert FILE` | `cert.pem` | TLS certificate file (PEM) |
| `--key FILE` | `key.pem` | TLS private key file (PEM) |
| `--domain NAME` | `localhost` | Certificate CN / hostname |
| `--acme` | off | Request a certificate from Let's Encrypt via ACME v2 |
| `--email EMAIL` | — | Contact email (required with `--acme`) |
| `--staging` | off | Use the Let's Encrypt staging server |

## Uploading files

### Web UI

1. Open `https://<host>:<port>` in your browser.
2. Choose a file, optionally enable **Single-time download**, and click **Upload**.
3. Copy the link and share it.

### Command line (`curl`)

```bash
# Basic upload — prints the download URL
curl -kT photo.jpg https://localhost:8443/photo.jpg

# Single-download (file deleted after first download)
curl -kT report.pdf "https://localhost:8443/report.pdf?single"

# Capture the URL in a variable
url=$(curl -skT archive.tar.gz https://localhost:8443/archive.tar.gz)
echo "Share this: $url"
```

The server responds with the download URL as a single plain-text line.

Drop `-k` when using a trusted certificate (Let's Encrypt or custom CA).

## How it works

1. A file is uploaded via the web UI (`POST /upload`) or via `PUT /<filename>`.
2. The server generates a random 10-character hex token as the URL identifier.
3. The file is saved to `data/<token>_<filename>` alongside a JSON metadata file.
4. On download the SHA-256 hash is re-computed and verified against the stored value.
5. If single-time download was selected, both the file and its metadata are deleted
   immediately before the response is sent.

All files and their JSON metadata are stored in the `data/` directory next to the binary.

## TLS certificates

On first startup (when neither `cert.pem` nor `key.pem` exists) the server automatically
generates a self-signed RSA-2048 certificate valid for 10 years. The certificate includes
Subject Alternative Names for the configured domain, `localhost`, and `127.0.0.1`.

Each generated certificate gets a **random serial number** to avoid the
`SEC_ERROR_REUSED_ISSUER_AND_SERIAL` error that NSS-based browsers (Firefox, Chrome on
Linux) raise when a new self-signed cert reuses the same issuer + serial pair as a
previously trusted one.

To replace the certificate at any time, delete `cert.pem` and `key.pem` and restart the
server, or supply your own files with `--cert` / `--key`.

## Tech Stack

| Component | Library |
|-----------|---------|
| HTTP/HTTPS server | [Crow](https://github.com/CrowCpp/Crow) v1.2.0 |
| JSON | [nlohmann/json](https://github.com/nlohmann/json) v3.11.3 |
| TLS & cert generation | OpenSSL 3.x |
| ACME / Let's Encrypt | libcurl (optional) |
| Build system | CMake ≥ 3.20 |
| Language | C++20 |
