# Share2Me

Lightweight, single-binary HTTP file sharing server built with C++20.

## Features

- **Upload** any file via a clean web UI
- **Single-time download** option — file is auto-deleted after the first download
- **Unique hash links** — e.g. `http://yourhost:8080/a1b2c3d4e5`
- **Standalone binary** — minimal runtime dependencies

## Building

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

The binary is placed at `build/share2me`.

## Running

```bash
# Default port 8080
./build/share2me

# Custom port
./build/share2me 9000
```

Then open `http://localhost:8080` in your browser.

## How it works

1. Visit the web UI and pick a file to upload.
2. Optionally check **Single-time download**.
3. Click **Upload** — the server returns a unique link.
4. Share the link. The recipient downloads the file via that link.
5. If single-time download was selected, the file is removed after the first download.

All files and their JSON metadata are stored in the `data/` directory next to the binary.

## Tech Stack

| Component | Library |
|-----------|---------|
| HTTP server | [Crow](https://github.com/CrowCpp/Crow) v1.2.0 |
| JSON | [nlohmann/json](https://github.com/nlohmann/json) v3.11.3 |
| Build system | CMake ≥ 3.20 |
| Language | C++20 |
