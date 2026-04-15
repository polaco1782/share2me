#pragma once

#include <string>

/// Main upload page HTML (large constant defined in page.cpp).
extern const char* const INDEX_HTML;

/// Client-side E2EE decrypt page HTML (defined in page.cpp).
extern const char* const DECRYPT_PAGE_HTML;

/// Generate the text viewer HTML page with embedded metadata.
std::string text_viewer_html(const std::string& token,
                             const std::string& filename,
                             bool single_download,
                             const std::string& base_url = "");

/// Generate the E2EE text viewer HTML page.
std::string encrypted_text_viewer_html(const std::string& token,
                                       bool single_download,
                                       const std::string& base_url = "");

/// Generate the image viewer HTML page with embedded metadata.
std::string image_viewer_html(const std::string& token,
                              const std::string& filename,
                              bool single_download,
                              const std::string& base_url = "");

/// Generate the E2EE image viewer HTML page.
std::string encrypted_image_viewer_html(const std::string& token,
                                         bool single_download,
                                         const std::string& base_url = "");
