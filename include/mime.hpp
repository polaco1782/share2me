#pragma once

#include <string>

/// Guess a Content-Type from the file extension.
/// Falls back to application/octet-stream for unknown types.
std::string mime_for(const std::string& filename);
