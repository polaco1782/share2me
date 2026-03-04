// token.hpp – Random URL token generation
#pragma once

#include <cstdint>
#include <random>
#include <sstream>
#include <string>

/// Generate a random 10-character lowercase hex token used as the URL identifier.
inline std::string generate_token() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    std::uint64_t value = dist(rng);

    std::ostringstream oss;
    oss << std::hex << (value & 0xFF'FFFF'FFFFull); // 10 hex chars
    std::string h = oss.str();
    while (h.size() < 10) h.insert(h.begin(), '0'); // pad leading zeros
    return h;
}
