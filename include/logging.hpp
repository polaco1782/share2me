#pragma once

#include <cstdio>
#include <ctime>
#include <filesystem>
#include <string>
#include <type_traits>

/// Minimal logging macros
/// Each macro produces a temporary object whose destructor flushes the line.

namespace s2m_log {

enum class Level { Info, Warning, Error };

struct LogLine {
    Level level;
    std::string buf;

    LogLine(Level l, const char* file, int line) : level(l) {
        char ts[32];
        std::time_t now = std::time(nullptr);
        std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

        const char* tag = "INFO";
        if (level == Level::Warning) tag = "WARN";
        else if (level == Level::Error) tag = "ERROR";

        buf.reserve(256);
        buf += '[';
        buf += ts;
        buf += "] [";
        buf += tag;
        buf += "] ";
    }

    // C-string literals and const char*
    LogLine& operator<<(const char* s) {
        if (s) buf += s;
        return *this;
    }

    // std::string
    LogLine& operator<<(const std::string& s) {
        buf += s;
        return *this;
    }

    // std::string_view
    LogLine& operator<<(std::string_view sv) {
        buf.append(sv.data(), sv.size());
        return *this;
    }

    // filesystem::path
    LogLine& operator<<(const std::filesystem::path& p) {
        buf += p.string();
        return *this;
    }

    // Arithmetic types (int, float, size_t, etc.)
    template <typename T,
              std::enable_if_t<std::is_arithmetic_v<T>, int> = 0>
    LogLine& operator<<(T val) {
        buf += std::to_string(val);
        return *this;
    }

    ~LogLine() {
        buf += '\n';
        std::fputs(buf.c_str(), stderr);
        std::fflush(stderr);
    }

    LogLine(const LogLine&) = delete;
    LogLine& operator=(const LogLine&) = delete;
    LogLine(LogLine&&) = default;
};

} // namespace s2m_log

#define LOG_INFO    s2m_log::LogLine(s2m_log::Level::Info,    __FILE__, __LINE__)
#define LOG_WARNING s2m_log::LogLine(s2m_log::Level::Warning, __FILE__, __LINE__)
#define LOG_ERROR   s2m_log::LogLine(s2m_log::Level::Error,   __FILE__, __LINE__)
