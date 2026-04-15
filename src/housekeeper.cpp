#include "housekeeper.hpp"
#include "logging.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

Housekeeper::Housekeeper(const FileStore& store)
    : store_(store)
{}

Housekeeper::~Housekeeper() {
    stop();
}

void Housekeeper::start() {
    stop_ = false;

    thread_ = std::thread([this]() {
        while (!stop_.load()) {
            for (int i = 0; i < 60 && !stop_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));
            if (stop_.load()) break;

            try {
                const auto& data_dir = store_.data_dir();
                long long now_sec = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                for (auto& entry : fs::directory_iterator(data_dir)) {
                    if (entry.path().extension() != ".json") continue;

                    std::error_code ec;
                    if (entry.is_symlink(ec)) {
                        LOG_WARNING << "Housekeep: skipping symlink: "
                                    << entry.path().filename();
                        continue;
                    }

                    try {
                        nlohmann::json meta;
                        {
                            std::ifstream ifs(entry.path());
                            if (!ifs) continue;
                            ifs >> meta;
                        }
                        if (!meta.contains("expires_at")) continue;
                        long long expires_at = meta["expires_at"].get<long long>();
                        if (now_sec >= expires_at) {
                            std::string stored_as = meta.value("stored_as", "");

                            if (!stored_as.empty()) {
                                fs::path stored_path = data_dir / stored_as;
                                if (fs::is_symlink(stored_path, ec)) {
                                    LOG_WARNING << "Housekeep: refusing to "
                                                   "remove symlink: "
                                                << stored_as;
                                } else {
                                    fs::remove(stored_path, ec);
                                }
                            }

                            fs::remove(entry.path(), ec);
                            LOG_INFO << "Housekeep: expired file removed: "
                                     << meta.value("id", "?");
                        }
                    } catch (...) {}
                }
            } catch (...) {}
        }
    });
}

void Housekeeper::stop() {
    stop_ = true;
    if (thread_.joinable())
        thread_.join();
}
