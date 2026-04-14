#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <thread>

namespace housekeeper {

std::atomic<bool> stop_housekeep{false};
std::thread housekeep_thread;

void start_housekeeper_thread() {
    // Background thread that periodically scans for expired files and removes them.
    housekeep_thread = std::thread([]() {
        while (!stop_housekeep.load()) {
            // Sleep 60 seconds but wake quickly on stop.
            for (int i = 0; i < 60 && !stop_housekeep.load(); ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));
            if (stop_housekeep.load()) break;

            try {
                long long now_sec = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                for (auto& entry : fs::directory_iterator(DATA_DIR)) {
                    if (entry.path().extension() != ".json") continue;

                    // Skip symlinks to prevent symlink attacks
                    std::error_code ec;
                    if (entry.is_symlink(ec)) {
                        CROW_LOG_WARNING << "Housekeep: skipping symlink: "
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

                            // Verify stored file is not a symlink before removing
                            if (!stored_as.empty()) {
                                fs::path stored_path = DATA_DIR / stored_as;
                                if (fs::is_symlink(stored_path, ec)) {
                                    CROW_LOG_WARNING << "Housekeep: refusing to remove symlink: "
                                                     << stored_as;
                                } else {
                                    fs::remove(stored_path, ec);
                                }
                            }

                            fs::remove(entry.path(), ec);
                            CROW_LOG_INFO << "Housekeep: expired file removed: "
                                          << meta.value("id", "?");
                        }
                    } catch (...) {}
                }
            } catch (...) {}
        }
    });
}

void stop_housekeeper_thread() {
    stop_housekeep = true;
    if (housekeep_thread.joinable()) housekeep_thread.join();
}

}