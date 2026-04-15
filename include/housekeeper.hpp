#pragma once

#include "store.hpp"

#include <atomic>
#include <thread>

/// Background thread that periodically scans for and removes expired files.
class Housekeeper {
public:
    explicit Housekeeper(const FileStore& store);
    ~Housekeeper();

    Housekeeper(const Housekeeper&)            = delete;
    Housekeeper& operator=(const Housekeeper&) = delete;

    /// Spawn the cleanup thread (non-blocking).
    void start();

    /// Signal the thread to stop and join.
    void stop();

private:
    const FileStore&    store_;
    std::atomic<bool>   stop_{false};
    std::thread         thread_;
};
