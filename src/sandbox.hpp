#pragma once

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>

#ifdef __linux__
#  include <sys/types.h>
#  include <grp.h>
#  include <pwd.h>
#  include <unistd.h>
#endif

namespace sandbox {

struct UserInfo {
    uid_t       uid{};
    gid_t       gid{};
    std::string name;
};

/// Look up a user by name and return its UID/GID.
/// Must be called *before* enter_chroot() — requires /etc/passwd.
UserInfo lookup_user(const std::string& username) {
#ifdef __linux__
    errno = 0;
    const struct passwd* pw = ::getpwnam(username.c_str());
    if (!pw)
        throw std::runtime_error(errno
            ? "getpwnam(" + username + "): " + std::strerror(errno)
            : "user not found: " + username);
    return {pw->pw_uid, pw->pw_gid, username};
#else
    (void)username;
    throw std::runtime_error("sandbox::lookup_user: not supported on this platform");
#endif
}

/// Transfer ownership of @dir to @user so the process can write files
/// after privilege drop.  Skipped silently if the effective UID is not root.
void chown_jail(const std::filesystem::path& dir, const UserInfo& user) {
#ifdef __linux__
    if (::geteuid() == 0 &&
        ::chown(dir.c_str(), user.uid, user.gid) != 0)
        throw std::system_error(errno, std::generic_category(),
                                "chown(" + dir.string() + ")");
#else
    (void)dir; (void)user;
#endif
}

/// Jail the calling process into @dir via chroot(2) + chdir("/").
/// Requires CAP_SYS_CHROOT (effective UID 0 on most Linux systems).
/// chroot is process-wide — all threads are jailed simultaneously.
void enter_chroot(const std::filesystem::path& dir) {
#ifdef __linux__
    if (::chroot(dir.c_str()) != 0)
        throw std::system_error(errno, std::generic_category(),
                                "chroot(" + dir.string() + ")");
    if (::chdir("/") != 0)
        throw std::system_error(errno, std::generic_category(),
                                "chdir(/) after chroot");
#else
    (void)dir;
    throw std::runtime_error("sandbox::enter_chroot: not supported on this platform");
#endif
}

/// Permanently drop privileges to @user.
/// Requires CAP_SETUID + CAP_SETGID (effective UID 0).
/// Order: clear supplementary groups → setgid → setuid.
/// Verifies that UID 0 cannot be re-acquired afterwards.
void drop_privileges(const UserInfo& user) {
#ifdef __linux__
    if (::setgroups(0, nullptr) != 0)
        throw std::system_error(errno, std::generic_category(), "setgroups");
    if (::setgid(user.gid) != 0)
        throw std::system_error(errno, std::generic_category(), "setgid");
    if (::setuid(user.uid) != 0)
        throw std::system_error(errno, std::generic_category(), "setuid");
    // Sanity check: after a successful drop, setuid(0) must fail.
    if (::setuid(0) == 0)
        throw std::runtime_error(
            "sandbox: privilege drop verification failed - "
            "process can still re-acquire UID 0");
#else
    (void)user;
    throw std::runtime_error("sandbox::drop_privileges: not supported on this platform");
#endif
}

} // namespace sandbox
