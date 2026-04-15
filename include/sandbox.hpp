#pragma once

#include <filesystem>
#include <string>

#ifdef __linux__
#  include <sys/types.h>
#endif

namespace sandbox {

struct UserInfo {
#ifdef __linux__
    uid_t       uid{};
    gid_t       gid{};
#endif
    std::string name;
};

/// Look up a user by name and return its UID/GID.
/// Must be called *before* enter_chroot() — requires /etc/passwd.
UserInfo lookup_user(const std::string& username);

/// Transfer ownership of @dir to @user so the process can write files
/// after privilege drop.  Skipped silently if the effective UID is not root.
void chown_jail(const std::filesystem::path& dir, const UserInfo& user);

/// Jail the calling process into @dir via chroot(2) + chdir("/").
void enter_chroot(const std::filesystem::path& dir);

/// Permanently drop privileges to @user.
void drop_privileges(const UserInfo& user);

} // namespace sandbox
