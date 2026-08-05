use std::path::Path;

use anyhow::{Context, Result, bail};
use nix::{
    sys::resource::{Resource, getrlimit, setrlimit},
    unistd::{
        Uid, User, chdir, chown, chroot, getegid, geteuid, getgid, getuid, setgid, setgroups,
        setuid,
    },
};

pub fn apply_resource_limits() -> Result<()> {
    setrlimit(Resource::RLIMIT_CORE, 0, 0).context("disabling core dumps")?;
    let (_, hard_limit) =
        getrlimit(Resource::RLIMIT_NOFILE).context("reading the descriptor limit")?;
    let descriptor_limit = hard_limit.min(4096);
    setrlimit(Resource::RLIMIT_NOFILE, descriptor_limit, descriptor_limit)
        .context("limiting open descriptors")
}

pub fn resolve_user(name: Option<&str>) -> Result<Option<User>> {
    let Some(name) = name else {
        return Ok(None);
    };
    let user = User::from_name(name)
        .context("looking up --user")?
        .ok_or_else(|| anyhow::anyhow!("system user '{name}' does not exist"))?;
    if user.uid.is_root() {
        bail!("--user must name an unprivileged account");
    }
    Ok(Some(user))
}

pub fn require_root(sandbox: bool, user: Option<&User>) -> Result<()> {
    if (sandbox || user.is_some()) && !geteuid().is_root() {
        bail!("--sandbox and --user require root privileges");
    }
    Ok(())
}

pub fn warn_if_root(user: Option<&User>) {
    if geteuid().is_root() && user.is_none() {
        tracing::warn!("running as root; use --user to reduce process privileges");
    }
}

pub fn assign_data_directory(data_dir: &Path, user: &User) -> Result<()> {
    chown(data_dir, Some(user.uid), Some(user.gid)).context("changing data directory owner")
}

pub fn enter(data_dir: &Path) -> Result<()> {
    chroot(data_dir).with_context(|| format!("entering chroot at {}", data_dir.display()))?;
    chdir("/").context("changing to the chroot root")?;
    Ok(())
}

pub fn drop_privileges(user: &User) -> Result<()> {
    setgroups(&[]).context("clearing supplementary groups")?;
    setgid(user.gid).context("setting process group")?;
    setuid(user.uid).context("setting process user")?;

    if getuid() != user.uid
        || geteuid() != user.uid
        || getgid() != user.gid
        || getegid() != user.gid
    {
        bail!("privilege-drop verification failed");
    }
    if setuid(Uid::from_raw(0)).is_ok() {
        bail!("privilege-drop verification failed: root can be reacquired");
    }
    tracing::info!(user = %user.name, uid = user.uid.as_raw(), gid = user.gid.as_raw(), "privileges dropped and verified");
    Ok(())
}
