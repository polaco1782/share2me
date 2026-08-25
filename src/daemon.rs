use anyhow::Result;

/// Daemonize the current process using the `daemonize` crate.
pub fn daemonize() -> Result<()> {
    let daemonize_crate = daemonize::Daemonize::new()
        .pid_file("share2me.pid")
        .chown_pid_file(true);

    if let Err(error) = daemonize_crate.start() {
        anyhow::bail!("failed to daemonize: {error}");
    }

    Ok(())
}
