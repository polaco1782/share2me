mod certificates;
mod config;
mod daemon;
mod housekeeper;
mod live;
mod media;
mod page;
mod routes;
mod sandbox;
mod store;

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use hyper_util::{
    rt::{TokioExecutor, TokioTimer},
    server::conn::auto::Builder as HttpBuilder,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::fs::File;
use tokio::{sync::watch, task::JoinHandle};
use tracing_subscriber::{
    EnvFilter, fmt::Layer, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

use crate::{
    certificates::CertificateConfig,
    config::{AppConfig, MediaMode},
    live::LiveHub,
    media::ForwardEvent,
    routes::AppState,
    store::FileStore,
};

type ServerTask = JoinHandle<io::Result<()>>;

struct PreparedServers {
    secure_listener: TcpListener,
    redirect_handle: Handle<SocketAddr>,
    redirect_task: Option<ServerTask>,
    challenges: certificates::Challenges,
    certificate_config: CertificateConfig,
    tls: RustlsConfig,
}

struct ActiveMedia {
    forwarder: media::MediaForwarder,
    runtime: media::MediaRuntime,
    events: tokio::sync::mpsc::UnboundedReceiver<ForwardEvent>,
}

struct RunningMedia {
    runtime: media::MediaRuntime,
    event_task: JoinHandle<()>,
}

#[tokio::main]
async fn main() {
    let config = match AppConfig::from_args() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    };

    if config.daemon
        && let Err(error) = daemon::daemonize()
    {
        eprintln!("Failed to daemonize: {error}");
        std::process::exit(1);
    }

    init_logging(config.log_file.as_deref());

    if let Err(error) = run(config).await {
        tracing::error!(error = %format!("{error:#}"), "Share2Me failed");
        std::process::exit(1);
    }
}

async fn run(config: AppConfig) -> Result<()> {
    sandbox::apply_resource_limits()?;
    let mut store = FileStore::new(config.data_dir.clone()).context("initializing data storage")?;
    let jail_user = sandbox::resolve_user(config.drop_user.as_deref())?;
    sandbox::require_root(config.sandbox, jail_user.as_ref())?;
    sandbox::warn_if_root(jail_user.as_ref());
    if let Some(user) = &jail_user {
        sandbox::assign_data_directory(store.data_dir(), user)?;
    }

    let PreparedServers {
        secure_listener,
        redirect_handle,
        redirect_task,
        challenges,
        certificate_config,
        tls,
    } = prepare_servers(&config).await?;
    let media_setup = start_media(&config).await?;

    if config.sandbox {
        tracing::info!(path = %store.data_dir().display(), "entering chroot jail");
        sandbox::enter(store.data_dir())?;
        store.rebase_after_chroot();
        tracing::info!("chroot jail active");
    }
    if let Some(user) = &jail_user {
        sandbox::drop_privileges(user)?;
    }

    let live = LiveHub::default();
    let (forwarder, running_media) = attach_media(&live, media_setup);
    let state = AppState::new(
        store.clone(),
        config.base_url(),
        live,
        config.media_mode,
        config.rtc_ice_servers(),
        forwarder,
    );
    let app = routes::https_router(state, config.http_log, &config.domain);
    let secure_handle: Handle<SocketAddr> = Handle::new();
    let mut server =
        axum_server::from_tcp_rustls(secure_listener, tls.clone())?.handle(secure_handle.clone());
    configure_http(server.http_builder());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let housekeeper_task = tokio::spawn(housekeeper::run(store, shutdown_rx.clone()));
    let renewal_task = if config.sandbox {
        tracing::warn!("automatic certificate renewal is disabled inside the chroot jail");
        None
    } else {
        Some(tokio::spawn(certificates::renewal_loop(
            certificate_config,
            challenges,
            tls,
            shutdown_rx,
        )))
    };

    let mut secure_task = tokio::spawn(server.serve(app.into_make_service()));
    let secure_address = wait_for_server("HTTPS", &secure_handle, &mut secure_task).await?;
    tracing::info!(
        address = %secure_address,
        http_port = config.http_port,
        data_dir = %config.data_dir.display(),
        "Share2Me is listening"
    );
    let early_server_result = tokio::select! {
        result = &mut secure_task => Some(result),
        result = tokio::signal::ctrl_c() => {
            result.context("installing shutdown signal handler")?;
            tracing::info!("shutdown requested");
            None
        }
    };

    secure_handle.graceful_shutdown(Some(Duration::from_secs(10)));
    if redirect_task.is_some() {
        redirect_handle.graceful_shutdown(Some(Duration::from_secs(10)));
    }
    let _ = shutdown_tx.send(true);
    housekeeper_task.await.context("joining housekeeper")?;
    if let Some(task) = renewal_task {
        task.await.context("joining certificate renewal task")?;
    }
    if let Some(task) = redirect_task {
        task.await.context("joining HTTP server task")??;
    }
    let secure_result = match early_server_result {
        Some(result) => result
            .context("joining HTTPS server task")
            .and_then(|result| result.context("running HTTPS server")),
        None => secure_task
            .await
            .context("joining HTTPS server task")
            .and_then(|result| result.context("running HTTPS server")),
    };
    if let Some(media) = running_media {
        media.shutdown().await?;
    }
    secure_result?;
    Ok(())
}

async fn prepare_servers(config: &AppConfig) -> Result<PreparedServers> {
    // Bind privileged ports before ACME provisioning and before dropping privileges.
    let secure_listener = bind_listener(config.https_port, "HTTPS")?;
    let redirect_listener = if config.http_port == 0 {
        None
    } else {
        Some(bind_listener(config.http_port, "HTTP")?)
    };
    let challenges = certificates::restore_challenges(std::path::Path::new("acme_work")).await;
    let redirect_handle: Handle<SocketAddr> = Handle::new();
    let mut redirect_task = spawn_http_server(
        redirect_listener,
        challenges.clone(),
        config.base_url(),
        config.http_log,
        redirect_handle.clone(),
    );
    if let Some(task) = redirect_task.as_mut() {
        let address = wait_for_server("HTTP", &redirect_handle, task).await?;
        tracing::info!(%address, "HTTP challenge and redirect server is ready");
    }
    let certificate_config = certificate_config(config);
    provision_while_http_runs(&certificate_config, &challenges, redirect_task.as_mut()).await?;
    let tls = RustlsConfig::from_pem_file(&config.cert, &config.key)
        .await
        .context("loading TLS certificate and private key")?;
    Ok(PreparedServers {
        secure_listener,
        redirect_handle,
        redirect_task,
        challenges,
        certificate_config,
        tls,
    })
}

async fn start_media(config: &AppConfig) -> Result<Option<ActiveMedia>> {
    if config.media_mode != MediaMode::Forward {
        tracing::info!(mode = ?config.media_mode, "live media mode configured");
        return Ok(None);
    }
    let address = resolve_media_address(config).await?;
    let (forwarder, runtime, events) = media::start(address)?;
    tracing::info!(%address, "built-in media forwarder is ready on UDP");
    Ok(Some(ActiveMedia {
        forwarder,
        runtime,
        events,
    }))
}

fn attach_media(
    live: &LiveHub,
    setup: Option<ActiveMedia>,
) -> (Option<media::MediaForwarder>, Option<RunningMedia>) {
    let Some(ActiveMedia {
        forwarder,
        runtime,
        mut events,
    }) = setup
    else {
        return (None, None);
    };
    let event_hub = live.clone();
    let event_task = tokio::spawn(async move {
        while let Some(ForwardEvent::Disconnected {
            session_id,
            role,
            connection_id,
        }) = events.recv().await
        {
            event_hub
                .release_forward_peer(&session_id, role, connection_id)
                .await;
        }
    });
    (
        Some(forwarder),
        Some(RunningMedia {
            runtime,
            event_task,
        }),
    )
}

impl RunningMedia {
    async fn shutdown(self) -> Result<()> {
        self.runtime.shutdown().await;
        self.event_task.await.context("joining media event task")?;
        Ok(())
    }
}

async fn resolve_media_address(config: &AppConfig) -> Result<SocketAddr> {
    let ip = if let Some(address) = config.media_address {
        address
    } else if config.domain == "localhost" {
        Ipv4Addr::LOCALHOST.into()
    } else if let Ok(address) = config.domain.parse() {
        address
    } else {
        let addresses = tokio::net::lookup_host((config.domain.as_str(), config.media_port))
            .await
            .with_context(|| format!("resolving media address for {}", config.domain))?
            .collect::<Vec<_>>();
        addresses
            .iter()
            .find(|address| address.is_ipv4())
            .or_else(|| addresses.first())
            .map(SocketAddr::ip)
            .ok_or_else(|| anyhow!("{} did not resolve to a media address", config.domain))?
    };
    Ok(SocketAddr::new(ip, config.media_port))
}

fn spawn_http_server(
    listener: Option<TcpListener>,
    challenges: certificates::Challenges,
    base_url: String,
    http_log: bool,
    handle: Handle<SocketAddr>,
) -> Option<ServerTask> {
    listener.map(|listener| {
        let router = routes::http_router(challenges, base_url, http_log);
        tokio::spawn(async move {
            let mut server = axum_server::from_tcp(listener)?.handle(handle);
            configure_http(server.http_builder());
            server.serve(router.into_make_service()).await
        })
    })
}

async fn wait_for_server(
    label: &'static str,
    handle: &Handle<SocketAddr>,
    task: &mut ServerTask,
) -> Result<SocketAddr> {
    tokio::select! {
        address = handle.listening() => {
            address.with_context(|| format!("{label} server failed before listening"))
        }
        result = &mut *task => Err(server_exit_error(label, result)),
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            bail!("timed out waiting for {label} server readiness")
        }
    }
}

async fn provision_while_http_runs(
    config: &CertificateConfig,
    challenges: &certificates::Challenges,
    http_task: Option<&mut ServerTask>,
) -> Result<()> {
    if let Some(task) = http_task {
        tokio::select! {
            result = certificates::provision(config, challenges, 3, true) => result.map(drop),
            result = &mut *task => Err(server_exit_error("HTTP", result)),
        }
    } else {
        certificates::provision(config, challenges, 3, true)
            .await
            .map(drop)
    }
}

fn server_exit_error(
    label: &str,
    result: Result<io::Result<()>, tokio::task::JoinError>,
) -> anyhow::Error {
    match result {
        Ok(Ok(())) => anyhow!("{label} server stopped unexpectedly"),
        Ok(Err(error)) => anyhow!("{label} server failed: {error}"),
        Err(error) => anyhow!("{label} server task failed: {error}"),
    }
}

fn certificate_config(config: &AppConfig) -> CertificateConfig {
    CertificateConfig {
        cert_path: config.cert.clone(),
        key_path: config.key.clone(),
        domain: config.domain.clone(),
        use_acme: config.acme,
        email: config.email.clone(),
        staging: config.staging,
        verbose: config.acme_verbose,
        work_dir: "acme_work".into(),
    }
}

fn bind_listener(port: u16, label: &str) -> Result<TcpListener> {
    let ipv6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
    match bind_socket(ipv6) {
        Ok(listener) => Ok(listener),
        Err(ipv6_error) => bind_socket(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .with_context(|| {
                format!("binding {label} port {port}; IPv6 attempt failed: {ipv6_error}")
            }),
    }
}

fn bind_socket(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        // HTTP-01 must be reachable through both A and AAAA records.
        socket.set_only_v6(false)?;
    }
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn configure_http(builder: &mut HttpBuilder<TokioExecutor>) {
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_headers(64)
        .max_buf_size(64 * 1024);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(Some(64))
        .max_header_list_size(32 * 1024)
        .max_pending_accept_reset_streams(Some(32));
}

fn init_logging(log_file: Option<&std::path::Path>) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("share2me=info,instant_acme=warn,axum_server=warn"));
    let subscriber = tracing_subscriber::registry().with(filter);

    let subscriber = subscriber.with(
        Layer::default()
            .with_ansi(true)
            .with_target(false)
            .compact(),
    );

    if let Some(path) = log_file {
        let file = File::create(path)
            .unwrap_or_else(|e| panic!("failed to open log file '{}': {e}", path.display()));
        let file_layer = Layer::default()
            .with_writer(file)
            .with_ansi(false)
            .with_target(false)
            .compact();
        subscriber.with(file_layer).init();
    } else {
        subscriber.init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_start_failure_is_reported_before_waiting_for_acme() {
        let handle = Handle::new();
        let mut task = tokio::spawn(async { Err(io::Error::other("listener failed")) });
        let error = wait_for_server("HTTP", &handle, &mut task)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("listener failed"));
    }
}
