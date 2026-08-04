mod certificates;
mod config;
mod housekeeper;
mod page;
mod routes;
mod sandbox;
mod store;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    time::Duration,
};

use anyhow::{Context, Result};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use hyper_util::{
    rt::{TokioExecutor, TokioTimer},
    server::conn::auto::Builder as HttpBuilder,
};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

use crate::{
    certificates::CertificateConfig, config::AppConfig, routes::AppState, store::FileStore,
};

#[tokio::main]
async fn main() {
    init_logging();
    if let Err(error) = run().await {
        tracing::error!(error = %format!("{error:#}"), "Share2Me failed");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    sandbox::apply_resource_limits()?;
    let config = AppConfig::from_args()?;
    let mut store = FileStore::new(config.data_dir.clone()).context("initializing data storage")?;
    let jail_user = sandbox::resolve_user(config.drop_user.as_deref())?;
    sandbox::require_root(config.sandbox, jail_user.as_ref())?;
    sandbox::warn_if_root(jail_user.as_ref());
    if let Some(user) = &jail_user {
        sandbox::assign_data_directory(store.data_dir(), user)?;
    }

    // Bind privileged ports before ACME provisioning and before dropping privileges.
    let secure_listener = bind_listener(config.https_port, "HTTPS")?;
    let redirect_listener = if config.http_port == 0 {
        None
    } else {
        Some(bind_listener(config.http_port, "HTTP")?)
    };

    let challenges = certificates::restore_challenges(std::path::Path::new("acme_work")).await;
    let redirect_handle: Handle<SocketAddr> = Handle::new();
    let redirect_task = redirect_listener.map(|listener| {
        let router = routes::http_router(challenges.clone(), config.base_url(), config.http_log);
        let handle = redirect_handle.clone();
        tokio::spawn(async move {
            let mut server = axum_server::from_tcp(listener)?.handle(handle);
            configure_http(server.http_builder());
            server.serve(router.into_make_service()).await
        })
    });

    let certificate_config = certificate_config(&config);
    certificates::provision(&certificate_config, &challenges, 3).await?;
    let tls = RustlsConfig::from_pem_file(&config.cert, &config.key)
        .await
        .context("loading TLS certificate and private key")?;

    if config.sandbox {
        tracing::info!(path = %store.data_dir().display(), "entering chroot jail");
        sandbox::enter(store.data_dir())?;
        store.rebase_after_chroot();
        tracing::info!("chroot jail active");
    }
    if let Some(user) = &jail_user {
        sandbox::drop_privileges(user)?;
    }

    let state = AppState::new(store.clone(), config.base_url());
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

    tracing::info!(
        https_port = config.https_port,
        http_port = config.http_port,
        data_dir = %config.data_dir.display(),
        "Share2Me is listening"
    );

    let mut secure_task = tokio::spawn(server.serve(app.into_make_service()));
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
    match early_server_result {
        Some(result) => result.context("joining HTTPS server task")??,
        None => secure_task.await.context("joining HTTPS server task")??,
    }
    Ok(())
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
    match TcpListener::bind(ipv6) {
        Ok(listener) => Ok(listener),
        Err(ipv6_error) => TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .with_context(|| {
                format!("binding {label} port {port}; IPv6 attempt failed: {ipv6_error}")
            }),
    }
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

fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("share2me=info,instant_acme=warn,axum_server=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}
