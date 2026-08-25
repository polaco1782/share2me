use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{
        DefaultBodyLimit, FromRequest, Multipart, Path, Query, Request, State, ws::WebSocketUpgrade,
    },
    http::{
        HeaderMap, HeaderValue, StatusCode, Uri,
        header::{
            CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_SECURITY_POLICY,
            CONTENT_TYPE, LOCATION, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
            X_CONTENT_TYPE_OPTIONS,
        },
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use futures_util::StreamExt;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::json;
use str0m::change::SdpOffer;
use tokio::sync::Semaphore;
use tokio_util::io::ReaderStream;
use tower_http::{
    catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, timeout::RequestBodyTimeoutLayer,
};

use crate::{
    certificates::Challenges,
    config::{MediaMode, RtcIceServer},
    live::{LiveHub, MAX_SDP_BYTES, MAX_SIGNAL_BYTES, PeerRole},
    media::{ForwardJoinError, MediaForwarder, MediaRole},
    page::{
        ViewerKind, decrypt_page_html, index_html, share_page_html, viewer_html, watch_page_html,
    },
    store::{FileStore, MAX_UPLOAD_BYTES, StorageError, is_safe_filename, is_valid_token},
};

const MULTIPART_OVERHEAD_ALLOWANCE: usize = 1024 * 1024;
const MAX_EXPIRY_SECONDS: u64 = 100 * 365 * 86_400;
const IMAGE_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "webp", "svg", "ico", "bmp", "tiff", "tif", "avif",
];
const ENCRYPTED_TEXT_EXTENSIONS: &[&str] = &[
    "txt", "md", "json", "xml", "html", "htm", "css", "js", "mjs", "ts", "tsx", "yaml", "yml",
    "toml", "ini", "cfg", "conf", "log", "csv", "tsv", "c", "cpp", "cc", "cxx", "h", "hpp", "hxx",
    "java", "py", "rb", "go", "rs", "php", "sh", "bash", "zsh", "fish", "pl", "lua", "r", "sql",
    "diff", "patch", "tex", "latex",
];

#[derive(Clone, Debug)]
pub struct AppState {
    store: FileStore,
    base_url: String,
    claims: Arc<Mutex<HashSet<String>>>,
    upload_slots: Arc<Semaphore>,
    live: LiveHub,
    ice_servers: Arc<Vec<RtcIceServer>>,
    media_mode: MediaMode,
    forwarder: Option<MediaForwarder>,
}

impl AppState {
    pub fn new(
        store: FileStore,
        base_url: String,
        live: LiveHub,
        media_mode: MediaMode,
        ice_servers: Vec<RtcIceServer>,
        forwarder: Option<MediaForwarder>,
    ) -> Self {
        Self {
            store,
            base_url,
            claims: Arc::new(Mutex::new(HashSet::new())),
            upload_slots: Arc::new(Semaphore::new(8)),
            live,
            ice_servers: Arc::new(ice_servers),
            media_mode,
            forwarder,
        }
    }
}

#[derive(Clone, Copy, Debug, serde::Deserialize)]
struct SignalQuery {
    role: PeerRole,
}

#[derive(Clone, Debug)]
struct HttpState {
    challenges: Challenges,
    base_url: String,
}

#[derive(Clone, Copy, Debug)]
struct RequestPolicy {
    log_requests: bool,
    hsts: bool,
}

pub fn https_router(state: AppState, log_requests: bool, domain: &str) -> Router {
    let body_limit = usize::try_from(MAX_UPLOAD_BYTES)
        .unwrap_or(usize::MAX.saturating_sub(MULTIPART_OVERHEAD_ALLOWANCE))
        .saturating_add(MULTIPART_OVERHEAD_ALLOWANCE);
    let policy = RequestPolicy {
        log_requests,
        hsts: domain != "localhost" && domain.parse::<IpAddr>().is_err(),
    };
    let media_mode = state.media_mode;
    let router = Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
        .route("/robots.txt", get(robots))
        .route("/sitemap.xml", get(sitemap))
        .route("/upload", axum::routing::post(multipart_upload))
        .route("/d/{token}", get(decrypt_page))
        .route("/v/{token}", get(viewer))
        .route("/{name}", get(download).put(raw_upload))
        .fallback(not_found);
    let router = if media_mode.enabled() {
        let router = router
            .route("/share", get(share_page))
            .route("/watch/{token}", get(watch_page))
            .route("/api/live", post(create_live_share));
        if media_mode.is_direct() {
            router.route("/api/live/{token}/signal", any(live_signal))
        } else {
            router.route(
                "/api/live/{token}/forward",
                post(forward_signal).delete(stop_forward_share),
            )
        }
    } else {
        router
    };
    router
        .with_state(state)
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(RequestBodyLimitLayer::new(body_limit))
        // The timeout is per body frame, so active large uploads can continue.
        .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(30)))
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn_with_state(policy, request_policy))
}

pub fn http_router(challenges: Challenges, base_url: String, log_requests: bool) -> Router {
    let state = HttpState {
        challenges,
        base_url,
    };
    let policy = RequestPolicy {
        log_requests,
        hsts: false,
    };
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(acme_challenge))
        .route("/.well-known/{*rest}", any(not_found))
        .fallback(any(http_redirect))
        .with_state(state)
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn_with_state(policy, request_policy))
}

async fn request_policy(
    State(policy): State<RequestPolicy>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = Instant::now();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if !headers.contains_key(CONTENT_SECURITY_POLICY) {
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
            ),
        );
    }
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static(
            "camera=(), microphone=(self), geolocation=(), display-capture=(self)",
        ),
    );
    if policy.hsts {
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    if policy.log_requests {
        tracing::info!(%method, %path, status = response.status().as_u16(), elapsed_ms = started.elapsed().as_millis(), "HTTP request");
    }
    response
}

async fn index(State(state): State<AppState>) -> Response {
    html_response(index_html(state.media_mode.enabled()))
}

async fn share_page(State(state): State<AppState>) -> Response {
    html_response(share_page_html(state.media_mode, &state.ice_servers))
}

async fn watch_page(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    if !is_valid_token(&token) || !state.live.contains(&token).await {
        return not_found().await;
    }
    html_response(watch_page_html(
        &token,
        state.media_mode,
        &state.ice_servers,
    ))
}

async fn create_live_share(State(state): State<AppState>, request: Request) -> Response {
    if !browser_origin_allowed(request.headers(), &state.base_url) {
        return body_response(StatusCode::FORBIDDEN, "text/plain", "Forbidden\n");
    }
    let Some(session) = state.live.create_session().await else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok":false,"error":"Live sharing capacity is full"}),
        );
    };
    let watch_url = format!("{}/watch/{}", state.base_url, session.id);
    tracing::info!(session = %session.id, "live screen share created");
    json_response(
        StatusCode::CREATED,
        json!({
            "ok": true,
            "id": session.id,
            "host_key": session.host_key,
            "watch_url": watch_url,
            "mode": state.media_mode,
        }),
    )
}

async fn live_signal(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(query): Query<SignalQuery>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !state.media_mode.is_direct() {
        return not_found().await;
    }
    if !browser_origin_allowed(&headers, &state.base_url) {
        return body_response(StatusCode::FORBIDDEN, "text/plain", "Forbidden\n");
    }
    if !is_valid_token(&token) || !state.live.contains(&token).await {
        return not_found().await;
    }
    upgrade
        .max_message_size(MAX_SIGNAL_BYTES)
        .max_frame_size(MAX_SIGNAL_BYTES)
        .on_upgrade(move |socket| state.live.handle_socket(socket, token, query.role))
}

async fn forward_signal(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(query): Query<SignalQuery>,
    request: Request,
) -> Response {
    if state.media_mode != MediaMode::Forward
        || !browser_origin_allowed(request.headers(), &state.base_url)
        || !is_valid_token(&token)
        || !state.live.contains(&token).await
    {
        return not_found().await;
    }
    let host_key = request
        .headers()
        .get("x-share2me-host-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() == 64)
        .map(str::to_owned);
    let Ok(body) = to_bytes(request.into_body(), MAX_SDP_BYTES).await else {
        return json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"ok":false,"error":"WebRTC offer is too large"}),
        );
    };
    let Ok(offer) = serde_json::from_slice::<SdpOffer>(&body) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"ok":false,"error":"Invalid WebRTC offer"}),
        );
    };
    let connection_id = rand::random::<u128>();
    let role = match query.role {
        PeerRole::Host => {
            let Some(host_key) = host_key else {
                return body_response(StatusCode::FORBIDDEN, "text/plain", "Forbidden\n");
            };
            if !state
                .live
                .claim_forward_host(&token, &host_key, connection_id)
                .await
            {
                return body_response(StatusCode::FORBIDDEN, "text/plain", "Forbidden\n");
            }
            MediaRole::Publisher
        }
        PeerRole::Viewer => {
            if !state.live.claim_forward_viewer(&token, connection_id).await {
                return json_response(
                    StatusCode::CONFLICT,
                    json!({"ok":false,"error":"This live share is unavailable or full"}),
                );
            }
            MediaRole::Viewer
        }
    };
    let Some(forwarder) = &state.forwarder else {
        state
            .live
            .release_forward_peer(&token, role, connection_id)
            .await;
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok":false,"error":"Media forwarding is unavailable"}),
        );
    };
    match forwarder
        .join(token.clone(), role, connection_id, offer)
        .await
    {
        Ok(answer) => json_response(StatusCode::OK, json!(answer)),
        Err(error) => {
            state
                .live
                .release_forward_peer(&token, role, connection_id)
                .await;
            forward_error_response(&error)
        }
    }
}

async fn stop_forward_share(
    State(state): State<AppState>,
    Path(token): Path<String>,
    request: Request,
) -> Response {
    if state.media_mode != MediaMode::Forward
        || !browser_origin_allowed(request.headers(), &state.base_url)
        || !is_valid_token(&token)
    {
        return not_found().await;
    }
    let Some(host_key) = request
        .headers()
        .get("x-share2me-host-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() == 64)
    else {
        return body_response(StatusCode::FORBIDDEN, "text/plain", "Forbidden\n");
    };
    if !state.live.stop_forward_session(&token, host_key).await {
        return body_response(StatusCode::FORBIDDEN, "text/plain", "Forbidden\n");
    }
    if let Some(forwarder) = &state.forwarder
        && let Err(error) = forwarder.stop(token).await
    {
        return forward_error_response(&error);
    }
    StatusCode::NO_CONTENT.into_response()
}

fn forward_error_response(error: &ForwardJoinError) -> Response {
    let status = match error {
        ForwardJoinError::Busy => StatusCode::SERVICE_UNAVAILABLE,
        ForwardJoinError::Unavailable => StatusCode::CONFLICT,
        ForwardJoinError::InvalidOffer(_) => StatusCode::BAD_REQUEST,
        ForwardJoinError::Timeout => StatusCode::GATEWAY_TIMEOUT,
    };
    json_response(status, json!({"ok":false,"error":error.to_string()}))
}

async fn health() -> Response {
    body_response(StatusCode::OK, "text/plain; charset=utf-8", "OK")
}

async fn robots(State(state): State<AppState>) -> Response {
    body_response(
        StatusCode::OK,
        "text/plain; charset=utf-8",
        format!(
            "User-agent: *\nDisallow: /\nAllow: /$\nSitemap: {}/sitemap.xml\n",
            state.base_url
        ),
    )
}

async fn sitemap(State(state): State<AppState>) -> Response {
    body_response(
        StatusCode::OK,
        "application/xml; charset=utf-8",
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>{}/</loc><changefreq>monthly</changefreq><priority>1.0</priority></url></urlset>\n",
            state.base_url
        ),
    )
}

async fn acme_challenge(State(state): State<HttpState>, Path(token): Path<String>) -> Response {
    if token.is_empty()
        || token.len() > 256
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return not_found().await;
    }
    let challenges = state.challenges.read().await;
    match challenges.get(&token) {
        Some(value) => body_response(StatusCode::OK, "text/plain", value.clone()),
        None => not_found().await,
    }
}

async fn http_redirect(State(state): State<HttpState>, uri: Uri) -> Response {
    let suffix = uri
        .path_and_query()
        .map_or("/", axum::http::uri::PathAndQuery::as_str);
    let location = format!("{}{suffix}", state.base_url);
    let Ok(location) = HeaderValue::from_str(&location) else {
        return body_response(StatusCode::BAD_REQUEST, "text/plain", "Bad request\n");
    };
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::MOVED_PERMANENTLY;
    response.headers_mut().insert(LOCATION, location);
    response
}

#[allow(clippy::too_many_lines)]
async fn multipart_upload(State(state): State<AppState>, request: Request) -> Response {
    if !origin_allowed(request.headers(), &state.base_url) {
        return body_response(StatusCode::FORBIDDEN, "text/plain", "Forbidden\n");
    }
    let Ok(_permit) = state.upload_slots.clone().try_acquire_owned() else {
        return busy_response();
    };
    let mut multipart = match Multipart::from_request(request, &state).await {
        Ok(multipart) => multipart,
        Err(error) => {
            tracing::warn!(%error, "invalid multipart upload");
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"ok": false, "error": "Invalid multipart upload"}),
            );
        }
    };

    let mut pending = None;
    let mut filename = None;
    let mut content_type = None;
    let mut single_download = false;
    let mut expire_seconds = None;
    let mut encrypted = false;

    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(%error, "failed while reading multipart upload");
                return json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"ok": false, "error": "Invalid multipart upload"}),
                );
            }
        };
        let field_name = field.name().unwrap_or_default().to_owned();
        if field_name == "file" {
            if pending.is_some() {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"ok": false, "error": "Only one file may be uploaded"}),
                );
            }
            let candidate = field.file_name().unwrap_or_default().to_owned();
            if !is_safe_filename(&candidate) {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"ok": false, "error": "Invalid filename"}),
                );
            }
            content_type = field.content_type().map(ToString::to_string);
            filename = Some(candidate);
            let mut upload = match state.store.begin_upload() {
                Ok(upload) => upload,
                Err(error) => return upload_error(error),
            };
            loop {
                match field.chunk().await {
                    Ok(Some(chunk)) => {
                        if let Err(error) = upload.write_chunk(&chunk).await {
                            return upload_error(error);
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        tracing::warn!(%error, "failed while reading uploaded file");
                        return json_response(
                            StatusCode::BAD_REQUEST,
                            json!({"ok": false, "error": "Invalid multipart upload"}),
                        );
                    }
                }
            }
            pending = Some(upload);
        } else {
            let mut value = Vec::new();
            loop {
                match field.chunk().await {
                    Ok(Some(chunk)) if value.len() + chunk.len() <= 64 => {
                        value.extend_from_slice(&chunk);
                    }
                    Ok(Some(_)) => {
                        return json_response(
                            StatusCode::BAD_REQUEST,
                            json!({"ok": false, "error": "Invalid form field"}),
                        );
                    }
                    Ok(None) => break,
                    Err(_) => {
                        return json_response(
                            StatusCode::BAD_REQUEST,
                            json!({"ok": false, "error": "Invalid multipart upload"}),
                        );
                    }
                }
            }
            let value = String::from_utf8_lossy(&value);
            match field_name.as_str() {
                "single_download" => single_download = value == "1",
                "expire_after" => expire_seconds = parse_expiry(&value),
                "encrypted" => encrypted = value == "1",
                _ => {}
            }
        }
    }

    let (Some(upload), Some(filename)) = (pending, filename) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"ok": false, "error": "No file provided"}),
        );
    };
    let content_type = normalize_content_type(content_type.as_deref(), &filename);
    let result = match upload
        .commit(
            filename.clone(),
            single_download,
            expire_seconds,
            encrypted,
            content_type.clone(),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return upload_error(error),
    };
    tracing::info!(filename, token = %result.token, sha256 = %result.sha256, single_download, expire_seconds, encrypted, "multipart upload stored");
    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "hash": result.token,
            "content_type": content_type,
            "viewable": viewer_kind(&filename, false, &content_type).is_some(),
        }),
    )
}

async fn raw_upload(
    State(state): State<AppState>,
    Path(filename): Path<String>,
    uri: Uri,
    request: Request,
) -> Response {
    if !origin_allowed(request.headers(), &state.base_url) {
        return body_response(StatusCode::FORBIDDEN, "text/plain", "Forbidden\n");
    }
    if !is_safe_filename(&filename) {
        return body_response(StatusCode::BAD_REQUEST, "text/plain", "Invalid filename\n");
    }
    let Ok(_permit) = state.upload_slots.clone().try_acquire_owned() else {
        return busy_response();
    };
    let single_download = query_has(uri.query(), "single")
        || query_value(uri.query(), "single_download").is_some_and(|value| value == "1");
    let expire_seconds = query_value(uri.query(), "expire").and_then(parse_expiry);
    let content_type = normalize_content_type(
        request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        &filename,
    );

    let mut upload = match state.store.begin_upload() {
        Ok(upload) => upload,
        Err(error) => return upload_error_text(error),
    };
    let mut stream = request.into_body().into_data_stream();
    while let Some(frame) = stream.next().await {
        match frame {
            Ok(bytes) => {
                if let Err(error) = upload.write_chunk(&bytes).await {
                    return upload_error_text(error);
                }
            }
            Err(error) => {
                tracing::warn!(%error, "failed while reading raw upload");
                return body_response(
                    StatusCode::BAD_REQUEST,
                    "text/plain",
                    "Invalid request body\n",
                );
            }
        }
    }
    let result = match upload
        .commit(
            filename.clone(),
            single_download,
            expire_seconds,
            false,
            content_type,
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return upload_error_text(error),
    };
    tracing::info!(filename, token = %result.token, sha256 = %result.sha256, single_download, expire_seconds, "raw upload stored");
    body_response(
        StatusCode::CREATED,
        "text/plain; charset=utf-8",
        format!("{}/{}\n", state.base_url, result.token),
    )
}

async fn decrypt_page(Path(token): Path<String>) -> Response {
    if !is_valid_token(&token) {
        return not_found().await;
    }
    html_response(decrypt_page_html())
}

async fn viewer(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    if !is_valid_token(&token) {
        return not_found().await;
    }
    let Ok(metadata) = state.store.load_metadata(&token).await else {
        return not_found().await;
    };
    match state.store.remove_if_expired(&metadata).await {
        Ok(true) | Err(_) => return not_found().await,
        Ok(false) => {}
    }
    let Some(kind) = viewer_kind(
        &metadata.filename,
        metadata.encrypted,
        &metadata.content_type,
    ) else {
        if metadata.encrypted {
            return redirect_response(&format!("/d/{token}"), StatusCode::FOUND);
        }
        return not_found().await;
    };
    html_response(viewer_html(
        &token,
        &metadata.filename,
        metadata.single_download,
        metadata.encrypted,
        kind,
        &state.base_url,
    ))
}

async fn download(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    if !is_valid_token(&token) {
        return not_found().await;
    }
    let Ok(metadata) = state.store.load_metadata(&token).await else {
        return not_found().await;
    };
    match state.store.remove_if_expired(&metadata).await {
        Ok(true) | Err(_) => return not_found().await,
        Ok(false) => {}
    }

    let _claim = if metadata.single_download {
        match DownloadClaim::new(state.claims.clone(), &token) {
            Some(claim) => Some(claim),
            None => return not_found().await,
        }
    } else {
        None
    };
    let opened = match state.store.open_verified(&metadata).await {
        Ok(opened) => opened,
        Err(StorageError::Integrity) => {
            tracing::error!(%token, "download blocked by integrity failure");
            return body_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                "Internal server error",
            );
        }
        Err(_) => return not_found().await,
    };
    if metadata.single_download {
        if let Err(error) = state.store.remove(&metadata).await {
            tracing::error!(%error, %token, "failed to consume single-download file");
            return body_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                "Internal server error",
            );
        }
        tracing::info!(%token, "single-download file consumed");
    }

    tracing::info!(filename = %metadata.filename, %token, sha256 = %metadata.hash, "file downloaded");
    let file = tokio::fs::File::from_std(opened.file);
    let stream = ReaderStream::new(file);
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&mime_for(&metadata.filename))
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    if let Ok(value) = HeaderValue::from_str(&content_disposition(&metadata.filename)) {
        response.headers_mut().insert(CONTENT_DISPOSITION, value);
    }
    if let Ok(value) = HeaderValue::from_str(&opened.size.to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }
    response
}

async fn not_found() -> Response {
    body_response(StatusCode::NOT_FOUND, "text/plain", "Not found")
}

fn body_response(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<Body>,
) -> Response {
    let mut response = Response::new(body.into());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn html_response(body: impl AsRef<str>) -> Response {
    let nonce = format!("{:032x}", rand::random::<u128>());
    let body = body
        .as_ref()
        .replace("<script>", &format!("<script nonce=\"{nonce}\">"));
    let mut response = body_response(StatusCode::OK, "text/html; charset=utf-8", body);
    let policy = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    );
    if let Ok(policy) = HeaderValue::from_str(&policy) {
        response
            .headers_mut()
            .insert(CONTENT_SECURITY_POLICY, policy);
    }
    response
}

#[allow(clippy::needless_pass_by_value)]
fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    body_response(status, "application/json", value.to_string())
}

fn redirect_response(location: &str, status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    if let Ok(location) = HeaderValue::from_str(location) {
        response.headers_mut().insert(LOCATION, location);
    }
    response
}

fn busy_response() -> Response {
    let mut response = body_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "text/plain",
        "Upload capacity is busy; retry shortly\n",
    );
    response
        .headers_mut()
        .insert("retry-after", HeaderValue::from_static("2"));
    response
}

fn upload_error(error: StorageError) -> Response {
    let (status, message) = match error {
        StorageError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "File too large"),
        StorageError::EmptyUpload => (StatusCode::BAD_REQUEST, "No file provided"),
        StorageError::InvalidFilename => (StatusCode::BAD_REQUEST, "Invalid filename"),
        error => {
            tracing::error!(%error, "upload storage failure");
            (StatusCode::INTERNAL_SERVER_ERROR, "Upload failed")
        }
    };
    json_response(status, json!({"ok": false, "error": message}))
}

fn upload_error_text(error: StorageError) -> Response {
    let (status, message) = match error {
        StorageError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "File too large\n"),
        StorageError::EmptyUpload => (StatusCode::BAD_REQUEST, "Empty body\n"),
        StorageError::InvalidFilename => (StatusCode::BAD_REQUEST, "Invalid filename\n"),
        error => {
            tracing::error!(%error, "upload storage failure");
            (StatusCode::INTERNAL_SERVER_ERROR, "Upload failed\n")
        }
    };
    body_response(status, "text/plain", message)
}

fn origin_allowed(headers: &HeaderMap, base_url: &str) -> bool {
    let Some(origin) = headers.get("origin") else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    origin == base_url
}

fn browser_origin_allowed(headers: &HeaderMap, base_url: &str) -> bool {
    headers.contains_key("origin") && origin_allowed(headers, base_url)
}

fn parse_expiry(value: &str) -> Option<u64> {
    if value.len() < 2 || value.len() > 12 {
        return None;
    }
    let (number, unit) = value.split_at(value.len() - 1);
    if number.len() > 10 || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number = number.parse::<u64>().ok()?;
    let multiplier = match unit {
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        "y" => 31_536_000,
        _ => return None,
    };
    let seconds = number.checked_mul(multiplier)?;
    (seconds > 0 && seconds <= MAX_EXPIRY_SECONDS).then_some(seconds)
}

fn query_has(query: Option<&str>, name: &str) -> bool {
    query.is_some_and(|query| {
        query.split('&').any(|part| {
            let key = part.split_once('=').map_or(part, |(key, _)| key);
            key == name
        })
    })
}

fn query_value<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query?.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == name).then_some(value)
    })
}

fn normalize_content_type(value: Option<&str>, filename: &str) -> String {
    value
        .filter(|value| !value.is_empty() && value.len() <= 127)
        .and_then(|value| value.parse::<mime::Mime>().ok())
        .map_or_else(
            || mime_for(filename),
            |value| value.essence_str().to_owned(),
        )
}

fn mime_for(filename: &str) -> String {
    mime_guess::from_path(filename)
        .first_or_octet_stream()
        .essence_str()
        .to_owned()
}

fn viewer_kind(filename: &str, encrypted: bool, content_type: &str) -> Option<ViewerKind> {
    let extension = filename
        .rsplit_once('.')
        .map_or_else(String::new, |(_, extension)| extension.to_ascii_lowercase());
    if encrypted {
        if IMAGE_EXTENSIONS.contains(&extension.as_str()) {
            return Some(ViewerKind::Image);
        }
        return ENCRYPTED_TEXT_EXTENSIONS
            .contains(&extension.as_str())
            .then_some(ViewerKind::Text);
    }
    if matches!(extension.as_str(), "js" | "mjs" | "xml") {
        return None;
    }
    if content_type.starts_with("image/") {
        return Some(ViewerKind::Image);
    }
    (content_type.starts_with("text/") || content_type == "application/json")
        .then_some(ViewerKind::Text)
}

fn content_disposition(filename: &str) -> String {
    let mut fallback = filename
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, ' ' | '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if fallback.is_empty() {
        fallback.push_str("download");
    }
    let encoded = utf8_percent_encode(filename, NON_ALPHANUMERIC);
    format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
}

struct DownloadClaim {
    claims: Arc<Mutex<HashSet<String>>>,
    token: String,
}

impl DownloadClaim {
    fn new(claims: Arc<Mutex<HashSet<String>>>, token: &str) -> Option<Self> {
        let inserted = claims
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(token.to_owned());
        inserted.then(|| Self {
            claims,
            token: token.to_owned(),
        })
    }
}

impl Drop for DownloadClaim {
    fn drop(&mut self) {
        self.claims
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.token);
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, http::Request};
    use tempfile::tempdir;
    use tower::ServiceExt;

    use super::*;

    #[test]
    fn parses_only_bounded_expiry_values() {
        assert_eq!(parse_expiry("2h"), Some(7200));
        assert_eq!(parse_expiry("100y"), Some(MAX_EXPIRY_SECONDS));
        assert_eq!(parse_expiry("101y"), None);
        assert_eq!(parse_expiry("99999999999d"), None);
        assert_eq!(parse_expiry("0m"), None);
    }

    #[test]
    fn content_disposition_cannot_inject_headers() {
        let value = content_disposition("résumé.txt");
        assert!(HeaderValue::from_str(&value).is_ok());
        assert!(value.contains("filename*=UTF-8''"));
        assert!(!value.contains('\r'));
        assert!(!value.contains('\n'));
    }

    #[test]
    fn executable_text_is_not_viewed_inline() {
        assert_eq!(
            viewer_kind("payload.js", false, "application/javascript"),
            None
        );
        assert_eq!(
            viewer_kind("notes.txt", false, "text/plain"),
            Some(ViewerKind::Text)
        );
        assert_eq!(
            viewer_kind("photo.png", false, "image/png"),
            Some(ViewerKind::Image)
        );
        assert_eq!(
            viewer_kind("README", false, "text/plain"),
            Some(ViewerKind::Text)
        );
    }

    #[test]
    fn uploads_only_accept_the_configured_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("https://evil.example"));
        headers.insert("host", HeaderValue::from_static("evil.example"));
        assert!(!origin_allowed(&headers, "https://files.example"));
        headers.insert("origin", HeaderValue::from_static("https://files.example"));
        assert!(origin_allowed(&headers, "https://files.example"));
        assert!(browser_origin_allowed(&headers, "https://files.example"));
        headers.remove("origin");
        assert!(origin_allowed(&headers, "https://files.example"));
        assert!(!browser_origin_allowed(&headers, "https://files.example"));
    }

    #[tokio::test]
    async fn live_share_creation_returns_separate_host_and_viewer_secrets() {
        let directory = tempdir().unwrap();
        let store = FileStore::new(directory.path().to_path_buf()).unwrap();
        let app = https_router(
            AppState::new(
                store,
                "https://localhost:8443".to_owned(),
                LiveHub::default(),
                MediaMode::Stun,
                Vec::new(),
                None,
            ),
            false,
            "localhost",
        );
        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/live")
                    .header("origin", "https://localhost:8443")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let payload: serde_json::Value =
            serde_json::from_slice(&to_bytes(created.into_body(), 4096).await.unwrap()).unwrap();
        let id = payload["id"].as_str().unwrap();
        let host_key = payload["host_key"].as_str().unwrap();
        let watch_url = payload["watch_url"].as_str().unwrap();
        assert!(is_valid_token(id));
        assert_eq!(host_key.len(), 64);
        assert!(!watch_url.contains(host_key));

        let watch = app
            .oneshot(
                Request::builder()
                    .uri(format!("/watch/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(watch.status(), StatusCode::OK);
        let body = to_bytes(watch.into_body(), 256 * 1024).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("RTCPeerConnection"));
    }

    #[tokio::test]
    async fn disabled_mode_removes_live_routes_and_home_action() {
        let directory = tempdir().unwrap();
        let store = FileStore::new(directory.path().to_path_buf()).unwrap();
        let app = https_router(
            AppState::new(
                store,
                "https://localhost:8443".to_owned(),
                LiveHub::default(),
                MediaMode::Disabled,
                Vec::new(),
                None,
            ),
            false,
            "localhost",
        );
        let home = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            home.headers()
                .get("permissions-policy")
                .and_then(|value| value.to_str().ok()),
            Some("camera=(), microphone=(self), geolocation=(), display-capture=(self)")
        );
        let body = to_bytes(home.into_body(), 256 * 1024).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("href=\"/share\""));
        let share = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/share")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(share.status(), StatusCode::NOT_FOUND);
        let create = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/live")
                    .header("origin", "https://localhost:8443")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn forwarding_route_validates_and_authenticates_publisher_offers() {
        let directory = tempdir().unwrap();
        let store = FileStore::new(directory.path().to_path_buf()).unwrap();
        let live = LiveHub::default();
        let session = live.create_session().await.unwrap();
        let app = https_router(
            AppState::new(
                store,
                "https://localhost:8443".to_owned(),
                live,
                MediaMode::Forward,
                Vec::new(),
                None,
            ),
            false,
            "localhost",
        );
        let crypto = Arc::new(str0m::crypto::from_feature_flags());
        let mut rtc = str0m::Rtc::builder()
            .set_crypto_provider(crypto)
            .build(std::time::Instant::now());
        let mut changes = rtc.sdp_api();
        changes.add_channel("share2me-control".to_owned());
        changes.add_media(
            str0m::media::MediaKind::Video,
            str0m::media::Direction::SendOnly,
            Some("screen".to_owned()),
            None,
            None,
        );
        let offer = changes.apply().unwrap().0;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/live/{}/forward?role=host", session.id))
                    .header("origin", "https://localhost:8443")
                    .header("content-type", "application/json")
                    .header("x-share2me-host-key", &session.host_key)
                    .body(Body::from(serde_json::to_vec(&offer).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let missing = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/live/{}/forward?role=host", session.id))
                    .header("origin", "https://localhost:8443")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&offer).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn raw_upload_round_trips_through_the_router() {
        let directory = tempdir().unwrap();
        let store = FileStore::new(directory.path().to_path_buf()).unwrap();
        let app = https_router(
            AppState::new(
                store,
                "https://localhost:8443".to_owned(),
                LiveHub::default(),
                MediaMode::Disabled,
                Vec::new(),
                None,
            ),
            false,
            "localhost",
        );
        let upload = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/notes.txt?expire=2h")
                    .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Body::from("hello from rust"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(upload.status(), StatusCode::CREATED);
        let link =
            String::from_utf8(to_bytes(upload.into_body(), 1024).await.unwrap().to_vec()).unwrap();
        let token = link.trim().rsplit('/').next().unwrap();
        assert!(is_valid_token(token));

        let download = app
            .oneshot(
                Request::builder()
                    .uri(format!("/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(download.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(download.into_body(), 1024).await.unwrap(),
            "hello from rust"
        );
    }

    #[tokio::test]
    async fn single_use_link_is_consumed_before_a_second_request() {
        let directory = tempdir().unwrap();
        let store = FileStore::new(directory.path().to_path_buf()).unwrap();
        let app = https_router(
            AppState::new(
                store,
                "https://localhost:8443".to_owned(),
                LiveHub::default(),
                MediaMode::Disabled,
                Vec::new(),
                None,
            ),
            false,
            "localhost",
        );
        let upload = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/once.txt?single")
                    .body(Body::from("once"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let link =
            String::from_utf8(to_bytes(upload.into_body(), 1024).await.unwrap().to_vec()).unwrap();
        let path = format!("/{}", link.trim().rsplit('/').next().unwrap());

        let first = app
            .clone()
            .oneshot(Request::builder().uri(&path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(to_bytes(first.into_body(), 1024).await.unwrap(), "once");

        let second = app
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn http_router_serves_acme_challenges_without_redirecting() {
        let challenges: Challenges = Arc::default();
        challenges.write().await.insert(
            "challenge_token".to_owned(),
            "challenge_token.key_authorization".to_owned(),
        );
        let app = http_router(challenges, "https://localhost:8443".to_owned(), false);

        let challenge = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/acme-challenge/challenge_token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(challenge.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(challenge.into_body(), 1024).await.unwrap(),
            "challenge_token.key_authorization"
        );

        let redirect = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(redirect.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            redirect.headers().get(LOCATION).unwrap(),
            "https://localhost:8443/healthz"
        );
    }
}
