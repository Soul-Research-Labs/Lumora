//! Axum server setup and routing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::http::{header, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tower_http::cors::CorsLayer;

use lumora_node::LumoraNode;

use crate::handlers;
use crate::handlers::AppState;
use crate::jitter;
use crate::sync_handlers;

/// Default listen address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:3030";

/// Environment variable for optional API key authentication.
/// If set, all requests (except /health) must include `X-API-Key: <value>`.
const API_KEY_ENV: &str = "LUMORA_API_KEY";

/// Environment variable for optional CORS allowed origins.
/// Comma-separated list, e.g. `https://app.lumora.io,http://localhost:5173`.
/// If unset, no CORS headers are added (suitable for reverse-proxy deployments).
const CORS_ORIGINS_ENV: &str = "LUMORA_CORS_ORIGINS";

/// Maximum request body size: 2 MB.
const MAX_BODY_SIZE: usize = 2 * 1024 * 1024;

/// Maximum concurrent requests the server will handle before shedding load.
const MAX_CONCURRENT_REQUESTS: usize = 128;

/// Maximum requests per IP per window before rate-limiting kicks in.
const RATE_LIMIT_PER_IP: u32 = 60;

/// Rate-limit window duration.
const RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// Per-IP request counter with a sliding window.
struct IpBucket {
    count: u32,
    window_start: Instant,
}

/// Shared per-IP rate limiter.
#[derive(Clone)]
struct IpRateLimiter {
    buckets: Arc<Mutex<HashMap<IpAddr, IpBucket>>>,
}

impl IpRateLimiter {
    fn new() -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns `true` if the request is allowed, `false` if rate-limited.
    async fn check(&self, ip: IpAddr) -> bool {
        let mut map = self.buckets.lock().await;
        let now = Instant::now();
        let bucket = map.entry(ip).or_insert(IpBucket {
            count: 0,
            window_start: now,
        });
        if now.duration_since(bucket.window_start) >= RATE_LIMIT_WINDOW {
            bucket.count = 0;
            bucket.window_start = now;
        }
        bucket.count += 1;
        let allowed = bucket.count <= RATE_LIMIT_PER_IP;
        if map.len() > 10_000 {
            let cutoff = RATE_LIMIT_WINDOW * 2;
            map.retain(|_, b| now.duration_since(b.window_start) < cutoff);
        }
        allowed
    }
}

/// Build the axum router with all RPC endpoints.
pub fn router(node: LumoraNode) -> Router {
    let state: AppState = Arc::new(RwLock::new(node));
    router_with_state(state)
}

/// Build the router from an existing shared state.
///
/// Used by `serve()` so that background tasks and the HTTP server share the
/// same `Arc<RwLock<LumoraNode>>`.
fn router_with_state(state: AppState) -> Router {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
    let rate_limiter = IpRateLimiter::new();
    let api_key: Option<Arc<Zeroizing<String>>> = std::env::var(API_KEY_ENV)
        .ok()
        .filter(|k| !k.is_empty())
        .map(|k| Arc::new(Zeroizing::new(k)));

    // Install Prometheus metrics recorder.
    let prom_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus recorder");

    if api_key.is_some() {
        tracing::info!("API key authentication enabled (via {API_KEY_ENV})");
    }

    // Versioned API routes — all endpoints under /v1/.
    let v1 = Router::new()
        // Write operations
        .route("/deposit", post(handlers::deposit))
        .route("/transfer", post(handlers::transfer))
        .route("/withdraw", post(handlers::withdraw))
        .route("/relay-note", post(handlers::relay_note))
        // Read operations
        .route("/status", get(handlers::status))
        .route("/nullifier", post(handlers::nullifier_check))
        .route("/notes", post(handlers::get_notes))
        .route("/fees", get(handlers::fee_estimate))
        .route("/history", post(handlers::history))
        .route("/batch-verify", post(handlers::batch_verify))
        .route("/epoch-roots", get(handlers::epoch_roots))
        .route("/stealth-scan", post(handlers::stealth_scan))
        // Sync operations
        .route("/sync/status", get(sync_handlers::sync_status))
        .route("/sync/events", post(sync_handlers::sync_events))
        // BitVM bridge operations
        .route("/bitvm/status", get(handlers::bitvm_status))
        .route("/bitvm/poll", post(handlers::bitvm_poll_deposits))
        .route("/bitvm/commit-root", post(handlers::bitvm_commit_root));

    Router::new()
        .nest("/v1", v1.clone())
        // Backward-compatible unversioned routes.
        .merge(v1)
        // Health (unversioned — always at root).
        .route("/health", get(health))
        // Prometheus metrics endpoint.
        .route("/metrics", get(move || metrics_handler(prom_handle.clone())))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(cors_layer())
        // Relay jitter: random delay on POST responses for timing decorrelation.
        .layer(middleware::from_fn(jitter::jitter_middleware))
        .layer(middleware::from_fn(move |req: Request<axum::body::Body>, next: middleware::Next| {
            let sem = semaphore.clone();
            let key = api_key.clone();
            let rl = rate_limiter.clone();
            async move {
                // Concurrency limit.
                let _permit = match sem.try_acquire() {
                    Ok(p) => p,
                    Err(_) => {
                        counter!("http_requests_rejected_total", "reason" => "overload").increment(1);
                        return Err(StatusCode::SERVICE_UNAVAILABLE);
                    }
                };

                // Per-IP rate limiting (skip for /health and /metrics).
                let path_for_rl = req.uri().path().to_owned();
                if path_for_rl != "/health" && path_for_rl != "/metrics" {
                    // Extract client IP: prefer X-Forwarded-For (first entry,
                    // must be a valid IP), then ConnectInfo socket addr, then
                    // a non-routable sentinel so that unauthenticated traffic
                    // still gets rate-limited rather than skipped.
                    let forwarded_ip: Option<IpAddr> = {
                        let trust_proxy = std::env::var("LUMORA_TRUST_PROXY").ok()
                            .map_or(false, |v| v == "true" || v == "1");
                        if trust_proxy {
                            req.headers()
                                .get("x-forwarded-for")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|s| s.split(',').next())
                                .and_then(|s| s.trim().parse().ok())
                        } else {
                            None
                        }
                    };
                    let socket_ip: Option<IpAddr> = req
                        .extensions()
                        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                        .map(|ci| ci.0.ip());
                    let ip = forwarded_ip
                        .or(socket_ip)
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
                    if !rl.check(ip).await {
                        counter!("http_requests_rejected_total", "reason" => "rate_limit").increment(1);
                        return Err(StatusCode::TOO_MANY_REQUESTS);
                    }
                }
                // API key check (skip for /health and /metrics).
                if let Some(expected) = &key {
                    let path = req.uri().path();
                    if path != "/health" && path != "/metrics" {
                        let provided = req
                            .headers()
                            .get("x-api-key")
                            .and_then(|v| v.to_str().ok());
                        match provided {
                            Some(v) if bool::from(v.as_bytes().ct_eq(expected.as_bytes())) => {}
                            _ => {
                                counter!("http_requests_rejected_total", "reason" => "auth").increment(1);
                                return Err(StatusCode::UNAUTHORIZED);
                            }
                        }
                    }
                }

                let method = req.method().clone();
                let path = req.uri().path().to_owned();
                let start = Instant::now();

                let response = next.run(req).await;

                let status = response.status().as_u16().to_string();
                let elapsed = start.elapsed().as_secs_f64();

                counter!("http_requests_total",
                    "method" => method.to_string(),
                    "path"   => path.clone(),
                    "status" => status.clone(),
                ).increment(1);
                histogram!("http_request_duration_seconds",
                    "method" => method.to_string(),
                    "path"   => path,
                    "status" => status,
                ).record(elapsed);

                Ok(response)
            }
        }))
}

/// Return scraped Prometheus metrics.
async fn metrics_handler(handle: PrometheusHandle) -> impl IntoResponse {
    handle.render()
}

/// Build a CORS layer from the `LUMORA_CORS_ORIGINS` environment variable.
///
/// If the variable is unset or empty, returns a permissive no-op layer
/// (no CORS headers). If set, parses comma-separated origins and allows
/// standard methods and headers.
fn cors_layer() -> CorsLayer {
    let origins_str = std::env::var(CORS_ORIGINS_ENV).unwrap_or_default();
    if origins_str.is_empty() {
        return CorsLayer::new();
    }

    let origins: Vec<HeaderValue> = origins_str
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            trimmed.parse().ok()
        })
        .collect();

    if origins.is_empty() {
        tracing::warn!("{CORS_ORIGINS_ENV} set but no valid origins parsed");
        return CorsLayer::new();
    }

    tracing::info!(
        origins = %origins_str,
        "CORS enabled for configured origins",
    );

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, HeaderName::from_static("x-api-key")])
}

/// Build a lightweight router for testing (no Prometheus, no API-key, no
/// concurrency limit).
#[doc(hidden)]
pub fn test_router(node: LumoraNode) -> Router {
    let state: AppState = Arc::new(RwLock::new(node));

    let v1 = Router::new()
        .route("/deposit", post(handlers::deposit))
        .route("/transfer", post(handlers::transfer))
        .route("/withdraw", post(handlers::withdraw))
        .route("/relay-note", post(handlers::relay_note))
        .route("/status", get(handlers::status))
        .route("/nullifier", post(handlers::nullifier_check))
        .route("/notes", post(handlers::get_notes))
        .route("/fees", get(handlers::fee_estimate))
        .route("/history", post(handlers::history))
        .route("/batch-verify", post(handlers::batch_verify))
        .route("/epoch-roots", get(handlers::epoch_roots))
        .route("/stealth-scan", post(handlers::stealth_scan))
        .route("/sync/status", get(sync_handlers::sync_status))
        .route("/sync/events", post(sync_handlers::sync_events));

    Router::new()
        .nest("/v1", v1.clone())
        .merge(v1)
        .route("/health", get(health))
        .with_state(state)
}

/// Liveness probe — returns structured JSON with vital pool metrics.
async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    use ff::PrimeField;
    static START_TIME: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
    let mut node = state.write().await;
    let root = node.current_root();
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": START_TIME.elapsed().as_secs(),
        "pool_balance": node.pool_balance(),
        "commitment_count": node.commitment_count(),
        "current_epoch": node.pool.state.epoch_manager().current_epoch(),
        "merkle_root": hex::encode(root.to_repr()),
    }))
}

/// Start the RPC server, blocking until shutdown.
///
/// Spawns background tasks (batch polling, epoch finalization) alongside
/// the HTTP server. Tasks are shut down gracefully on server exit.
pub async fn serve(node: LumoraNode, addr: &str) -> std::io::Result<()> {
    // Build shared state before constructing the router so background tasks
    // can share the same Arc<RwLock<LumoraNode>>.
    let state: crate::handlers::AppState = Arc::new(RwLock::new(node));

    // Spawn background tasks.
    let bg = crate::tasks::spawn_background_tasks(state.clone());
    tracing::info!(tasks = bg.len(), "background tasks started");

    let app = router_with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Lumora RPC server listening on {addr}");
    let result = axum::serve(listener, app)
        .await
        .map_err(std::io::Error::other);

    // Graceful shutdown of background tasks.
    bg.shutdown().await;

    result
}
