//! Relay jitter middleware — timing decorrelation for privacy.
//!
//! Inspired by ZASEON's metadata resistance principles: adds a random delay
//! to state-mutating RPC responses so that observers cannot correlate request
//! timing with transaction processing. Read-only endpoints (GET) are exempt.
//!
//! The delay is drawn uniformly from `[min_jitter, max_jitter]` using the
//! OS random number generator and applied via `tokio::time::sleep`.

use std::time::Duration;

use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use rand::Rng;

/// Configuration for relay jitter.
#[derive(Clone, Debug)]
pub struct JitterConfig {
    /// Minimum jitter delay.
    pub min: Duration,
    /// Maximum jitter delay.
    pub max: Duration,
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl JitterConfig {
    /// Create a jitter config with the given range in milliseconds.
    pub fn from_millis(min_ms: u64, max_ms: u64) -> Self {
        let (min_ms, max_ms) = if min_ms > max_ms { (max_ms, min_ms) } else { (min_ms, max_ms) };
        Self {
            min: Duration::from_millis(min_ms),
            max: Duration::from_millis(max_ms),
        }
    }

    /// Read jitter configuration from environment variables, falling back
    /// to defaults (50–500ms).
    ///
    /// - `LUMORA_JITTER_MIN_MS` — minimum jitter in milliseconds
    /// - `LUMORA_JITTER_MAX_MS` — maximum jitter in milliseconds
    pub fn from_env() -> Self {
        let min_ms: u64 = std::env::var("LUMORA_JITTER_MIN_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let max_ms: u64 = std::env::var("LUMORA_JITTER_MAX_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500);
        Self::from_millis(min_ms, max_ms)
    }
}

/// Axum middleware that adds random jitter to state-mutating responses.
///
/// GET requests (status, fees, health) are not delayed. POST, PUT, PATCH, and
/// DELETE requests receive jitter to decorrelate response timing.
pub async fn jitter_middleware(
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let is_write = method == axum::http::Method::POST
        || method == axum::http::Method::PUT
        || method == axum::http::Method::PATCH
        || method == axum::http::Method::DELETE;
    let response = next.run(req).await;

    if is_write {
        // Apply random jitter from the default configuration.
        // In production this would read from a shared config, but the default
        // range (50-500ms) provides meaningful timing decorrelation.
        let config = JitterConfig::default();
        let delay_us = rand::thread_rng().gen_range(config.min.as_micros()..=config.max.as_micros());
        tokio::time::sleep(Duration::from_micros(delay_us as u64)).await;
    }

    response
}
