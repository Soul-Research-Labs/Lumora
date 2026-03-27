//! State sync RPC handlers.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use lumora_node::sync::SyncStatus;

use crate::handlers::AppState;
use crate::types::ErrorResp;

/// GET /sync/status — return current node sync status.
pub async fn sync_status(State(state): State<AppState>) -> Json<SyncStatus> {
    let mut node = state.write().await;
    let root = node.current_root();
    Json(SyncStatus {
        height: node.commitment_count(),
        root,
        nullifier_count: node.pool.state.nullifier_count(),
        pool_balance: node.pool_balance(),
    })
}

/// Request to fetch events from a given height.
#[derive(serde::Deserialize)]
pub struct SyncEventsReq {
    /// Fetch events starting from this commitment index.
    pub from_height: u64,
}

/// POST /sync/events — return events from `from_height` to current.
pub async fn sync_events(
    State(state): State<AppState>,
    Json(req): Json<SyncEventsReq>,
) -> Result<Json<lumora_node::sync::StateDelta>, (StatusCode, Json<ErrorResp>)> {
    let node = state.read().await;
    let all_events = node.pool.state.events();

    // Filter events that correspond to heights >= from_height.
    // Events are recorded in order; we approximate by skipping the first
    // `from_height` events (each deposit/transfer/withdraw increments height).
    let from = req.from_height as usize;
    const MAX_SYNC_EVENTS: usize = 1000;
    let events = if from < all_events.len() {
        let end = (from + MAX_SYNC_EVENTS).min(all_events.len());
        all_events[from..end].to_vec()
    } else {
        vec![]
    };

    Ok(Json(lumora_node::sync::StateDelta {
        from_height: req.from_height,
        events,
    }))
}
