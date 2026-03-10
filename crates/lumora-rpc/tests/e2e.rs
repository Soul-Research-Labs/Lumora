//! End-to-end integration tests for the Lumora RPC server.
//!
//! These tests exercise multi-step flows through the full HTTP API surface:
//! deposit → status → history, relay → fetch → stealth-scan, etc.
//!
//! Uses a lazily-initialized shared router so SRS key generation only
//! happens once (~40s).

use std::sync::LazyLock;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

/// Shared router — built once, cloned per test.
static SHARED_ROUTER: LazyLock<Router> = LazyLock::new(|| {
    let node = lumora_node::LumoraNode::init();
    lumora_rpc::test_router(node)
});

fn app() -> Router {
    SHARED_ROUTER.clone()
}

fn post_json(uri: &str, body: &impl serde::Serialize) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    serde_json::from_slice(&bytes).unwrap()
}

fn zero_field_hex() -> String {
    use ff::PrimeField;
    hex::encode(pasta_curves::pallas::Base::zero().to_repr())
}

fn zero_bytes32_hex() -> String {
    hex::encode([0u8; 32])
}

// ── E2E: deposit → status reflects new balance ─────────────────────

#[tokio::test]
async fn deposit_updates_pool_balance() {
    let router = app();

    // Get initial balance.
    let resp = router.clone().oneshot(get("/v1/status")).await.unwrap();
    let before: serde_json::Value = body_json(resp).await;
    let balance_before = before["pool_balance"].as_u64().unwrap();

    // Deposit 1000.
    let deposit = serde_json::json!({
        "commitment": zero_field_hex(),
        "amount": 1000
    });
    let resp = router
        .clone()
        .oneshot(post_json("/v1/deposit", &deposit))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let dr = body_json(resp).await;
    assert!(dr["new_root"].is_string());

    // Balance should have increased.
    let resp = router.oneshot(get("/v1/status")).await.unwrap();
    let after = body_json(resp).await;
    let balance_after = after["pool_balance"].as_u64().unwrap();
    assert!(balance_after >= balance_before + 1000);
}

// ── E2E: deposit → history event recorded ──────────────────────────

#[tokio::test]
async fn deposit_creates_history_event() {
    let router = app();

    // Get history count before.
    let hist_req = serde_json::json!({"offset": 0, "limit": 10000});
    let resp = router
        .clone()
        .oneshot(post_json("/v1/history", &hist_req))
        .await
        .unwrap();
    let before = body_json(resp).await;
    let total_before = before["total"].as_u64().unwrap();

    // Deposit.
    let deposit = serde_json::json!({
        "commitment": zero_field_hex(),
        "amount": 500
    });
    let resp = router
        .clone()
        .oneshot(post_json("/v1/deposit", &deposit))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // History total should have increased.
    let resp = router
        .oneshot(post_json("/v1/history", &hist_req))
        .await
        .unwrap();
    let after = body_json(resp).await;
    let total_after = after["total"].as_u64().unwrap();
    assert!(total_after > total_before);
}

// ── E2E: relay note → fetch by tag → stealth scan ─────────────────

#[tokio::test]
async fn relay_fetch_stealth_scan_flow() {
    let router = app();

    let tag = hex::encode([0xEEu8; 32]);
    let commitment = zero_bytes32_hex();
    let ephemeral_pubkey = zero_bytes32_hex();
    let ciphertext = hex::encode(b"test_encrypted_data_for_e2e");

    // 1) Relay a note.
    let relay = serde_json::json!({
        "recipient_tag": tag,
        "leaf_index": 999,
        "commitment": commitment,
        "ciphertext": ciphertext,
        "ephemeral_pubkey": ephemeral_pubkey,
    });
    let resp = router
        .clone()
        .oneshot(post_json("/v1/relay-note", &relay))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 2) Fetch notes by tag.
    let fetch = serde_json::json!({"recipient_tag": tag});
    let resp = router
        .clone()
        .oneshot(post_json("/v1/notes", &fetch))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let notes = body_json(resp).await;
    let notes_arr = notes.as_array().unwrap();
    assert!(notes_arr.iter().any(|n| n["leaf_index"] == 999));

    // 3) Stealth scan should include the note.
    let scan = serde_json::json!({"from_leaf_index": 0, "limit": 5000});
    let resp = router
        .oneshot(post_json("/v1/stealth-scan", &scan))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let scan_resp = body_json(resp).await;
    let scan_notes = scan_resp["notes"].as_array().unwrap();
    assert!(scan_notes.iter().any(|n| n["leaf_index"] == 999));
}

// ── E2E: health → enriched JSON ────────────────────────────────────

#[tokio::test]
async fn health_returns_enriched_json() {
    let resp = app().oneshot(get("/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "ok");
    assert!(json["version"].is_string());
    assert!(json["uptime_secs"].is_number());
    assert!(json["pool_balance"].is_number());
    assert!(json["commitment_count"].is_number());
    assert!(json["current_epoch"].is_number());
    assert!(!json["merkle_root"].as_str().unwrap().is_empty());
}

// ── E2E: deposit → commitment count increases ──────────────────────

#[tokio::test]
async fn deposit_increments_commitment_count() {
    let router = app();

    let resp = router.clone().oneshot(get("/v1/status")).await.unwrap();
    let before = body_json(resp).await;
    let count_before = before["commitment_count"].as_u64().unwrap();

    let deposit = serde_json::json!({
        "commitment": zero_field_hex(),
        "amount": 1000
    });
    let resp = router
        .clone()
        .oneshot(post_json("/v1/deposit", &deposit))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = router.oneshot(get("/v1/status")).await.unwrap();
    let after = body_json(resp).await;
    let count_after = after["commitment_count"].as_u64().unwrap();
    assert!(count_after > count_before);
}

// ── E2E: fee estimate sanity ───────────────────────────────────────

#[tokio::test]
async fn fee_estimate_is_consistent() {
    let resp = app().oneshot(get("/v1/fees")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let fees = body_json(resp).await;
    assert!(fees["transfer_fee"].as_u64().unwrap() > 0);
    assert!(fees["withdraw_fee"].as_u64().unwrap() > 0);
    assert!(fees["min_deposit"].as_u64().unwrap() > 0);
    assert!(fees["min_withdraw"].as_u64().unwrap() > 0);
}

// ── E2E: epoch roots available on fresh node ───────────────────────

#[tokio::test]
async fn epoch_roots_available() {
    let resp = app().oneshot(get("/v1/epoch-roots")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["current_epoch"].is_number());
    assert!(json["roots"].is_array());
}

// ── E2E: sync/status returns OK ────────────────────────────────────

#[tokio::test]
async fn sync_status_returns_ok() {
    let resp = app().oneshot(get("/v1/sync/status")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── E2E: batch verify with empty proofs rejected ───────────────────

#[tokio::test]
async fn batch_verify_empty_rejected() {
    let req = serde_json::json!({"proofs": []});
    let resp = app()
        .oneshot(post_json("/v1/batch-verify", &req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── E2E: nullifier check returns false for unused ──────────────────

#[tokio::test]
async fn unused_nullifier_returns_false() {
    let req = serde_json::json!({"nullifier": zero_field_hex()});
    let resp = app()
        .oneshot(post_json("/v1/nullifier", &req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["spent"], false);
}

// ── E2E: multiple deposits → merkle root changes ──────────────────

#[tokio::test]
async fn multiple_deposits_change_merkle_root() {
    let router = app();

    // Use a non-zero commitment so the tree root actually changes
    // (default empty leaves are zero, so inserting zero is a no-op for hashing).
    use ff::PrimeField;
    let cm = hex::encode(pasta_curves::pallas::Base::from(12345u64).to_repr());

    // First deposit.
    let dep1 = serde_json::json!({
        "commitment": cm,
        "amount": 1000
    });
    let resp = router
        .clone()
        .oneshot(post_json("/v1/deposit", &dep1))
        .await
        .unwrap();
    let root1 = body_json(resp).await["new_root"]
        .as_str()
        .unwrap()
        .to_string();

    // Second deposit.
    let resp = router
        .oneshot(post_json("/v1/deposit", &dep1))
        .await
        .unwrap();
    let root2 = body_json(resp).await["new_root"]
        .as_str()
        .unwrap()
        .to_string();

    // Roots must differ after inserting a new leaf.
    assert_ne!(root1, root2);
}

// ── E2E: versioned and unversioned routes both work ────────────────

#[tokio::test]
async fn versioned_and_unversioned_routes() {
    let router = app();

    // /v1/status
    let resp = router.clone().oneshot(get("/v1/status")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // /status (unversioned)
    let resp = router.oneshot(get("/status")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
