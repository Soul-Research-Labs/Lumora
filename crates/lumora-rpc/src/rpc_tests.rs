//! Integration tests for RPC endpoints.
//!
//! Uses a lazily-initialized shared `LumoraNode` so SRS key generation
//! only happens once across all tests (it takes ~40s).

use std::sync::LazyLock;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use ff::PrimeField;
use http_body_util::BodyExt;
use pasta_curves::pallas;
use tower::ServiceExt;

use crate::server::test_router;
use crate::types::*;

/// Shared router — built once, cloned per test.
static SHARED_ROUTER: LazyLock<Router> = LazyLock::new(|| {
    let node = lumora_node::LumoraNode::init();
    test_router(node)
});

/// Helper: build a JSON POST request.
fn post_json(uri: &str, body: &impl serde::Serialize) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// Helper: build a GET request.
fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// Helper: extract response body as bytes.
async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

/// Clone the shared router for each test.
fn app() -> Router {
    SHARED_ROUTER.clone()
}

/// Valid hex-encoded field element (all zeros).
fn zero_field_hex() -> String {
    hex::encode(pallas::Base::zero().to_repr())
}

/// Valid hex-encoded 32-byte zero buffer.
fn zero_bytes32_hex() -> String {
    hex::encode([0u8; 32])
}

// ── Health ────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok() {
    let resp = app().oneshot(get("/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["version"].is_string());
    assert!(json["uptime_secs"].is_number());
    assert!(json["pool_balance"].is_number());
    assert!(json["commitment_count"].is_number());
    assert!(json["current_epoch"].is_number());
    assert!(json["merkle_root"].is_string());
}

// ── Status ────────────────────────────────────────────────────────

#[tokio::test]
async fn status_returns_valid_response() {
    let resp = app().oneshot(get("/v1/status")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let status: StatusResp = serde_json::from_slice(&body).unwrap();
    // Balance and count may be non-zero if deposit tests ran first (shared state).
    assert!(!status.merkle_root.is_empty());
    assert!(!status.circuit_version.is_empty());
}

// ── Fee Estimate ──────────────────────────────────────────────────

#[tokio::test]
async fn fee_estimate_returns_valid_fees() {
    let resp = app().oneshot(get("/v1/fees")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let fees: FeeEstimateResp = serde_json::from_slice(&body).unwrap();
    assert!(fees.transfer_fee > 0);
    assert!(fees.withdraw_fee > 0);
    assert_eq!(fees.min_deposit, lumora_contracts::MIN_DEPOSIT_AMOUNT);
}

// ── Deposit ───────────────────────────────────────────────────────

#[tokio::test]
async fn deposit_success() {
    let req = DepositReq {
        commitment: zero_field_hex(),
        amount: 1000,
        asset: 0,
    };
    let resp = app().oneshot(post_json("/v1/deposit", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let dr: DepositResp = serde_json::from_slice(&body).unwrap();
    // leaf_index depends on how many deposits ran before (shared state).
    assert!(!dr.new_root.is_empty());
}

#[tokio::test]
async fn deposit_below_minimum_rejected() {
    let req = DepositReq {
        commitment: zero_field_hex(),
        amount: 1, // Below MIN_DEPOSIT_AMOUNT
        asset: 0,
    };
    let resp = app().oneshot(post_json("/v1/deposit", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn deposit_invalid_hex_rejected() {
    let req = serde_json::json!({
        "commitment": "not_valid_hex",
        "amount": 1000
    });
    let resp = app().oneshot(post_json("/v1/deposit", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deposit_wrong_length_rejected() {
    let req = serde_json::json!({
        "commitment": "aabb",  // Only 2 bytes, not 32
        "amount": 1000
    });
    let resp = app().oneshot(post_json("/v1/deposit", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Nullifier Check ───────────────────────────────────────────────

#[tokio::test]
async fn nullifier_unspent() {
    let req = NullifierReq {
        nullifier: zero_field_hex(),
    };
    let resp = app()
        .oneshot(post_json("/v1/nullifier", &req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let nr: NullifierResp = serde_json::from_slice(&body).unwrap();
    assert!(!nr.spent);
}

// ── Notes / Relay ─────────────────────────────────────────────────

#[tokio::test]
async fn relay_and_get_notes() {
    let router = app();

    // Use a unique tag so this test is independent of others.
    let tag = hex::encode([0xABu8; 32]);
    let relay_req = RelayNoteReq {
        recipient_tag: tag.clone(),
        leaf_index: 42,
        commitment: zero_bytes32_hex(),
        ciphertext: hex::encode(b"encrypted_data"),
        ephemeral_pubkey: zero_bytes32_hex(),
    };

    // Relay a note.
    let resp = router
        .clone()
        .oneshot(post_json("/v1/relay-note", &relay_req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Retrieve notes for the same tag.
    let get_req = GetNotesReq {
        recipient_tag: tag,
    };
    let resp = router
        .oneshot(post_json("/v1/notes", &get_req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let notes: Vec<EncryptedNoteResp> = serde_json::from_slice(&body).unwrap();
    assert!(!notes.is_empty());
    // At least one note should have the leaf_index we relayed.
    assert!(notes.iter().any(|n| n.leaf_index == 42));
}

// ── History ───────────────────────────────────────────────────────

#[tokio::test]
async fn history_returns_valid_response() {
    let req = HistoryReq {
        offset: 0,
        limit: 100,
    };
    let resp = app()
        .oneshot(post_json("/v1/history", &req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let hr: HistoryResp = serde_json::from_slice(&body).unwrap();
    // Total may be >0 if deposit tests ran first (shared state).
    assert!(hr.events.len() as u64 <= hr.total);
}

#[tokio::test]
async fn history_after_deposit() {
    let router = app();

    // Get current history total.
    let hist = HistoryReq { offset: 0, limit: 1000 };
    let resp = router.clone().oneshot(post_json("/v1/history", &hist)).await.unwrap();
    let before: HistoryResp = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let before_total = before.total;

    // Deposit.
    let dep = DepositReq {
        commitment: zero_field_hex(),
        amount: 500,
        asset: 0,
    };
    let resp = router
        .clone()
        .oneshot(post_json("/v1/deposit", &dep))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // History total should have increased by 1.
    let resp = router
        .oneshot(post_json("/v1/history", &hist))
        .await
        .unwrap();
    let after: HistoryResp = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(after.total, before_total + 1);
}

// ── Transfer (validation errors) ──────────────────────────────────

#[tokio::test]
async fn transfer_invalid_proof_hex_rejected() {
    let req = TransferReq {
        proof: "not_hex!!!".into(),
        merkle_root: zero_field_hex(),
        nullifiers: [zero_field_hex(), zero_field_hex()],
        output_commitments: [zero_field_hex(), zero_field_hex()],
        domain_chain_id: None,
        domain_app_id: None,
        fee: 0,
    };
    let resp = app()
        .oneshot(post_json("/v1/transfer", &req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Withdraw (validation errors) ──────────────────────────────────

#[tokio::test]
async fn withdraw_invalid_recipient_rejected() {
    let req = serde_json::json!({
        "proof": hex::encode(vec![0u8; 64]),
        "merkle_root": zero_field_hex(),
        "nullifiers": [zero_field_hex(), zero_field_hex()],
        "output_commitments": [zero_field_hex(), zero_field_hex()],
        "amount": 100,
        "recipient": "too_short"
    });
    let resp = app()
        .oneshot(post_json("/v1/withdraw", &req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Batch Verify ──────────────────────────────────────────────────

#[tokio::test]
async fn batch_verify_empty_rejected() {
    let req = BatchVerifyReq { proofs: vec![] };
    let resp = app()
        .oneshot(post_json("/v1/batch-verify", &req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn batch_verify_too_large_rejected() {
    let item = BatchVerifyItem {
        proof: hex::encode(vec![0u8; 64]),
        merkle_root: zero_field_hex(),
        nullifiers: [zero_field_hex(), zero_field_hex()],
        output_commitments: [zero_field_hex(), zero_field_hex()],
    };
    let req = BatchVerifyReq {
        proofs: vec![item; 65], // MAX_BATCH_SIZE = 64
    };
    let resp = app()
        .oneshot(post_json("/v1/batch-verify", &req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Sync ──────────────────────────────────────────────────────────

#[tokio::test]
async fn sync_status_ok() {
    let resp = app()
        .oneshot(get("/v1/sync/status"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Versioned vs Unversioned routing ──────────────────────────────

#[tokio::test]
async fn unversioned_routes_work() {
    // /status should work without /v1 prefix.
    let resp = app().oneshot(get("/status")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let resp = app().oneshot(get("/v1/nonexistent")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Epoch Roots ───────────────────────────────────────────────────

#[tokio::test]
async fn epoch_roots_returns_ok() {
    let resp = app().oneshot(get("/v1/epoch-roots")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let er: EpochRootsResp = serde_json::from_slice(&body).unwrap();
    // Fresh node has no finalized epochs yet.
    assert!(er.current_epoch > 0);
}

// ── Jitter Config ─────────────────────────────────────────────────

#[test]
fn jitter_from_millis() {
    let cfg = crate::jitter::JitterConfig::from_millis(10, 100);
    assert_eq!(cfg.min, std::time::Duration::from_millis(10));
    assert_eq!(cfg.max, std::time::Duration::from_millis(100));
}

#[test]
fn jitter_default_has_sane_range() {
    let cfg = crate::jitter::JitterConfig::from_millis(50, 500);
    assert!(cfg.min < cfg.max);
    assert!(cfg.min.as_millis() >= 1);
}

// ── Envelope decode_proof ─────────────────────────────────────────

#[test]
fn decode_proof_raw_bytes() {
    // Raw (non-envelope) hex should pass through unchanged.
    let raw = vec![1u8, 2, 3, 4];
    let hex_str = hex::encode(&raw);
    let decoded = crate::handlers::decode_proof(&hex_str).unwrap();
    assert_eq!(decoded, raw);
}

#[test]
fn decode_proof_envelope_roundtrip() {
    // Seal a payload, verify decode_proof unwraps it.
    let payload = vec![42u8; 100];
    let mut rng = rand::thread_rng();
    let envelope = lumora_primitives::envelope::seal(&payload, &mut rng).unwrap();
    let hex_str = hex::encode(&envelope);
    let decoded = crate::handlers::decode_proof(&hex_str).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn decode_proof_invalid_hex_rejected() {
    let result = crate::handlers::decode_proof("not-valid-hex!!");
    assert!(result.is_err());
}

// ── Stealth Scan ──────────────────────────────────────────────────

#[tokio::test]
async fn stealth_scan_returns_ok() {
    let req = StealthScanReq {
        from_leaf_index: 0,
        limit: 100,
    };
    let resp = app()
        .oneshot(post_json("/v1/stealth-scan", &req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let scan: StealthScanResp = serde_json::from_slice(&body).unwrap();
    // Notes may or may not exist depending on shared state.
    assert_eq!(scan.count, scan.notes.len());
}

// ── Additional Negative / Edge-Case Tests ─────────────────────────

#[tokio::test]
async fn deposit_zero_amount_rejected() {
    let req = DepositReq {
        commitment: zero_field_hex(),
        amount: 0,
        asset: 0,
    };
    let resp = app().oneshot(post_json("/v1/deposit", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deposit_missing_commitment_field_rejected() {
    let req = serde_json::json!({ "amount": 1000 });
    let resp = app().oneshot(post_json("/v1/deposit", &req)).await.unwrap();
    // Missing required field → 422 (deserialization failure)
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn nullifier_invalid_hex_rejected() {
    let req = serde_json::json!({ "nullifier": "ZZZZ_invalid" });
    let resp = app().oneshot(post_json("/v1/nullifier", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn transfer_unknown_root_rejected() {
    // A valid-format request with a root that doesn't exist in root history
    let req = TransferReq {
        proof: hex::encode(vec![0u8; 64]),
        merkle_root: hex::encode([0xABu8; 32]),
        nullifiers: [zero_field_hex(), zero_field_hex()],
        output_commitments: [zero_field_hex(), zero_field_hex()],
        domain_chain_id: None,
        domain_app_id: None,
        fee: 0,
    };
    let resp = app().oneshot(post_json("/v1/transfer", &req)).await.unwrap();
    // Should be 422 (unknown root) or 400 depending on implementation
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn withdraw_zero_amount_rejected() {
    let req = serde_json::json!({
        "proof": hex::encode(vec![0u8; 64]),
        "merkle_root": zero_field_hex(),
        "nullifiers": [zero_field_hex(), zero_field_hex()],
        "output_commitments": [zero_field_hex(), zero_field_hex()],
        "amount": 0,
        "recipient": zero_bytes32_hex()
    });
    let resp = app().oneshot(post_json("/v1/withdraw", &req)).await.unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn relay_note_missing_fields_rejected() {
    let req = serde_json::json!({ "recipient_tag": "aabb" });
    let resp = app().oneshot(post_json("/v1/relay-note", &req)).await.unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn get_notes_empty_tag_returns_empty() {
    let req = GetNotesReq {
        recipient_tag: hex::encode([0xFFu8; 32]),
    };
    let resp = app().oneshot(post_json("/v1/notes", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let notes: Vec<EncryptedNoteResp> = serde_json::from_slice(&body).unwrap();
    assert!(notes.is_empty(), "no notes should exist for random tag");
}

#[tokio::test]
async fn sync_events_from_zero() {
    let req = serde_json::json!({ "from_height": 0 });
    let resp = app().oneshot(post_json("/v1/sync/events", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn empty_body_to_post_endpoint_rejected() {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/deposit")
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());
}
