//! HTTP handler functions for the RPC API.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ff::PrimeField;
use pasta_curves::pallas;
use tokio::sync::RwLock;

use lumora_contracts::{
    ContractError, TransferRequest, WithdrawRequest,
};
use lumora_node::note_store::EncryptedNote;

use crate::types::*;

/// Shared application state — the node behind an RwLock so that read-only
/// queries (nullifier check, get notes, sync events) can run concurrently.
pub type AppState = Arc<RwLock<lumora_node::LumoraNode>>;

/// Maximum allowed proof size in bytes (512 KB).
const MAX_PROOF_BYTES: usize = 512 * 1024;

/// Decode hex proof bytes, attempt envelope unwrap, fall back to raw bytes.
///
/// Supports both enveloped proofs (fixed 2048 bytes) and raw proof bytes
/// for backward compatibility.
pub fn decode_proof(hex_str: &str) -> Result<Vec<u8>, (StatusCode, Json<ErrorResp>)> {
    let raw = hex::decode(hex_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResp {
                error: format!("invalid proof hex: {e}"),
            }),
        )
    })?;
    if raw.len() > MAX_PROOF_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResp {
                error: format!("proof too large: {} bytes (max {})", raw.len(), MAX_PROOF_BYTES),
            }),
        ));
    }
    // Try to unwrap as an envelope; fall back to raw bytes if not an envelope.
    match lumora_primitives::envelope::open(&raw) {
        Ok(payload) => Ok(payload),
        Err(_) => Ok(raw),
    }
}

/// Parse a hex string into a pallas::Base field element.
pub fn parse_field(hex_str: &str) -> Result<pallas::Base, (StatusCode, Json<ErrorResp>)> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResp {
                error: format!("invalid hex: {e}"),
            }),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResp {
                error: format!("expected 32 bytes, got {}", bytes.len()),
            }),
        ));
    }
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes);
    let opt: Option<pallas::Base> = pallas::Base::from_repr(repr).into();
    match opt {
        Some(f) => Ok(f),
        None => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResp {
                error: "invalid field element".into(),
            }),
        )),
    }
}

fn field_to_hex(f: pallas::Base) -> String {
    hex::encode(f.to_repr())
}

fn contract_err(e: ContractError) -> (StatusCode, Json<ErrorResp>) {
    // Log the specific error for operator debugging, but return a generic
    // message to clients so that different rejection reasons (spent
    // nullifier, invalid proof, unknown root) are indistinguishable.
    tracing::warn!(error = %e, "contract rejected transaction");
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(ErrorResp {
            error: "transaction rejected".to_string(),
        }),
    )
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ErrorResp>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResp { error: msg.into() }),
    )
}

pub fn parse_bytes32(hex_str: &str) -> Result<[u8; 32], (StatusCode, Json<ErrorResp>)> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResp {
                error: format!("invalid hex: {e}"),
            }),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResp {
                error: format!("expected 32 bytes, got {}", bytes.len()),
            }),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ── Deposit ────────────────────────────────────────────────────────

pub async fn deposit(
    State(state): State<AppState>,
    Json(req): Json<DepositReq>,
) -> Result<Json<DepositResp>, (StatusCode, Json<ErrorResp>)> {
    if req.amount == 0 {
        return Err(bad_request("amount must be greater than zero"));
    }
    let commitment = parse_field(&req.commitment)?;
    let mut node = state.write().await;
    let receipt = node
        .deposit(commitment, req.amount)
        .map_err(contract_err)?;
    tracing::info!(leaf_index = receipt.leaf_index, amount = req.amount, "deposit accepted");
    Ok(Json(DepositResp {
        leaf_index: receipt.leaf_index,
        new_root: field_to_hex(receipt.new_root),
    }))
}

// ── Transfer ───────────────────────────────────────────────────────

pub async fn transfer(
    State(state): State<AppState>,
    Json(req): Json<TransferReq>,
) -> Result<Json<TransferResp>, (StatusCode, Json<ErrorResp>)> {
    let merkle_root = parse_field(&req.merkle_root)?;
    let nf0 = parse_field(&req.nullifiers[0])?;
    let nf1 = parse_field(&req.nullifiers[1])?;
    let cm0 = parse_field(&req.output_commitments[0])?;
    let cm1 = parse_field(&req.output_commitments[1])?;
    let proof_bytes = decode_proof(&req.proof)?;

    let transfer_req = TransferRequest {
        proof_bytes,
        merkle_root,
        nullifiers: [nf0, nf1],
        output_commitments: [cm0, cm1],
        fee: req.fee,
        domain_chain_id: req.domain_chain_id,
        domain_app_id: req.domain_app_id,
    };

    let mut node = state.write().await;
    let receipt = node
        .pool
        .transfer(&transfer_req)
        .map_err(contract_err)?;
    // Keep local tree mirror in sync so the node can generate proofs later.
    for cm in &transfer_req.output_commitments {
        node.tree.try_insert(*cm).map_err(|_| contract_err(ContractError::TreeFull))?;
    }
    let root = node.current_root();
    tracing::info!(
        leaf_0 = receipt.leaf_indices[0],
        leaf_1 = receipt.leaf_indices[1],
        domain_chain_id = ?req.domain_chain_id,
        domain_app_id = ?req.domain_app_id,
        "transfer accepted",
    );
    Ok(Json(TransferResp {
        leaf_indices: receipt.leaf_indices,
        new_root: field_to_hex(root),
    }))
}

// ── Withdraw ───────────────────────────────────────────────────────

pub async fn withdraw(
    State(state): State<AppState>,
    Json(req): Json<WithdrawReq>,
) -> Result<Json<WithdrawResp>, (StatusCode, Json<ErrorResp>)> {
    if req.amount == 0 {
        return Err(bad_request("withdrawal amount must be greater than zero"));
    }
    let merkle_root = parse_field(&req.merkle_root)?;
    let nf0 = parse_field(&req.nullifiers[0])?;
    let nf1 = parse_field(&req.nullifiers[1])?;
    let cm0 = parse_field(&req.output_commitments[0])?;
    let cm1 = parse_field(&req.output_commitments[1])?;
    let proof_bytes = decode_proof(&req.proof)?;
    let recipient = parse_bytes32(&req.recipient)?;

    let withdraw_req = WithdrawRequest {
        proof_bytes,
        merkle_root,
        nullifiers: [nf0, nf1],
        output_commitments: [cm0, cm1],
        amount: req.amount,
        fee: req.fee,
        recipient,
        domain_chain_id: req.domain_chain_id,
        domain_app_id: req.domain_app_id,
    };

    let mut node = state.write().await;
    let receipt = node
        .pool
        .withdraw(&withdraw_req)
        .map_err(contract_err)?;
    // Keep local tree mirror in sync so the node can generate proofs later.
    for cm in &withdraw_req.output_commitments {
        node.tree.try_insert(*cm).map_err(|_| contract_err(ContractError::TreeFull))?;
    }
    let root = node.current_root();
    tracing::info!(
        amount = receipt.amount,
        domain_chain_id = ?req.domain_chain_id,
        domain_app_id = ?req.domain_app_id,
        "withdrawal accepted",
    );
    Ok(Json(WithdrawResp {
        change_leaf_indices: receipt.change_leaf_indices,
        new_root: field_to_hex(root),
        amount: receipt.amount,
    }))
}

// ── Status ─────────────────────────────────────────────────────────

pub async fn status(
    State(state): State<AppState>,
) -> Json<StatusResp> {
    let mut node = state.write().await;
    let root = node.current_root();
    Json(StatusResp {
        pool_balance: node.pool_balance(),
        commitment_count: node.commitment_count(),
        merkle_root: field_to_hex(root),
        circuit_version: lumora_circuits::CircuitVersion::CURRENT.label().to_string(),
    })
}

// ── Nullifier Query ────────────────────────────────────────────────

pub async fn nullifier_check(
    State(state): State<AppState>,
    Json(req): Json<NullifierReq>,
) -> Result<Json<NullifierResp>, (StatusCode, Json<ErrorResp>)> {
    let nf = parse_field(&req.nullifier)?;
    let node = state.read().await;
    let spent = node.pool.state.is_nullifier_spent(nf);
    Ok(Json(NullifierResp { spent }))
}

// ── Note Store ─────────────────────────────────────────────────────

pub async fn get_notes(
    State(state): State<AppState>,
    Json(req): Json<GetNotesReq>,
) -> Result<Json<Vec<EncryptedNoteResp>>, (StatusCode, Json<ErrorResp>)> {
    let tag = parse_bytes32(&req.recipient_tag)?;
    let node = state.read().await;
    let notes = node.get_notes(&tag);
    let resp: Vec<EncryptedNoteResp> = notes
        .iter()
        .map(|n| EncryptedNoteResp {
            leaf_index: n.leaf_index,
            commitment: hex::encode(n.commitment),
            ciphertext: hex::encode(&n.ciphertext),
            ephemeral_pubkey: hex::encode(n.ephemeral_pubkey),
        })
        .collect();
    Ok(Json(resp))
}

/// Maximum leaf index — Merkle tree depth is 32, so indices fit in u32.
const MAX_LEAF_INDEX: u64 = (1u64 << 32) - 1;

pub async fn relay_note(
    State(state): State<AppState>,
    Json(req): Json<RelayNoteReq>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResp>)> {
    if req.leaf_index > MAX_LEAF_INDEX {
        return Err(bad_request(format!(
            "leaf_index {} exceeds maximum {}",
            req.leaf_index, MAX_LEAF_INDEX
        )));
    }
    let tag = parse_bytes32(&req.recipient_tag)?;
    let commitment = parse_bytes32(&req.commitment)?;
    let ephemeral_pubkey = parse_bytes32(&req.ephemeral_pubkey)?;
    let ciphertext = hex::decode(&req.ciphertext).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResp {
                error: format!("invalid ciphertext hex: {e}"),
            }),
        )
    })?;

    // Limit ciphertext to 256 bytes to prevent memory exhaustion.
    const MAX_CIPHERTEXT_SIZE: usize = 256;
    if ciphertext.len() > MAX_CIPHERTEXT_SIZE {
        return Err(bad_request(format!(
            "ciphertext too large: {} bytes (max {MAX_CIPHERTEXT_SIZE})",
            ciphertext.len()
        )));
    }

    let note = EncryptedNote {
        leaf_index: req.leaf_index,
        commitment,
        ciphertext,
        ephemeral_pubkey,
    };

    let mut node = state.write().await;
    node.relay_note(tag, note);
    Ok(StatusCode::CREATED)
}

// ── Fee Estimation ─────────────────────────────────────────────────

/// Dynamic fee estimator shared across handlers.
static FEE_ESTIMATOR: std::sync::LazyLock<lumora_contracts::fee::DynamicFeeEstimator> =
    std::sync::LazyLock::new(lumora_contracts::fee::DynamicFeeEstimator::default);

pub async fn fee_estimate(
    State(state): State<AppState>,
) -> Json<FeeEstimateResp> {
    // Use pending tx count from the pool events as a congestion proxy.
    let node = state.read().await;
    let pending = node.pool.state.events().len();
    Json(FeeEstimateResp {
        transfer_fee: FEE_ESTIMATOR.transfer_fee(pending),
        withdraw_fee: FEE_ESTIMATOR.withdraw_fee(pending),
        min_deposit: lumora_contracts::MIN_DEPOSIT_AMOUNT,
        min_withdraw: lumora_contracts::MIN_WITHDRAW_AMOUNT,
    })
}

// ── Transaction History ────────────────────────────────────────────

pub async fn history(
    State(state): State<AppState>,
    Json(req): Json<HistoryReq>,
) -> Result<Json<HistoryResp>, (StatusCode, Json<ErrorResp>)> {
    let node = state.read().await;
    let all = node.pool.state.events();
    let total = all.len() as u64;
    let offset = (req.offset as usize).min(all.len());
    let limit = (req.limit as usize).min(1000);
    let page = &all[offset..all.len().min(offset + limit)];
    let events: Vec<serde_json::Value> = page
        .iter()
        .map(|e| serde_json::to_value(e).unwrap_or_default())
        .collect();
    Ok(Json(HistoryResp { total, events }))
}

// ── Batch Verification ─────────────────────────────────────────────

/// Maximum proofs allowed in a single batch request.
const MAX_BATCH_SIZE: usize = 16;

pub async fn batch_verify(
    State(state): State<AppState>,
    Json(req): Json<BatchVerifyReq>,
) -> Result<Json<BatchVerifyResp>, (StatusCode, Json<ErrorResp>)> {
    if req.proofs.is_empty() {
        return Err(bad_request("batch must contain at least one proof"));
    }
    if req.proofs.len() > MAX_BATCH_SIZE {
        return Err(bad_request(format!(
            "batch too large ({} proofs, max {MAX_BATCH_SIZE})",
            req.proofs.len()
        )));
    }

    const MAX_BATCH_BYTES: usize = 2 * 1024 * 1024; // 2 MB total for all proofs

    let mut items = Vec::with_capacity(req.proofs.len());
    let mut total_proof_bytes: usize = 0;
    for (i, p) in req.proofs.iter().enumerate() {
        let proof_bytes = hex::decode(&p.proof)
            .map_err(|_| bad_request(format!("invalid proof hex at index {i}")))?;
        if proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(bad_request(format!("proof at index {i} exceeds 512 KB")));
        }
        total_proof_bytes += proof_bytes.len();
        if total_proof_bytes > MAX_BATCH_BYTES {
            return Err(bad_request(format!(
                "total batch proof data exceeds {} bytes",
                MAX_BATCH_BYTES
            )));
        }
        let root = parse_field(&p.merkle_root)
            .map_err(|_| bad_request(format!("invalid merkle_root at index {i}")))?;
        let nullifiers = [
            parse_field(&p.nullifiers[0])
                .map_err(|_| bad_request(format!("invalid nullifier[0] at index {i}")))?,

            parse_field(&p.nullifiers[1])
                .map_err(|_| bad_request(format!("invalid nullifier[1] at index {i}")))?,

        ];
        let outputs = [
            parse_field(&p.output_commitments[0])
                .map_err(|_| bad_request(format!("invalid output[0] at index {i}")))?,

            parse_field(&p.output_commitments[1])
                .map_err(|_| bad_request(format!("invalid output[1] at index {i}")))?,

        ];
        items.push(lumora_verifier::TransferBatchItem {
            proof_bytes,
            merkle_root: root,
            nullifiers,
            output_commitments: outputs,
            fee: 0, // Batch verify uses fee=0 for now
        });
    }

    let node = state.read().await;
    let all_valid = lumora_verifier::batch_verify_transfers(&node.pool.verifier, &items);
    Ok(Json(BatchVerifyResp {
        all_valid,
        count: items.len(),
    }))
}

/// GET /v1/epoch-roots — return all finalized nullifier-epoch Merkle roots.
pub async fn epoch_roots(
    State(state): State<AppState>,
) -> Json<EpochRootsResp> {
    let node = state.read().await;
    let em = node.pool.state.epoch_manager();
    let roots = em
        .all_finalized_roots()
        .into_iter()
        .map(|(epoch_id, root)| {
            let bytes = root.to_repr();
            EpochRootEntry {
                epoch_id,
                root: hex::encode(bytes),
            }
        })
        .collect();
    Json(EpochRootsResp {
        current_epoch: em.current_epoch(),
        roots,
    })
}

/// POST /v1/stealth-scan — return all encrypted notes since a leaf index
/// for client-side stealth address scanning.
///
/// Clients must download all notes (not filter by tag) to avoid leaking
/// which notes belong to them. They then trial-decrypt each note locally
/// using their spending key.
pub async fn stealth_scan(
    State(state): State<AppState>,
    Json(req): Json<StealthScanReq>,
) -> Result<Json<StealthScanResp>, (StatusCode, Json<ErrorResp>)> {
    // Bug #24: enforce from_leaf_index == 0 to prevent inference attacks.
    // A non-zero start offset reveals which leaves a client has already seen,
    // which can be used to fingerprint or de-anonymize the client.
    if req.from_leaf_index != 0 {
        return Err(bad_request(
            "from_leaf_index must be 0; partial scans leak scanning progress",
        ));
    }
    let node = state.read().await;
    let all = node.note_store.all_notes_since(0);
    let effective_limit = req.limit.min(crate::types::MAX_SCAN_LIMIT);
    let notes: Vec<EncryptedNoteResp> = all
        .into_iter()
        .take(effective_limit)
        .map(|n| EncryptedNoteResp {
            leaf_index: n.leaf_index,
            commitment: hex::encode(n.commitment),
            ciphertext: hex::encode(&n.ciphertext),
            ephemeral_pubkey: hex::encode(n.ephemeral_pubkey),
        })
        .collect();
    let count = notes.len();
    Ok(Json(StealthScanResp { notes, count }))
}

// ── BitVM Bridge ───────────────────────────────────────────────────

/// GET /bitvm/status — Check whether a BitVM bridge is active.
pub async fn bitvm_status(
    State(state): State<AppState>,
) -> Json<BitvmStatusResp> {
    let node = state.read().await;
    Json(BitvmStatusResp {
        bridge_active: node.has_bridge(),
        deposits_processed: 0,
        roots_committed: 0,
    })
}

/// POST /bitvm/poll — Poll the host chain for new deposits.
pub async fn bitvm_poll_deposits(
    State(state): State<AppState>,
) -> Result<Json<BitvmPollResp>, (StatusCode, Json<ErrorResp>)> {
    let mut node = state.write().await;
    let new_deposits = node.poll_bridge_deposits().map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResp {
                error: format!("bridge poll failed: {e}"),
            }),
        )
    })?;
    if new_deposits > 0 {
        tracing::info!(new_deposits, "polled L1 deposits via BitVM bridge");
    }
    Ok(Json(BitvmPollResp { new_deposits }))
}

/// POST /bitvm/commit-root — Commit the current Merkle root to the host chain.
pub async fn bitvm_commit_root(
    State(state): State<AppState>,
) -> Result<Json<BitvmCommitRootResp>, (StatusCode, Json<ErrorResp>)> {
    let mut node = state.write().await;
    node.commit_root_to_bridge().map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResp {
                error: format!("bridge commit failed: {e}"),
            }),
        )
    })?;
    let root = node.pool.state.current_root();
    Ok(Json(BitvmCommitRootResp {
        committed_root: field_to_hex(root),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    // ── parse_field ─────────────────────────────────────────────────

    #[test]
    fn parse_field_valid_zero() {
        let hex = hex::encode([0u8; 32]);
        let f = parse_field(&hex).unwrap();
        assert_eq!(f, pallas::Base::zero());
    }

    #[test]
    fn parse_field_valid_one() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        let hex_str = hex::encode(bytes);
        let f = parse_field(&hex_str).unwrap();
        assert_eq!(f, pallas::Base::one());
    }

    #[test]
    fn parse_field_invalid_hex() {
        let (status, _) = parse_field("zzzz").unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_field_wrong_length() {
        let hex = hex::encode([0u8; 16]); // 16 bytes
        let (status, body) = parse_field(&hex).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.error.contains("expected 32 bytes"));
    }

    #[test]
    fn parse_field_empty() {
        let (status, _) = parse_field("").unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // ── parse_bytes32 ──────────────────────────────────────────────

    #[test]
    fn parse_bytes32_valid() {
        let input = [0xABu8; 32];
        let hex = hex::encode(input);
        let out = parse_bytes32(&hex).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn parse_bytes32_invalid_hex() {
        let (status, _) = parse_bytes32("not-hex!").unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_bytes32_wrong_length() {
        let hex = hex::encode([0u8; 20]);
        let (status, body) = parse_bytes32(&hex).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.error.contains("expected 32 bytes"));
    }

    // ── decode_proof ───────────────────────────────────────────────

    #[test]
    fn decode_proof_valid_raw() {
        let proof_bytes = vec![1u8, 2, 3, 4];
        let hex = hex::encode(&proof_bytes);
        let out = decode_proof(&hex).unwrap();
        // May pass through envelope::open fallback to raw.
        assert!(!out.is_empty());
    }

    #[test]
    fn decode_proof_invalid_hex() {
        let (status, _) = decode_proof("xyz!").unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn decode_proof_too_large() {
        let big = hex::encode(vec![0u8; MAX_PROOF_BYTES + 1]);
        let (status, body) = decode_proof(&big).unwrap_err();
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(body.error.contains("too large"));
    }

    #[test]
    fn decode_proof_empty_is_ok() {
        // Empty string → empty bytes → passes size check.
        let out = decode_proof("").unwrap();
        assert!(out.is_empty());
    }

    // ── field_to_hex ───────────────────────────────────────────────

    #[test]
    fn field_to_hex_roundtrip() {
        let f = pallas::Base::from(12345u64);
        let hex_str = field_to_hex(f);
        let back = parse_field(&hex_str).unwrap();
        assert_eq!(f, back);
    }
}
