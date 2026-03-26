//! Mempool RPC handlers — submit transactions for deferred execution.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use lumora_node::mempool::PendingTx;
use lumora_contracts::{DepositRequest, TransferRequest, WithdrawRequest};

use crate::handlers::{parse_field, parse_bytes32};
use crate::types::*;

/// Shared state extended with a mempool.
pub type MempoolState = std::sync::Arc<tokio::sync::Mutex<MempoolNode>>;

/// Node + mempool bundle.
pub struct MempoolNode {
    pub node: lumora_node::LumoraNode,
    pub mempool: lumora_node::Mempool,
}

// ── Submit deposit to mempool ──────────────────────────────────────

pub async fn submit_deposit(
    State(state): State<MempoolState>,
    Json(req): Json<DepositReq>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResp>)> {
    let commitment = parse_field(&req.commitment)?;
    let mut s = state.lock().await;
    let accepted = s.mempool.submit(PendingTx::Deposit(DepositRequest {
        commitment,
        amount: req.amount,
    }));
    if accepted {
        Ok(StatusCode::ACCEPTED)
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResp { error: "mempool full".into() }),
        ))
    }
}

// ── Submit transfer to mempool ─────────────────────────────────────

pub async fn submit_transfer(
    State(state): State<MempoolState>,
    Json(req): Json<TransferReq>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResp>)> {
    let merkle_root = parse_field(&req.merkle_root)?;
    let nf0 = parse_field(&req.nullifiers[0])?;
    let nf1 = parse_field(&req.nullifiers[1])?;
    let cm0 = parse_field(&req.output_commitments[0])?;
    let cm1 = parse_field(&req.output_commitments[1])?;
    let proof_bytes = hex::decode(&req.proof).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResp { error: format!("invalid proof hex: {e}") }))
    })?;

    let mut s = state.lock().await;
    let accepted = s.mempool.submit(PendingTx::Transfer(TransferRequest {
        proof_bytes,
        merkle_root,
        nullifiers: [nf0, nf1],
        output_commitments: [cm0, cm1],
        fee: 0,
        domain_chain_id: req.domain_chain_id,
        domain_app_id: req.domain_app_id,
    }));
    if accepted {
        Ok(StatusCode::ACCEPTED)
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResp { error: "mempool full".into() }),
        ))
    }
}

// ── Submit withdraw to mempool ─────────────────────────────────────

pub async fn submit_withdraw(
    State(state): State<MempoolState>,
    Json(req): Json<WithdrawReq>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResp>)> {
    let merkle_root = parse_field(&req.merkle_root)?;
    let nf0 = parse_field(&req.nullifiers[0])?;
    let nf1 = parse_field(&req.nullifiers[1])?;
    let cm0 = parse_field(&req.output_commitments[0])?;
    let cm1 = parse_field(&req.output_commitments[1])?;
    let proof_bytes = hex::decode(&req.proof).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorResp { error: format!("invalid proof hex: {e}") }))
    })?;
    let recipient = parse_bytes32(&req.recipient)?;

    let mut s = state.lock().await;
    let accepted = s.mempool.submit(PendingTx::Withdraw(WithdrawRequest {
        proof_bytes,
        merkle_root,
        nullifiers: [nf0, nf1],
        output_commitments: [cm0, cm1],
        amount: req.amount,
        fee: 0,
        recipient,
        domain_chain_id: req.domain_chain_id,
        domain_app_id: req.domain_app_id,
    }));
    if accepted {
        Ok(StatusCode::ACCEPTED)
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResp { error: "mempool full".into() }),
        ))
    }
}

// ── Mempool status ─────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct MempoolStatusResp {
    pub pending_count: usize,
}

pub async fn mempool_status(
    State(state): State<MempoolState>,
) -> Json<MempoolStatusResp> {
    let s = state.lock().await;
    Json(MempoolStatusResp {
        pending_count: s.mempool.len(),
    })
}
