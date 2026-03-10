//! Rollup integration layer — Strata bridge, deposit/withdrawal lifecycle,
//! state root commitment, and finality tracking.
//!
//! Items covered:
//! - #46 StrataBridge implementing [`RollupBridge`]
//! - #47 L1DepositListener trait + mock
//! - #48 L1WithdrawalSubmitter trait + mock
//! - #49 StateRootCommitter with batch commitment
//! - #50 Halo2 IPA verifier contract interface
//! - #51 DepositFinalityTracker with confirmation counting
//! - #52 AtomicDepositWithdrawal coordinator

use ff::PrimeField;
use pasta_curves::pallas;

use crate::bridge::{BridgeError, InboundDeposit, OutboundWithdrawal, RollupBridge};

// ---------------------------------------------------------------------------
// #47 — L1DepositListener
// ---------------------------------------------------------------------------

/// Trait for monitoring L1 deposit events.
pub trait L1DepositListener {
    /// Fetch new deposits since the given block height.
    fn listen_from(&self, from_height: u64) -> Result<Vec<InboundDeposit>, BridgeError>;

    /// Return the latest block height observed.
    fn latest_height(&self) -> Result<u64, BridgeError>;
}

/// Mock deposit listener that returns a configurable set of deposits.
pub struct MockDepositListener {
    pub deposits: Vec<InboundDeposit>,
    pub height: u64,
}

impl Default for MockDepositListener {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDepositListener {
    pub fn new() -> Self {
        Self {
            deposits: Vec::new(),
            height: 0,
        }
    }

    pub fn with_deposits(deposits: Vec<InboundDeposit>, height: u64) -> Self {
        Self { deposits, height }
    }
}

impl L1DepositListener for MockDepositListener {
    fn listen_from(&self, _from_height: u64) -> Result<Vec<InboundDeposit>, BridgeError> {
        Ok(self.deposits.clone())
    }

    fn latest_height(&self) -> Result<u64, BridgeError> {
        Ok(self.height)
    }
}

// ---------------------------------------------------------------------------
// #48 — L1WithdrawalSubmitter
// ---------------------------------------------------------------------------

/// Result of a withdrawal submission to L1.
#[derive(Debug, Clone)]
pub struct WithdrawalReceipt {
    /// Host chain tx hash.
    pub tx_id: Vec<u8>,
    /// Block height at which the withdrawal was included.
    pub block_height: u64,
}

/// Trait for submitting verified withdrawals to the host chain.
pub trait L1WithdrawalSubmitter {
    /// Submit a single withdrawal and return a receipt.
    fn submit(&self, withdrawal: &OutboundWithdrawal) -> Result<WithdrawalReceipt, BridgeError>;

    /// Submit multiple withdrawals in a single batch.
    fn submit_batch(
        &self,
        withdrawals: &[OutboundWithdrawal],
    ) -> Result<Vec<WithdrawalReceipt>, BridgeError>;
}

/// Mock submitter — returns synthetic receipts.
pub struct MockWithdrawalSubmitter {
    pub block_height: u64,
}

impl MockWithdrawalSubmitter {
    pub fn new(block_height: u64) -> Self {
        Self { block_height }
    }
}

impl L1WithdrawalSubmitter for MockWithdrawalSubmitter {
    fn submit(&self, _withdrawal: &OutboundWithdrawal) -> Result<WithdrawalReceipt, BridgeError> {
        Ok(WithdrawalReceipt {
            tx_id: vec![0xAB; 32],
            block_height: self.block_height,
        })
    }

    fn submit_batch(
        &self,
        withdrawals: &[OutboundWithdrawal],
    ) -> Result<Vec<WithdrawalReceipt>, BridgeError> {
        withdrawals.iter().map(|w| self.submit(w)).collect()
    }
}

// ---------------------------------------------------------------------------
// #49 — StateRootCommitter
// ---------------------------------------------------------------------------

/// Commits Lumora Merkle roots to the host chain for data availability.
pub struct StateRootCommitter<B: RollupBridge> {
    bridge: B,
    /// History of committed roots (newest last).
    committed: Vec<pallas::Base>,
    /// Pending roots awaiting batch flush.
    pending: Vec<pallas::Base>,
    /// Maximum roots to batch before auto-flush.
    batch_capacity: usize,
}

impl<B: RollupBridge> StateRootCommitter<B> {
    pub fn new(bridge: B, batch_capacity: usize) -> Self {
        Self {
            bridge,
            committed: Vec::new(),
            pending: Vec::new(),
            batch_capacity,
        }
    }

    /// Queue a root for the next batch commit.
    pub fn queue(&mut self, root: pallas::Base) {
        self.pending.push(root);
        if self.pending.len() >= self.batch_capacity {
            let _ = self.flush();
        }
    }

    /// Commit all pending roots to the host chain in order.
    pub fn flush(&mut self) -> Result<usize, BridgeError> {
        let count = self.pending.len();
        for root in self.pending.drain(..) {
            self.bridge.commit_state_root(root)?;
            self.committed.push(root);
        }
        Ok(count)
    }

    pub fn committed_count(&self) -> usize {
        self.committed.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

// ---------------------------------------------------------------------------
// #50 — Halo2 IPA Verifier contract interface
// ---------------------------------------------------------------------------

/// Interface for on-chain Halo2 IPA verification.
///
/// In production, verification happens in a host-chain smart contract
/// (e.g. a Strata covenant script). The [`IpaTransferVerifier`]
/// implementation delegates to `lumora-verifier` for cryptographic
/// verification; [`IpaVerifierStub`] is provided for lightweight testing.
pub trait OnChainVerifier {
    /// Verify a serialised proof against expected public inputs.
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError>;
}

/// Real Halo2 IPA verifier for transfer proofs.
///
/// Wraps `lumora-verifier` and performs genuine cryptographic verification
/// of Halo2 IPA proofs against the circuit's verifying key.
pub struct IpaTransferVerifier {
    verifier: lumora_prover::VerifierParams,
}

impl IpaTransferVerifier {
    /// Create from an existing verifier params bundle (generated during setup).
    pub fn new(verifier: lumora_prover::VerifierParams) -> Self {
        Self { verifier }
    }
}

impl OnChainVerifier for IpaTransferVerifier {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        use halo2_proofs::plonk;
        use halo2_proofs::transcript::{Blake2bRead, Challenge255};
        use pasta_curves::vesta;

        let strategy = plonk::SingleVerifier::new(&self.verifier.params);
        let mut transcript =
            Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof_bytes);

        let result = plonk::verify_proof(
            &self.verifier.params,
            &self.verifier.vk,
            strategy,
            &[&[public_inputs]],
            &mut transcript,
        );

        match result {
            Ok(()) => Ok(true),
            Err(plonk::Error::ConstraintSystemFailure) => Ok(false),
            Err(plonk::Error::InvalidInstances) => Ok(false),
            Err(e) => Err(BridgeError::VerificationFailed(format!("{e:?}"))),
        }
    }
}

/// Lightweight verifier stub for testing — only checks proof byte length.
///
/// Useful when you need an `OnChainVerifier` in tests without the overhead
/// of key generation and real proof verification.
pub struct IpaVerifierStub {
    /// Minimum expected proof byte length.
    pub min_proof_len: usize,
}

impl Default for IpaVerifierStub {
    fn default() -> Self {
        Self::new()
    }
}

impl IpaVerifierStub {
    pub fn new() -> Self {
        Self {
            min_proof_len: 32,
        }
    }
}

impl OnChainVerifier for IpaVerifierStub {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        if proof_bytes.len() < self.min_proof_len {
            return Ok(false);
        }
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// #51 — DepositFinalityTracker
// ---------------------------------------------------------------------------

/// Tracks deposit confirmations so that Lumora only processes deposits
/// that have reached sufficient finality on the host chain.
pub struct DepositFinalityTracker {
    /// Number of confirmations required before a deposit is considered final.
    required_confirmations: u64,
    /// (deposit tx_id, first_seen_height)
    pending: Vec<(Vec<u8>, u64)>,
}

impl DepositFinalityTracker {
    pub fn new(required_confirmations: u64) -> Self {
        Self {
            required_confirmations,
            pending: Vec::new(),
        }
    }

    /// Register a deposit observed at the given block height.
    pub fn observe(&mut self, tx_id: Vec<u8>, block_height: u64) {
        if !self.pending.iter().any(|(id, _)| id == &tx_id) {
            self.pending.push((tx_id, block_height));
        }
    }

    /// Return deposit tx_ids that have reached finality given the current
    /// chain tip, and remove them from the pending set.
    pub fn finalized(&mut self, current_height: u64) -> Vec<Vec<u8>> {
        let (ready, still_pending): (Vec<_>, Vec<_>) = self
            .pending
            .drain(..)
            .partition(|(_, seen)| current_height.saturating_sub(*seen) >= self.required_confirmations);

        self.pending = still_pending;
        ready.into_iter().map(|(id, _)| id).collect()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

// ---------------------------------------------------------------------------
// #52 — AtomicDepositWithdrawal coordinator
// ---------------------------------------------------------------------------

/// Outcome of a single processing cycle.
#[derive(Debug, Default)]
pub struct CycleResult {
    pub deposits_processed: usize,
    pub withdrawals_submitted: usize,
    pub roots_committed: usize,
}

/// Coordinates deposits, withdrawals, and state root commits atomically.
///
/// A single `run_cycle` call:
/// 1. Polls for new deposits via `L1DepositListener`
/// 2. Checks finality via `DepositFinalityTracker`
/// 3. Submits queued withdrawals via `L1WithdrawalSubmitter`
/// 4. Commits the state root via `StateRootCommitter`
pub struct AtomicDepositWithdrawal<L, S, B>
where
    L: L1DepositListener,
    S: L1WithdrawalSubmitter,
    B: RollupBridge,
{
    listener: L,
    submitter: S,
    committer: StateRootCommitter<B>,
    tracker: DepositFinalityTracker,
    last_scanned_height: u64,
    withdrawal_queue: Vec<OutboundWithdrawal>,
}

impl<L, S, B> AtomicDepositWithdrawal<L, S, B>
where
    L: L1DepositListener,
    S: L1WithdrawalSubmitter,
    B: RollupBridge,
{
    pub fn new(
        listener: L,
        submitter: S,
        committer: StateRootCommitter<B>,
        tracker: DepositFinalityTracker,
    ) -> Self {
        Self {
            listener,
            submitter,
            committer,
            tracker,
            last_scanned_height: 0,
            withdrawal_queue: Vec::new(),
        }
    }

    /// Enqueue a verified withdrawal for submission in the next cycle.
    pub fn enqueue_withdrawal(&mut self, wd: OutboundWithdrawal) {
        self.withdrawal_queue.push(wd);
    }

    /// Execute one processing cycle.
    ///
    /// Returns deposit tx_ids that reached finality so the caller can insert
    /// the corresponding note commitments into the Merkle tree.
    pub fn run_cycle(
        &mut self,
        current_root: pallas::Base,
    ) -> Result<(CycleResult, Vec<Vec<u8>>), BridgeError> {
        let mut result = CycleResult::default();

        // 1. Poll deposits
        let deposits = self.listener.listen_from(self.last_scanned_height)?;
        let tip = self.listener.latest_height()?;
        for d in &deposits {
            self.tracker.observe(d.tx_id.clone(), tip);
        }
        self.last_scanned_height = tip;

        // 2. Check finality
        let finalized = self.tracker.finalized(tip);
        result.deposits_processed = finalized.len();

        // 3. Submit queued withdrawals
        let queued: Vec<OutboundWithdrawal> = self.withdrawal_queue.drain(..).collect();
        if !queued.is_empty() {
            let receipts = self.submitter.submit_batch(&queued)?;
            result.withdrawals_submitted = receipts.len();
        }

        // 4. Commit state root
        self.committer.queue(current_root);
        let flushed = self.committer.flush()?;
        result.roots_committed = flushed;

        Ok((result, finalized))
    }
}

// ---------------------------------------------------------------------------
// #46 — StrataBridge (ties it all together)
// ---------------------------------------------------------------------------

/// Configuration for the Strata rollup bridge.
#[derive(Debug, Clone)]
pub struct StrataConfig {
    /// Strata RPC endpoint (e.g. `http://127.0.0.1:18443`).
    pub rpc_url: String,
    /// Required L1 confirmations for deposit finality.
    pub confirmations: u64,
    /// Maximum withdrawals per batch.
    pub max_batch_size: usize,
}

impl Default for StrataConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:18443"),
            confirmations: 6,
            max_batch_size: 16,
        }
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 Protocol Types
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, serde::Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct JsonRpcResponse {
    pub id: u64,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

/// Transport layer for sending JSON-RPC requests to the Strata node.
///
/// Implement this trait to plug in your preferred HTTP client (e.g. `reqwest`,
/// `ureq`, or a custom transport).
pub trait RpcTransport {
    /// Send a JSON-RPC request and return the parsed response.
    fn send(&self, url: &str, request: &JsonRpcRequest) -> Result<JsonRpcResponse, BridgeError>;
}

/// Offline transport — returns empty successful results without making any
/// network calls. Used when running in standalone mode or in tests.
pub struct OfflineTransport;

impl RpcTransport for OfflineTransport {
    fn send(&self, _url: &str, request: &JsonRpcRequest) -> Result<JsonRpcResponse, BridgeError> {
        let result = match request.method.as_str() {
            "lumora_getDeposits" => serde_json::json!([]),
            "lumora_submitWithdrawal" => serde_json::json!({ "tx_id": "0".repeat(64) }),
            "lumora_commitRoot" => serde_json::json!(true),
            _ => serde_json::json!(null),
        };
        Ok(JsonRpcResponse {
            id: request.id,
            result: Some(result),
            error: None,
        })
    }
}

/// Strata-specific bridge implementation.
///
/// Communicates with the Strata rollup node via its JSON-RPC interface.
/// The transport layer is pluggable — use [`OfflineTransport`] for standalone
/// operation, or provide a real HTTP transport when connected to a Strata node.
pub struct StrataBridge<T: RpcTransport = OfflineTransport> {
    config: StrataConfig,
    transport: T,
    next_id: std::cell::Cell<u64>,
}

impl StrataBridge<OfflineTransport> {
    /// Create a bridge with the default offline transport.
    pub fn new(config: StrataConfig) -> Self {
        Self {
            config,
            transport: OfflineTransport,
            next_id: std::cell::Cell::new(1),
        }
    }
}

impl<T: RpcTransport> StrataBridge<T> {
    /// Create a bridge with a custom RPC transport.
    pub fn with_transport(config: StrataConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            next_id: std::cell::Cell::new(1),
        }
    }

    pub fn config(&self) -> &StrataConfig {
        &self.config
    }

    /// Build a JSON-RPC request with auto-incrementing ID.
    fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, BridgeError> {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));

        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };

        let resp = self.transport.send(&self.config.rpc_url, &req)?;

        if let Some(err) = resp.error {
            return Err(BridgeError::ConnectionError(format!(
                "RPC error {}: {}",
                err.code, err.message
            )));
        }

        resp.result.ok_or_else(|| {
            BridgeError::ConnectionError("RPC response missing result".into())
        })
    }
}

impl<T: RpcTransport> RollupBridge for StrataBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("lumora_getDeposits", serde_json::json!([]))?;

        let deposits: Vec<serde_json::Value> = serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse deposits: {e}")))?;

        deposits
            .into_iter()
            .map(|d| {
                let amount = d["amount"].as_u64().unwrap_or(0);
                let tx_id_hex = d["tx_id"].as_str().unwrap_or("");
                let commitment_hex = d["commitment"].as_str().unwrap_or("");

                let tx_id = hex::decode(tx_id_hex)
                    .unwrap_or_default();

                // Parse commitment from hex (32-byte LE field element).
                let cm_bytes: [u8; 32] = hex::decode(commitment_hex)
                    .unwrap_or_else(|_| vec![0u8; 32])
                    .try_into()
                    .unwrap_or([0u8; 32]);
                let commitment = pallas::Base::from_repr(cm_bytes)
                    .unwrap_or(pallas::Base::zero());

                Ok(InboundDeposit {
                    commitment,
                    amount,
                    tx_id,
                })
            })
            .collect()
    }

    fn execute_withdrawal(&self, withdrawal: &OutboundWithdrawal) -> Result<Vec<u8>, BridgeError> {
        let result = self.rpc_call(
            "lumora_submitWithdrawal",
            serde_json::json!({
                "amount": withdrawal.amount,
                "recipient": hex::encode(withdrawal.recipient),
                "proof_bytes": hex::encode(&withdrawal.proof_bytes),
            }),
        )?;

        let tx_id_hex = result["tx_id"]
            .as_str()
            .unwrap_or("");
        hex::decode(tx_id_hex)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid tx_id hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        let root_hex = hex::encode(root.to_repr());
        self.rpc_call("lumora_commitRoot", serde_json::json!([root_hex]))?;
        Ok(())
    }

    fn commit_nullifier_epoch_root(
        &self,
        epoch_id: crate::epoch::EpochId,
        root: pallas::Base,
    ) -> Result<(), BridgeError> {
        let root_hex = hex::encode(root.to_repr());
        self.rpc_call(
            "lumora_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": root_hex }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(
        &self,
    ) -> Result<Vec<crate::bridge::RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call(
            "lumora_getRemoteNullifierRoots",
            serde_json::json!([]),
        )?;

        let entries: Vec<serde_json::Value> = serde_json::from_value(result)
            .map_err(|e| BridgeError::NullifierSyncFailed(format!("parse: {e}")))?;

        entries
            .into_iter()
            .map(|e| {
                let chain_id = e["chain_id"].as_u64().unwrap_or(0);
                let epoch_id = e["epoch_id"].as_u64().unwrap_or(0);
                let root_hex = e["root"].as_str().unwrap_or("");
                let root_bytes: [u8; 32] = hex::decode(root_hex)
                    .unwrap_or_else(|_| vec![0u8; 32])
                    .try_into()
                    .unwrap_or([0u8; 32]);
                let root = pallas::Base::from_repr(root_bytes)
                    .unwrap_or(pallas::Base::zero());
                Ok(crate::bridge::RemoteNullifierEpochRoot {
                    chain_id,
                    epoch_id,
                    root,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::LocalBridge;
    use pasta_curves::pallas;

    #[test]
    fn finality_tracker_basic() {
        let mut tracker = DepositFinalityTracker::new(3);
        tracker.observe(vec![1], 10);
        tracker.observe(vec![2], 12);

        assert_eq!(tracker.pending_count(), 2);

        // At height 12, deposit 1 has 2 confirmations (not enough)
        let ready = tracker.finalized(12);
        assert!(ready.is_empty());

        // At height 13, deposit 1 has 3 confirmations (ready)
        let ready = tracker.finalized(13);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], vec![1]);

        // Deposit 2 still pending
        assert_eq!(tracker.pending_count(), 1);
    }

    #[test]
    fn state_root_committer_flush() {
        let bridge = LocalBridge;
        let mut committer = StateRootCommitter::new(bridge, 4);

        committer.queue(pallas::Base::zero());
        committer.queue(pallas::Base::zero());
        assert_eq!(committer.pending_count(), 2);

        let flushed = committer.flush().unwrap();
        assert_eq!(flushed, 2);
        assert_eq!(committer.committed_count(), 2);
        assert_eq!(committer.pending_count(), 0);
    }

    #[test]
    fn atomic_cycle_runs() {
        let listener = MockDepositListener::new();
        let submitter = MockWithdrawalSubmitter::new(100);
        let committer = StateRootCommitter::new(LocalBridge, 10);
        let tracker = DepositFinalityTracker::new(1);

        let mut coordinator =
            AtomicDepositWithdrawal::new(listener, submitter, committer, tracker);

        let (result, finalized) = coordinator.run_cycle(pallas::Base::zero()).unwrap();
        assert_eq!(result.deposits_processed, 0);
        assert_eq!(result.withdrawals_submitted, 0);
        assert_eq!(result.roots_committed, 1);
        assert!(finalized.is_empty());
    }

    #[test]
    fn strata_bridge_defaults() {
        let bridge = StrataBridge::new(StrataConfig::default());
        assert_eq!(bridge.config().confirmations, 6);
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn strata_bridge_custom_transport() {
        use std::cell::RefCell;
        use std::rc::Rc;

        struct RecordingTransport {
            calls: Rc<RefCell<Vec<String>>>,
        }

        impl RpcTransport for RecordingTransport {
            fn send(
                &self,
                _url: &str,
                request: &JsonRpcRequest,
            ) -> Result<JsonRpcResponse, BridgeError> {
                self.calls.borrow_mut().push(request.method.clone());
                let result = match request.method.as_str() {
                    "lumora_getDeposits" => serde_json::json!([]),
                    "lumora_submitWithdrawal" => {
                        serde_json::json!({ "tx_id": "ab".repeat(32) })
                    }
                    "lumora_commitRoot" => serde_json::json!(true),
                    _ => serde_json::json!(null),
                };
                Ok(JsonRpcResponse {
                    id: request.id,
                    result: Some(result),
                    error: None,
                })
            }
        }

        let calls = Rc::new(RefCell::new(vec![]));
        let transport = RecordingTransport {
            calls: Rc::clone(&calls),
        };
        let bridge = StrataBridge::with_transport(StrataConfig::default(), transport);

        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());

        let wd = OutboundWithdrawal {
            amount: 100,
            recipient: [1u8; 32],
            proof_bytes: vec![0xaa; 64],
            nullifiers: [pallas::Base::zero(); 2],
        };
        let tx_id = bridge.execute_withdrawal(&wd).unwrap();
        assert_eq!(tx_id.len(), 32);

        bridge.commit_state_root(pallas::Base::zero()).unwrap();

        let recorded = calls.borrow();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0], "lumora_getDeposits");
        assert_eq!(recorded[1], "lumora_submitWithdrawal");
        assert_eq!(recorded[2], "lumora_commitRoot");
    }

    #[test]
    fn strata_bridge_rpc_error() {
        struct ErrorTransport;

        impl RpcTransport for ErrorTransport {
            fn send(
                &self,
                _url: &str,
                request: &JsonRpcRequest,
            ) -> Result<JsonRpcResponse, BridgeError> {
                Ok(JsonRpcResponse {
                    id: request.id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32600,
                        message: "Invalid Request".into(),
                    }),
                })
            }
        }

        let bridge = StrataBridge::with_transport(StrataConfig::default(), ErrorTransport);
        let err = bridge.poll_deposits().unwrap_err();
        match err {
            BridgeError::ConnectionError(msg) => {
                assert!(msg.contains("-32600"));
                assert!(msg.contains("Invalid Request"));
            }
            _ => panic!("expected ConnectionError"),
        }
    }

    #[test]
    fn mock_withdrawal_submitter() {
        let sub = MockWithdrawalSubmitter::new(50);
        let wd = OutboundWithdrawal {
            amount: 100,
            recipient: [0u8; 32],
            proof_bytes: vec![0; 64],
            nullifiers: [pallas::Base::zero(); 2],
        };
        let receipt = sub.submit(&wd).unwrap();
        assert_eq!(receipt.block_height, 50);
        assert_eq!(receipt.tx_id.len(), 32);
    }
}
