//! LUMORA Node daemon — the core transaction processor.
//!
//! `LumoraNode` is the main entry point. It wraps:
//! - The privacy pool (on-chain state + verifier params)
//! - Prover params for both transfer and withdrawal circuits
//! - A note store for encrypted note relay
//! - A local Merkle tree mirror for proof generation

use lumora_contracts::{
    ContractError, DepositReceipt, DepositRequest, PrivacyPool, TransferReceipt,
    TransferRequest, WithdrawReceipt, WithdrawRequest,
    BridgeError, OutboundWithdrawal, RollupBridge,
};
use lumora_prover::{
    self, InputNote, OutputNote, ProverParams, WithdrawProverParams,
};
use lumora_tree::IncrementalMerkleTree;
use ff::PrimeField;
use pasta_curves::pallas;

use crate::batch_accumulator::{BatchAccumulator, BatchConfig};
use crate::note_store::{EncryptedNote, NoteStore, RecipientTag};

/// The LUMORA node: state manager, proof generator, and note relay.
pub struct LumoraNode {
    /// The privacy pool (state + verifier keys).
    pub pool: PrivacyPool,
    /// Transfer circuit prover parameters.
    pub transfer_prover: ProverParams,
    /// Withdrawal circuit prover parameters.
    pub withdraw_prover: WithdrawProverParams,
    /// Local Merkle tree mirror (must stay in sync with pool state).
    pub tree: IncrementalMerkleTree,
    /// Encrypted note store for relaying to recipients.
    pub note_store: NoteStore,
    /// Batch accumulator for metadata-resistant transaction submission.
    pub batch: BatchAccumulator,
    /// Optional rollup bridge for host-chain interaction (BitVM, Strata, etc.).
    pub bridge: Option<Box<dyn RollupBridge + Send + Sync>>,
}

impl LumoraNode {
    /// Initialize the node: generate proving/verifying keys for both circuits.
    pub fn init() -> Self {
        let (transfer_prover, transfer_verifier) = lumora_prover::setup().expect("transfer keygen");
        let (withdraw_prover, withdraw_verifier) = lumora_prover::setup_withdraw().expect("withdraw keygen");

        Self {
            pool: PrivacyPool::new(transfer_verifier, withdraw_verifier),
            transfer_prover,
            withdraw_prover,
            tree: IncrementalMerkleTree::new(),
            note_store: NoteStore::new(),
            batch: BatchAccumulator::new(BatchConfig::default()),
            bridge: None,
        }
    }

    /// Initialize the node, loading SRS from a cached file if available.
    ///
    /// If `srs_path` exists, load the SRS and derive keys from it (skipping
    /// SRS generation). Otherwise, generate fresh SRS and save it to disk.
    pub fn init_cached(srs_path: &std::path::Path) -> Self {
        let params = if srs_path.exists() {
            lumora_prover::load_params(srs_path).expect("load cached SRS")
        } else {
            let p = lumora_prover::generate_params();
            lumora_prover::save_params(&p, srs_path).expect("save SRS");
            p
        };

        let (transfer_prover, transfer_verifier) =
            lumora_prover::setup_from_params(params.clone()).expect("transfer keygen");
        let (withdraw_prover, withdraw_verifier) =
            lumora_prover::setup_withdraw_from_params(params).expect("withdraw keygen");

        Self {
            pool: PrivacyPool::new(transfer_verifier, withdraw_verifier),
            transfer_prover,
            withdraw_prover,
            tree: IncrementalMerkleTree::new(),
            note_store: NoteStore::new(),
            batch: BatchAccumulator::new(BatchConfig::default()),
            bridge: None,
        }
    }

    /// Process a deposit: insert commitment into the pool and local tree.
    pub fn deposit(
        &mut self,
        commitment: pallas::Base,
        amount: u64,
    ) -> Result<DepositReceipt, ContractError> {
        // Insert into the Merkle tree first — try_insert returns an error if
        // the tree is full, so we never credit the pool balance for a
        // commitment that has no Merkle path (which would be unspendable).
        self.tree
            .try_insert(commitment)
            .map_err(|_| ContractError::TreeFull)?;
        let receipt = self.pool.deposit(&DepositRequest { commitment, amount })?;
        Ok(receipt)
    }

    /// Insert a zero-value padding commitment for circuit input padding.
    ///
    /// Bypasses deposit validation (min amount) since padding notes carry no
    /// value and don't affect pool balance.
    pub fn insert_padding(&mut self, commitment: pallas::Base) -> DepositReceipt {
        let leaf_index = self.pool.state.insert_commitment(commitment);
        let new_root = self.pool.state.current_root();
        self.tree.insert(commitment);
        DepositReceipt { leaf_index, new_root }
    }

    /// Process a private transfer.
    ///
    /// The node generates the ZK proof and submits it to the pool.
    pub fn transfer(
        &mut self,
        inputs: &[InputNote; 2],
        outputs: &[OutputNote; 2],
        fee: u64,
    ) -> Result<(TransferReceipt, lumora_prover::TransferProof), ContractError> {
        // Generate proof using local tree state.
        let proof = lumora_prover::prove_transfer(
            &self.transfer_prover,
            inputs,
            outputs,
            &mut self.tree,
            fee,
        )
        .map_err(|e| ContractError::ProofError(format!("{e:?}")))?;

        // Submit to pool.
        let receipt = self.pool.transfer(&TransferRequest {
            proof_bytes: proof.proof_bytes.clone(),
            merkle_root: proof.merkle_root,
            nullifiers: proof.nullifiers,
            output_commitments: proof.output_commitments,
            fee,
            domain_chain_id: None,
            domain_app_id: None,
        })?;

        // Update local tree with output commitments.
        for cm in &proof.output_commitments {
            self.tree.try_insert(*cm)
                .map_err(|e| ContractError::ProofError(format!("tree insert failed: {e:?}")))?;
        }

        Ok((receipt, proof))
    }

    /// Process a withdrawal.
    ///
    /// The node generates the withdrawal proof and submits it to the pool.
    pub fn withdraw(
        &mut self,
        inputs: &[InputNote; 2],
        outputs: &[OutputNote; 2],
        exit_value: u64,
        fee: u64,
        recipient: [u8; 32],
    ) -> Result<(WithdrawReceipt, lumora_prover::WithdrawProof), ContractError> {
        let proof = lumora_prover::prove_withdraw(
            &self.withdraw_prover,
            inputs,
            outputs,
            &mut self.tree,
            exit_value,
            fee,
        )
        .map_err(|e| ContractError::ProofError(format!("{e:?}")))?;

        let receipt = self.pool.withdraw(&WithdrawRequest {
            proof_bytes: proof.proof_bytes.clone(),
            merkle_root: proof.merkle_root,
            nullifiers: proof.nullifiers,
            output_commitments: proof.output_commitments,
            amount: exit_value,
            fee,
            recipient,
            domain_chain_id: None,
            domain_app_id: None,
        })?;

        // Update local tree with change commitments.
        for cm in &proof.output_commitments {
            self.tree.try_insert(*cm)
                .map_err(|e| ContractError::ProofError(format!("tree insert failed: {e:?}")))?;
        }

        Ok((receipt, proof))
    }

    /// Store an encrypted note for later retrieval by the recipient.
    pub fn relay_note(&mut self, tag: RecipientTag, note: EncryptedNote) {
        self.note_store.insert(tag, note);
    }

    /// Retrieve encrypted notes for a recipient.
    pub fn get_notes(&self, tag: &RecipientTag) -> &[EncryptedNote] {
        self.note_store.get(tag)
    }

    /// Current pool balance.
    pub fn pool_balance(&self) -> u64 {
        self.pool.state.pool_balance()
    }

    /// Number of commitments in the tree.
    pub fn commitment_count(&self) -> u64 {
        self.pool.state.commitment_count()
    }

    /// Current Merkle root.
    pub fn current_root(&mut self) -> pallas::Base {
        self.pool.state.current_root()
    }

    /// Save all node state to a directory.
    ///
    /// Writes three files:
    /// - `pool_state.json`  — privacy pool state (tree, nullifiers, roots, balance, events)
    /// - `note_store.json`  — encrypted note relay store
    /// - `srs.bin`          — structured reference string (for fast key derivation on restart)
    pub fn save_state(&self, dir: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        self.pool.state.save(&dir.join("pool_state.json"))?;
        self.note_store.save(dir.join("note_store.json"))?;
        lumora_prover::save_params(&self.transfer_prover.params, dir.join("srs.bin"))?;
        Ok(())
    }

    /// Recover a node from previously saved state.
    ///
    /// Re-derives proving/verifying keys from the cached SRS, then restores
    /// pool state and note store from disk.
    pub fn init_recover(dir: &std::path::Path) -> std::io::Result<Self> {
        let params = lumora_prover::load_params(dir.join("srs.bin"))?;
        let mut state = lumora_contracts::PrivacyPoolState::load(&dir.join("pool_state.json"))?;
        let note_store = crate::note_store::NoteStore::load(dir.join("note_store.json"))?;

        let mut tree = state.tree().clone();

        // Verify that the recovered tree root matches the pool's recorded state root.
        // A mismatch indicates on-disk corruption or a partial save; fail fast so
        // the operator can restore from a known-good backup.
        let tree_root = tree.root();
        let state_root = state.current_root();
        if tree_root != state_root {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "State recovery: Merkle tree root does not match pool state root — \
                     data may be corrupt. tree_root={tree_root:?} state_root={state_root:?}"
                ),
            ));
        }

        let (transfer_prover, transfer_verifier) =
            lumora_prover::setup_from_params(params.clone())
                .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let (withdraw_prover, withdraw_verifier) =
            lumora_prover::setup_withdraw_from_params(params)
                .map_err(|e| std::io::Error::other(format!("{e:?}")))?;

        Ok(Self {
            pool: PrivacyPool::new_with_state(state, transfer_verifier, withdraw_verifier),
            transfer_prover,
            withdraw_prover,
            tree,
            note_store,
            batch: BatchAccumulator::new(BatchConfig::default()),
            bridge: None,
        })
    }

    /// Set the rollup bridge implementation.
    pub fn set_bridge(&mut self, bridge: Box<dyn RollupBridge + Send + Sync>) {
        self.bridge = Some(bridge);
    }

    /// Poll the host chain for new deposits and insert them into the pool.
    ///
    /// Returns the number of deposits processed.
    pub fn poll_bridge_deposits(&mut self) -> Result<usize, BridgeError> {
        let bridge = match &self.bridge {
            Some(b) => b,
            None => return Ok(0),
        };
        let deposits = bridge.poll_deposits()?;
        let count = deposits.len();
        for dep in &deposits {
            // Insert into the tree first — if the tree is full, we must not
            // credit the pool for a commitment that has no Merkle path.
            self.tree.try_insert(dep.commitment).map_err(|_| {
                BridgeError::DepositRejected(format!(
                    "tree full when inserting commitment {}",
                    hex::encode(dep.commitment.to_repr())
                ))
            })?;
            match self.pool.deposit(&DepositRequest {
                commitment: dep.commitment,
                amount: dep.amount,
            }) {
                Ok(_) => {}
                Err(e) => {
                    // A deposit error means the pool and tree have diverged;
                    // propagate as a bridge error so the caller can stop and
                    // perform reconciliation rather than silently continuing.
                    return Err(BridgeError::DepositRejected(
                        format!("deposit commitment {} failed: {e}", hex::encode(dep.commitment.to_repr()))
                    ));
                }
            }
        }
        Ok(count)
    }

    /// Commit the current Merkle root to the host chain via the bridge.
    pub fn commit_root_to_bridge(&mut self) -> Result<(), BridgeError> {
        let bridge = match &self.bridge {
            Some(b) => b,
            None => return Ok(()),
        };
        let root = self.pool.state.current_root();
        bridge.commit_state_root(root)
    }

    /// Execute a withdrawal on the host chain via the bridge.
    pub fn bridge_withdrawal(
        &self,
        withdrawal: &OutboundWithdrawal,
    ) -> Result<Vec<u8>, BridgeError> {
        let bridge = match &self.bridge {
            Some(b) => b,
            None => return Err(BridgeError::ConnectionError("no bridge configured".into())),
        };
        bridge.execute_withdrawal(withdrawal)
    }

    /// Whether a rollup bridge is currently configured.
    pub fn has_bridge(&self) -> bool {
        self.bridge.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lumora_note::keys::scalar_to_base;
    use lumora_note::{Note, SpendingKey};
    use lumora_prover::circuit_commitment;

    #[test]
    fn test_node_deposit() {
        let mut node = LumoraNode::init();

        let sk_base = pallas::Base::from(42u64);
        let randomness = pallas::Base::from(999u64);
        let cm = circuit_commitment(sk_base, 100, 0, randomness);

        let receipt = node.deposit(cm, 100).expect("deposit should succeed");
        assert_eq!(receipt.leaf_index, 0);
        assert_eq!(node.pool_balance(), 100);
        assert_eq!(node.commitment_count(), 1);
    }

    #[test]
    fn test_node_deposit_transfer_cycle() {
        let mut node = LumoraNode::init();

        // Create keys.
        let sk_alice = SpendingKey::random(&mut rand::rngs::OsRng);
        let sk_alice_base = scalar_to_base(sk_alice.inner());
        let sk_bob = SpendingKey::random(&mut rand::rngs::OsRng);
        let sk_bob_base = scalar_to_base(sk_bob.inner());

        let r1_scalar = pallas::Scalar::from(111u64);
        let r2_scalar = pallas::Scalar::from(222u64);
        let r1 = scalar_to_base(r1_scalar);
        let r2 = scalar_to_base(r2_scalar);

        // Deposit two notes for Alice (each >= MIN_DEPOSIT_AMOUNT).
        let cm1 = circuit_commitment(sk_alice_base, 600, 0, r1);
        let cm2 = circuit_commitment(sk_alice_base, 400, 0, r2);

        node.deposit(cm1, 600).unwrap();
        node.deposit(cm2, 400).unwrap();
        assert_eq!(node.pool_balance(), 1000);

        // Transfer: Alice sends 700 to Bob, 300 change.
        let r_out1 = pallas::Base::from(333u64);
        let r_out2 = pallas::Base::from(444u64);

        let inputs = [
            InputNote {
                spending_key: sk_alice.clone(),
                note: Note {
                    owner: sk_alice_base,
                    value: 600,
                    asset: 0,
                    randomness: r1_scalar,
                },
                merkle_index: 0,
            },
            InputNote {
                spending_key: sk_alice.clone(),
                note: Note {
                    owner: sk_alice_base,
                    value: 400,
                    asset: 0,
                    randomness: r2_scalar,
                },
                merkle_index: 1,
            },
        ];

        let outputs = [
            OutputNote {
                owner_pubkey_field: sk_bob_base,
                value: 700,
                asset: 0,
                randomness: r_out1,
            },
            OutputNote {
                owner_pubkey_field: sk_alice_base,
                value: 300,
                asset: 0,
                randomness: r_out2,
            },
        ];

        let (receipt, _proof) = node.transfer(&inputs, &outputs, 0).expect("transfer should succeed");
        assert_eq!(node.pool_balance(), 1000);
        assert_eq!(node.commitment_count(), 4);
        assert_eq!(receipt.leaf_indices[0], 2);
        assert_eq!(receipt.leaf_indices[1], 3);
    }

    #[test]
    fn test_node_full_cycle_with_withdraw() {
        let mut node = LumoraNode::init();

        let sk_alice = SpendingKey::random(&mut rand::rngs::OsRng);
        let sk_alice_base = scalar_to_base(sk_alice.inner());

        let r1_scalar = pallas::Scalar::from(111u64);
        let r2_scalar = pallas::Scalar::from(222u64);
        let r1 = scalar_to_base(r1_scalar);
        let r2 = scalar_to_base(r2_scalar);

        // Deposit 1000 total (each >= MIN_DEPOSIT_AMOUNT).
        let cm1 = circuit_commitment(sk_alice_base, 600, 0, r1);
        let cm2 = circuit_commitment(sk_alice_base, 400, 0, r2);

        node.deposit(cm1, 600).unwrap();
        node.deposit(cm2, 400).unwrap();
        assert_eq!(node.pool_balance(), 1000);

        // Withdraw 700, change 300.
        let r_out1 = pallas::Base::from(333u64);
        let r_out2 = pallas::Base::from(444u64);

        let inputs = [
            InputNote {
                spending_key: sk_alice.clone(),
                note: Note {
                    owner: sk_alice_base,
                    value: 600,
                    asset: 0,
                    randomness: r1_scalar,
                },
                merkle_index: 0,
            },
            InputNote {
                spending_key: sk_alice.clone(),
                note: Note {
                    owner: sk_alice_base,
                    value: 400,
                    asset: 0,
                    randomness: r2_scalar,
                },
                merkle_index: 1,
            },
        ];

        let outputs = [
            OutputNote {
                owner_pubkey_field: sk_alice_base,
                value: 300,
                asset: 0,
                randomness: r_out1,
            },
            OutputNote {
                owner_pubkey_field: sk_alice_base,
                value: 0,
                asset: 0,
                randomness: r_out2,
            },
        ];

        let recipient = [42u8; 32];
        let (receipt, _proof) = node
            .withdraw(&inputs, &outputs, 700, 0, recipient)
            .expect("withdraw should succeed");

        assert_eq!(receipt.amount, 700);
        assert_eq!(node.pool_balance(), 300);
        assert_eq!(node.commitment_count(), 4); // 2 deposits + 2 change notes
    }
}
