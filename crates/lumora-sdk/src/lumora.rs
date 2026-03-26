//! `Lumora` — the unified orchestrator.
//!
//! Combines a `LumoraNode` (prover/verifier/pool) with a `Wallet` (key
//! management, note tracking) into one ergonomic struct.
//!
//! ```text
//!   Lumora::init()
//!     .deposit(100)
//!     .send(recipient, 70)
//!     .withdraw(30, address)
//! ```

use ff::{Field, PrimeField};
use lumora_client::wallet::{Wallet, TxRecord};
use lumora_contracts::{ContractError, DepositReceipt, TransferReceipt, WithdrawReceipt};
use lumora_note::encryption;
use lumora_note::keys::{recipient_tag, scalar_to_base, ViewingKey};
use lumora_note::{Note, SpendingKey};
use lumora_node::daemon::LumoraNode;
use lumora_node::note_store::EncryptedNote;
use lumora_prover::{circuit_commitment, TransferProof, WithdrawProof};
use pasta_curves::pallas;
use rand::rngs::OsRng;

/// High-level privacy coprocessor handle.
///
/// Holds a node (proving infrastructure + pool state) and a user-facing wallet.
pub struct Lumora {
    /// The backend node that generates proofs and manages the pool.
    pub node: LumoraNode,
    /// The user's wallet (key material + note tracking).
    pub wallet: Wallet,
}

/// Result of a successful send (private transfer).
pub struct SendResult {
    pub receipt: TransferReceipt,
    pub proof: TransferProof,
    /// Recipient tag for note store lookup (so the receiver can find their note).
    pub recipient_tag: [u8; 32],
}

/// Result of a successful withdraw.
pub struct WithdrawResult {
    pub receipt: WithdrawReceipt,
    pub proof: WithdrawProof,
}

/// Result of a successful stealth send.
pub struct StealthSendResult {
    pub receipt: TransferReceipt,
    pub proof: TransferProof,
    /// Stealth metadata the sender must share with the recipient.
    pub stealth_meta: lumora_note::StealthMeta,
}

impl Lumora {
    /// Initialise a new Lumora instance with a random wallet.
    ///
    /// This runs key generation for both circuits — expensive, do it once.
    pub fn init() -> Self {
        Self {
            node: LumoraNode::init(),
            wallet: Wallet::random(OsRng),
        }
    }

    /// Initialise with an existing spending key.
    pub fn init_with_key(spending_key: SpendingKey) -> Self {
        Self {
            node: LumoraNode::init(),
            wallet: Wallet::new(spending_key),
        }
    }

    /// Current pool balance.
    pub fn pool_balance(&self) -> u64 {
        self.node.pool_balance()
    }

    /// Current Merkle root of the commitment tree.
    pub fn merkle_root(&mut self) -> pallas::Base {
        self.node.current_root()
    }

    /// Number of commitments in the tree.
    pub fn commitment_count(&self) -> u64 {
        self.node.commitment_count()
    }

    /// Check whether a nullifier has already been spent.
    pub fn is_nullifier_spent(&self, nullifier: pallas::Base) -> bool {
        self.node.pool.state.is_nullifier_spent(nullifier)
    }

    /// Enumerate unspent notes in the wallet.
    pub fn notes(&self) -> &[lumora_client::wallet::OwnedNote] {
        self.wallet.notes()
    }

    /// Wallet balance for the native asset.
    pub fn balance(&self) -> u64 {
        self.wallet.balance(0)
    }

    /// Wallet balance for a specific asset.
    pub fn balance_of(&self, asset: u64) -> u64 {
        self.wallet.balance(asset)
    }

    /// Deposit funds into the pool and track the resulting note.
    ///
    /// Creates a note owned by this wallet, deposits its commitment,
    /// and adds the note to the wallet.
    pub fn deposit(&mut self, value: u64) -> Result<DepositReceipt, ContractError> {
        self.deposit_asset(value, 0)
    }

    /// Deposit a specific asset into the pool.
    pub fn deposit_asset(
        &mut self,
        value: u64,
        asset: u64,
    ) -> Result<DepositReceipt, ContractError> {
        let owner = self.wallet.owner_field();
        let randomness = pallas::Scalar::random(&mut OsRng);
        let randomness_base = scalar_to_base(randomness);
        let commitment = circuit_commitment(owner, value, asset, randomness_base);

        let receipt = self.node.deposit(commitment, value)?;

        // Track the note in the wallet.
        let note = Note {
            owner,
            value,
            asset,
            randomness,
        };
        self.wallet.add_note(note, receipt.leaf_index);

        self.wallet.record_tx(TxRecord::Deposit {
            amount: value,
            asset,
            leaf_index: receipt.leaf_index,
        });

        Ok(receipt)
    }

    /// Send `amount` of the native asset to a recipient.
    ///
    /// Selects notes, builds a 2-in-2-out transfer (with change back to self),
    /// generates a ZK proof, and submits it.
    ///
    /// `recipient` is the recipient's owner field (for the commitment).
    /// `recipient_pk` is the recipient's EC public key (for ECIES encryption).
    pub fn send(
        &mut self,
        recipient: pallas::Base,
        recipient_pk: pallas::Point,
        amount: u64,
    ) -> Result<SendResult, ContractError> {
        self.send_asset(recipient, recipient_pk, amount, 0)
    }

    /// Send `amount` of a specific asset.
    pub fn send_asset(
        &mut self,
        recipient: pallas::Base,
        recipient_pk: pallas::Point,
        amount: u64,
        asset: u64,
    ) -> Result<SendResult, ContractError> {
        // Collect selected notes into owned data to free the borrow on self.wallet.
        let (selected, total) = self
            .wallet
            .select_notes(asset, amount)
            .ok_or(ContractError::InsufficientPoolBalance)?;
        let selected_owned: Vec<_> = selected.into_iter().cloned().collect();

        let (input0, input1) = self.pad_inputs(&selected_owned)?;

        let change = total - amount;
        let r_recv_scalar = pallas::Scalar::random(&mut OsRng);
        let r_change_scalar = pallas::Scalar::random(&mut OsRng);
        let r_recv = scalar_to_base(r_recv_scalar);
        let r_change = scalar_to_base(r_change_scalar);

        let outputs = [
            Wallet::build_output(recipient, amount, asset, r_recv),
            Wallet::build_output(self.wallet.owner_field(), change, asset, r_change),
        ];

        let inputs = [input0, input1];
        let (receipt, proof) = self.node.transfer(&inputs, &outputs, 0)?;

        for sel in &selected_owned {
            self.wallet.mark_spent(sel.leaf_index);
        }

        if change > 0 {
            let change_note = Note {
                owner: self.wallet.owner_field(),
                value: change,
                asset,
                randomness: r_change_scalar,
            };
            self.wallet
                .add_note(change_note, receipt.leaf_indices[1]);
        }

        // Encrypt the recipient's note and relay it via the note store.
        let tag = recipient_tag(recipient);
        let (eph_pk, ciphertext) = encryption::encrypt_note(
            recipient_pk,
            amount,
            asset,
            r_recv_scalar,
            OsRng,
        ).ok_or(ContractError::ProofError("recipient public key is identity point".into()))?;
        let commitment_bytes = proof.output_commitments[0].to_repr();
        self.node.relay_note(tag, EncryptedNote {
            leaf_index: receipt.leaf_indices[0],
            commitment: commitment_bytes,
            ciphertext,
            ephemeral_pubkey: eph_pk,
        });

        self.wallet.record_tx(TxRecord::Send {
            amount,
            asset,
            recipient_hex: hex::encode(recipient.to_repr()),
        });

        Ok(SendResult { receipt, proof, recipient_tag: tag })
    }

    /// Send `amount` to a stealth address derived from the recipient's public key.
    ///
    /// Returns a `StealthSendResult` containing the transfer proof and the
    /// `StealthMeta` that the sender must share with the recipient (e.g. via
    /// an out-of-band channel or the note store) so they can detect the note.
    pub fn send_stealth(
        &mut self,
        recipient_pk: pallas::Point,
        amount: u64,
    ) -> Result<StealthSendResult, ContractError> {
        self.send_stealth_asset(recipient_pk, amount, 0)
    }

    /// Send `amount` of a specific asset to a stealth address.
    pub fn send_stealth_asset(
        &mut self,
        recipient_pk: pallas::Point,
        amount: u64,
        asset: u64,
    ) -> Result<StealthSendResult, ContractError> {
        let (one_time_owner, stealth_meta) =
            lumora_note::keys::stealth_send(recipient_pk, OsRng)
            .ok_or(ContractError::ProofError("stealth send: identity point".into()))?;

        let result = self.send_asset(one_time_owner, recipient_pk, amount, asset)?;

        Ok(StealthSendResult {
            receipt: result.receipt,
            proof: result.proof,
            stealth_meta,
        })
    }

    // ── Consolidation (sweep) ───────────────────────────────────────

    /// Consolidate small notes by performing a self-send.
    ///
    /// Merges up to 2 notes whose value is below `threshold` into a single
    /// output note.  Returns the number of consolidation rounds performed.
    /// Call repeatedly until it returns 0 to fully sweep dust.
    pub fn consolidate(
        &mut self,
        asset: u64,
        threshold: u64,
    ) -> Result<usize, ContractError> {
        let mut rounds = 0usize;
        loop {
            // Collect dust candidates.
            let dust: Vec<_> = self
                .wallet
                .notes()
                .iter()
                .filter(|n| n.note.asset == asset && n.note.value < threshold)
                .take(2)
                .cloned()
                .collect();

            if dust.len() < 2 {
                break;
            }

            let total: u64 = dust.iter().map(|n| n.note.value).sum();
            let (input0, input1) = self.pad_inputs(&dust)?;

            let r_scalar = pallas::Scalar::random(&mut OsRng);
            let r_base = scalar_to_base(r_scalar);

            // Single meaningful output + a zero-value padding output.
            let outputs = [
                Wallet::build_output(self.wallet.owner_field(), total, asset, r_base),
                Wallet::build_output(
                    self.wallet.owner_field(),
                    0,
                    asset,
                    scalar_to_base(pallas::Scalar::random(&mut OsRng)),
                ),
            ];

            let (receipt, _proof) = self.node.transfer(&[input0, input1], &outputs, 0)?;

            for d in &dust {
                self.wallet.mark_spent(d.leaf_index);
            }

            let merged = Note {
                owner: self.wallet.owner_field(),
                value: total,
                asset,
                randomness: r_scalar,
            };
            self.wallet.add_note(merged, receipt.leaf_indices[0]);
            self.wallet.record_tx(TxRecord::Send {
                amount: total,
                asset,
                recipient_hex: "self-consolidation".into(),
            });

            rounds += 1;
        }
        Ok(rounds)
    }

    /// Withdraw `amount` of the native asset to an external recipient.
    pub fn withdraw(
        &mut self,
        amount: u64,
        recipient: [u8; 32],
    ) -> Result<WithdrawResult, ContractError> {
        self.withdraw_asset(amount, 0, recipient)
    }

    /// Withdraw `amount` of a specific asset.
    pub fn withdraw_asset(
        &mut self,
        amount: u64,
        asset: u64,
        recipient: [u8; 32],
    ) -> Result<WithdrawResult, ContractError> {
        let (selected, total) = self
            .wallet
            .select_notes(asset, amount)
            .ok_or(ContractError::InsufficientPoolBalance)?;
        let selected_owned: Vec<_> = selected.into_iter().cloned().collect();

        let (input0, input1) = self.pad_inputs(&selected_owned)?;

        let change = total - amount;
        let r_change0_scalar = pallas::Scalar::random(&mut OsRng);
        let r_change1_scalar = pallas::Scalar::random(&mut OsRng);
        let r_change0 = scalar_to_base(r_change0_scalar);
        let r_change1 = scalar_to_base(r_change1_scalar);

        let outputs = [
            Wallet::build_output(self.wallet.owner_field(), change, asset, r_change0),
            Wallet::build_output(self.wallet.owner_field(), 0, asset, r_change1),
        ];

        let inputs = [input0, input1];
        let (receipt, proof) = self.node.withdraw(&inputs, &outputs, amount, 0, recipient)?;

        for sel in &selected_owned {
            self.wallet.mark_spent(sel.leaf_index);
        }

        if change > 0 {
            let change_note = Note {
                owner: self.wallet.owner_field(),
                value: change,
                asset,
                randomness: r_change0_scalar,
            };
            self.wallet
                .add_note(change_note, receipt.change_leaf_indices[0]);
        }

        self.wallet.record_tx(TxRecord::Withdraw { amount, asset });

        Ok(WithdrawResult { receipt, proof })
    }

    // ── Note Scanning ─────────────────────────────────────────────────

    /// Scan the node's note store for notes addressed to this wallet.
    ///
    /// Uses the wallet's viewing key to compute the recipient tag, queries
    /// stored encrypted notes, attempts decryption, and adds any newly
    /// discovered notes to the wallet.  Returns the number of new notes found.
    pub fn scan_notes(&mut self) -> usize {
        let tag = self.wallet.viewing_key().tag();
        let encrypted = self.node.get_notes(&tag);
        let sk = self.wallet.spending_key().inner();

        let mut found = 0;
        for enc in encrypted {
            // Skip notes we already own.
            if self.wallet.has_leaf(enc.leaf_index) {
                continue;
            }

            if let Some((value, asset, randomness)) =
                encryption::decrypt_note(sk, &enc.ephemeral_pubkey, &enc.ciphertext)
            {
                let note = Note {
                    owner: self.wallet.owner_field(),
                    value,
                    asset,
                    randomness,
                };
                self.wallet.add_note(note, enc.leaf_index);
                found += 1;
            }
        }
        found
    }

    /// Export the wallet's viewing key for disclosure to an auditor or regulator.
    ///
    /// The viewing key allows the recipient to scan the note store and identify
    /// notes belonging to this wallet, but does **not** grant spending authority.
    pub fn disclose_viewing_key(&self) -> ViewingKey {
        self.wallet.export_viewing_key()
    }

    /// Generate a compliance disclosure report.
    ///
    /// Returns balances, note summaries, and transaction history — suitable for
    /// sharing with an auditor without revealing spending key material.
    pub fn disclosure_report(&self) -> lumora_client::wallet::DisclosureReport {
        self.wallet.disclosure_report()
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Pad selected notes to exactly 2 inputs.
    ///
    /// If only 1 note is selected, we deposit a zero-value dummy note first
    /// so the circuit always has 2 inputs.
    fn pad_inputs(
        &mut self,
        selected: &[lumora_client::wallet::OwnedNote],
    ) -> Result<(lumora_prover::InputNote, lumora_prover::InputNote), ContractError> {
        match selected.len() {
            1 => {
                let owner = self.wallet.owner_field();
                let pad_rand = pallas::Scalar::random(&mut OsRng);
                let pad_rand_base = scalar_to_base(pad_rand);
                let pad_cm = circuit_commitment(owner, 0, 0, pad_rand_base);
                let pad_receipt = self.node.insert_padding(pad_cm);

                let pad_note = Note {
                    owner,
                    value: 0,
                    asset: 0,
                    randomness: pad_rand,
                };
                self.wallet.add_note(pad_note.clone(), pad_receipt.leaf_index);

                let i0 = self.wallet.build_input(&selected[0]);
                let pad_owned = lumora_client::wallet::OwnedNote {
                    note: pad_note,
                    commitment: pad_cm,
                    leaf_index: pad_receipt.leaf_index,
                };
                let i1 = self.wallet.build_input(&pad_owned);

                self.wallet.mark_spent(pad_receipt.leaf_index);

                Ok((i0, i1))
            }
            2 => {
                let i0 = self.wallet.build_input(&selected[0]);
                let i1 = self.wallet.build_input(&selected[1]);
                Ok((i0, i1))
            }
            _ => Err(ContractError::TooManyInputNotes),
        }
    }

    /// Save the full node state (pool, notes, SRS) and wallet to a directory.
    pub fn save_state(&self, dir: &std::path::Path) -> std::io::Result<()> {
        self.node.save_state(dir)?;
        self.wallet.save(&dir.join("wallet.json"))
    }

    /// Recover from previously saved state.
    ///
    /// Loads the node (pool state, note store, SRS → re-derives keys) and
    /// wallet from the given directory.
    pub fn init_recover(dir: &std::path::Path) -> std::io::Result<Self> {
        let node = LumoraNode::init_recover(dir)?;
        let wallet = Wallet::load(&dir.join("wallet.json"))?;
        Ok(Self { node, wallet })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_and_balance() {
        let mut lumora = Lumora::init();
        assert_eq!(lumora.balance(), 0);
        assert_eq!(lumora.pool_balance(), 0);

        let receipt = lumora.deposit(100).expect("deposit");
        assert_eq!(receipt.leaf_index, 0);
        assert_eq!(lumora.balance(), 100);
        assert_eq!(lumora.pool_balance(), 100);
    }

    #[test]
    fn test_deposit_send_cycle() {
        let mut lumora = Lumora::init();

        // Deposit two notes to satisfy the 2-input circuit.
        lumora.deposit(600).expect("deposit 600");
        lumora.deposit(400).expect("deposit 400");
        assert_eq!(lumora.balance(), 1000);

        // Send 700 to a recipient.
        let recipient_sk = SpendingKey::from_scalar(pallas::Scalar::from(0xBEEFu64));
        let recipient = recipient_sk.public_key_field();
        let recipient_pk = recipient_sk.public_key();
        let send_result = lumora.send(recipient, recipient_pk, 700).expect("send 700");
        assert_eq!(send_result.receipt.leaf_indices.len(), 2);

        // Wallet should have the 300 change note.
        assert_eq!(lumora.balance(), 300);
        // Pool balance unchanged (private transfer).
        assert_eq!(lumora.pool_balance(), 1000);

        // Verify the encrypted note was relayed.
        let tag = lumora_note::keys::recipient_tag(recipient);
        assert_eq!(lumora.node.get_notes(&tag).len(), 1);
    }

    #[test]
    fn test_deposit_send_withdraw_cycle() {
        let mut lumora = Lumora::init();

        lumora.deposit(600).expect("d1");
        lumora.deposit(400).expect("d2");
        assert_eq!(lumora.balance(), 1000);

        // Send 700 to some recipient.
        let recipient_sk = SpendingKey::from_scalar(pallas::Scalar::from(0xCAFEu64));
        let recipient = recipient_sk.public_key_field();
        let recipient_pk = recipient_sk.public_key();
        lumora.send(recipient, recipient_pk, 700).expect("send");
        assert_eq!(lumora.balance(), 300);

        // Need a second note for the 2-input circuit.
        lumora.deposit(200).expect("d3");
        assert_eq!(lumora.balance(), 500);

        // Withdraw 500.
        let addr = [0xABu8; 32];
        let wr = lumora.withdraw(500, addr).expect("withdraw");
        assert_eq!(wr.receipt.amount, 500);
        // After withdrawing exactly everything, balance is 0.
        assert_eq!(lumora.balance(), 0);
        assert_eq!(lumora.pool_balance(), 700); // 1200 deposited - 500 withdrawn
    }

    #[test]
    fn test_scan_notes_discovers_incoming() {
        let mut lumora = Lumora::init();

        // Deposit so sender has funds.
        lumora.deposit(600).expect("d1");
        lumora.deposit(400).expect("d2");

        // Create a recipient wallet (separate key).
        let recipient_sk = SpendingKey::from_scalar(pallas::Scalar::from(0xFACEu64));
        let recipient = recipient_sk.public_key_field();
        let recipient_pk = recipient_sk.public_key();

        // Send 500 to the recipient — encrypted note is relayed to the node.
        lumora.send(recipient, recipient_pk, 500).expect("send 500");

        // Now simulate the recipient scanning: replace the wallet with the
        // recipient's key and scan for notes.
        lumora.wallet = Wallet::new(recipient_sk);
        let found = lumora.scan_notes();
        assert_eq!(found, 1);
        assert_eq!(lumora.balance_of(0), 500);
    }

    #[test]
    fn test_stealth_send_and_receive() {
        let mut lumora = Lumora::init();
        lumora.deposit(600).expect("d1");
        lumora.deposit(400).expect("d2");

        // Recipient key pair.
        let recipient_sk = SpendingKey::from_scalar(pallas::Scalar::from(0xDEADu64));
        let recipient_pk = recipient_sk.public_key();

        // Stealth send 300.
        let result = lumora.send_stealth(recipient_pk, 300).expect("stealth send");
        assert_eq!(result.receipt.leaf_indices.len(), 2);
        assert_eq!(lumora.balance(), 700); // 1000 - 300

        // Stealth meta should be populated.
        let meta = &result.stealth_meta;
        // Recipient can detect the one-time address.
        assert!(recipient_sk.stealth_receive(meta).is_some());
    }

    #[test]
    fn test_stealth_send_non_recipient_cannot_detect() {
        let mut lumora = Lumora::init();
        lumora.deposit(600).expect("d1");
        lumora.deposit(400).expect("d2");

        let recipient_sk = SpendingKey::from_scalar(pallas::Scalar::from(0xBEEFu64));
        let bystander_sk = SpendingKey::from_scalar(pallas::Scalar::from(0xCAFEu64));

        let result = lumora
            .send_stealth(recipient_sk.public_key(), 200)
            .expect("stealth send");

        // Bystander cannot detect the note.
        assert!(bystander_sk.stealth_receive(&result.stealth_meta).is_none());
        // Recipient can.
        assert!(recipient_sk.stealth_receive(&result.stealth_meta).is_some());
    }

    #[test]
    fn test_disclosure_report() {
        let mut lumora = Lumora::init();
        lumora.deposit(500).expect("d1");
        let report = lumora.disclosure_report();
        // The report should have at least one balance entry.
        assert!(!report.balances.is_empty());
    }
}
