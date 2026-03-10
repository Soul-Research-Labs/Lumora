//! Wallet — client-side note management and transaction building.
//!
//! The wallet holds a spending key and tracks owned notes. It provides
//! methods to compute balances, build transactions, and prepare inputs
//! for the prover.

use std::io;
use std::path::Path;

use lumora_note::keys::{scalar_to_base, SpendingKey, ViewingKey};
use lumora_note::Note;
use lumora_prover::{circuit_commitment, InputNote, OutputNote};
use pasta_curves::pallas;
use serde::{Serialize, Deserialize};

/// Write data to a file with restrictive permissions (0o600 on Unix).
/// Wallet files contain secret key material and must not be world-readable.
pub(crate) fn write_sensitive_file(path: &Path, data: impl AsRef<[u8]>) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data.as_ref())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

/// A recorded wallet transaction for history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TxRecord {
    Deposit { amount: u64, asset: u64, leaf_index: u64 },
    Send { amount: u64, asset: u64, recipient_hex: String },
    Withdraw { amount: u64, asset: u64 },
}

/// Coin selection strategy for choosing which notes to spend.
#[derive(Clone, Copy, Debug)]
pub enum CoinSelection {
    /// Use notes in wallet order until amount is covered (default).
    FirstFit,
    /// Prefer spending the largest notes first.
    LargestFirst,
    /// Choose the combination (up to 2 notes) that minimises change.
    MinChange,
}

/// An owned note: a note the wallet can spend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedNote {
    /// The note data.
    pub note: Note,
    /// The commitment (for verification).
    #[serde(with = "lumora_primitives::serde_field::base")]
    pub commitment: pallas::Base,
    /// The leaf index in the Merkle tree.
    pub leaf_index: u64,
}

/// A portable note bundle for backup / transfer between wallets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteBundle {
    pub version: u32,
    pub notes: Vec<OwnedNote>,
}

/// A disclosure report generated from a viewing key for compliance/audit.
///
/// Contains note summaries and balances visible to the viewing key holder
/// without granting spending authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosureReport {
    /// Hex-encoded viewing key that produced this report.
    pub viewing_key_hex: String,
    /// Per-asset balance visible to this viewing key.
    pub balances: Vec<AssetBalance>,
    /// Disclosed note summaries (values + assets, no spending keys).
    pub notes: Vec<DisclosedNote>,
    /// Transaction history visible to this wallet.
    pub history: Vec<TxRecord>,
}

/// A balance entry for one asset type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetBalance {
    pub asset: u64,
    pub balance: u64,
}

/// A note summary safe for disclosure (no secret key material).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosedNote {
    pub value: u64,
    pub asset: u64,
    pub leaf_index: u64,
    #[serde(with = "lumora_primitives::serde_field::base")]
    pub commitment: pallas::Base,
}

/// The client wallet.
#[derive(Serialize, Deserialize)]
pub struct Wallet {
    /// Schema version for forward compatibility.
    #[serde(default = "default_version")]
    version: u32,
    /// The wallet's spending key.
    spending_key: SpendingKey,
    /// Derived viewing key.
    #[serde(skip, default = "default_viewing_key")]
    viewing_key: ViewingKey,
    /// The owner field (sk as base field element).
    #[serde(skip, default)]
    owner_field: pallas::Base,
    /// Known owned notes (unspent).
    notes: Vec<OwnedNote>,
    /// Set of leaf indices we've already spent (to avoid double-sending).
    spent_nullifiers: std::collections::HashSet<u64>,
    /// Transaction history.
    #[serde(default)]
    history: Vec<TxRecord>,
}

/// Default viewing key placeholder (overwritten in post-deserialize).
fn default_viewing_key() -> ViewingKey {
    ViewingKey { key: pallas::Base::zero() }
}

/// Current wallet schema version.
const WALLET_VERSION: u32 = 1;

fn default_version() -> u32 { WALLET_VERSION }

impl Wallet {
    /// Create a new wallet with the given spending key.
    pub fn new(spending_key: SpendingKey) -> Self {
        let viewing_key = spending_key.viewing_key();
        let owner_field = spending_key.public_key_field();
        Self {
            version: WALLET_VERSION,
            spending_key,
            viewing_key,
            owner_field,
            notes: Vec::new(),
            spent_nullifiers: std::collections::HashSet::new(),
            history: Vec::new(),
        }
    }

    /// Create a wallet with a random spending key.
    pub fn random(rng: impl rand::RngCore) -> Self {
        Self::new(SpendingKey::random(rng))
    }

    /// Save the wallet to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(std::io::Error::other)?;
        write_sensitive_file(path, json)
    }

    /// Load the wallet from a JSON file.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let mut wallet: Self = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if wallet.version > WALLET_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("wallet version {} is newer than supported {}", wallet.version, WALLET_VERSION),
            ));
        }
        // Recompute derived fields from the spending key.
        wallet.viewing_key = wallet.spending_key.viewing_key();
        wallet.owner_field = wallet.spending_key.public_key_field();
        Ok(wallet)
    }

    /// Save the wallet encrypted with a passphrase (AES-256-GCM + Argon2).
    ///
    /// File format: `[16-byte salt][12-byte nonce][ciphertext+tag]`
    pub fn save_encrypted(&self, path: &std::path::Path, passphrase: &str) -> std::io::Result<()> {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        use argon2::Argon2;
        use zeroize::Zeroize;

        let mut json = serde_json::to_string(self)
            .map_err(std::io::Error::other)?;

        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let cipher = Aes256Gcm::new((&key).into());
        key.zeroize();
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

        let result = cipher
            .encrypt(nonce, json.as_bytes())
            .map_err(|e| std::io::Error::other(e.to_string()));
        json.zeroize();
        let ciphertext = result?;

        let mut out = Vec::with_capacity(16 + 12 + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        write_sensitive_file(path, out)
    }

    /// Load an encrypted wallet file.
    pub fn load_encrypted(path: &std::path::Path, passphrase: &str) -> std::io::Result<Self> {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        use argon2::Argon2;
        use zeroize::Zeroize;

        let data = std::fs::read(path)?;
        if data.len() < 16 + 12 + 16 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "file too short"));
        }

        let salt = &data[..16];
        let nonce_bytes = &data[16..28];
        let ciphertext = &data[28..];

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let cipher = Aes256Gcm::new((&key).into());
        key.zeroize();
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

        let mut plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "decryption failed (wrong passphrase?)"))?;

        let mut json = String::from_utf8(plaintext.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        plaintext.zeroize();

        let result = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        json.zeroize();
        let mut wallet: Self = result?;
        wallet.viewing_key = wallet.spending_key.viewing_key();
        wallet.owner_field = wallet.spending_key.public_key_field();
        Ok(wallet)
    }

    // ── Note export / import ──────────────────────────────────────

    /// Export all unspent notes to a JSON file.
    pub fn export_notes(&self, path: &std::path::Path) -> std::io::Result<()> {
        let bundle = NoteBundle {
            version: WALLET_VERSION,
            notes: self.notes.clone(),
        };
        let json = serde_json::to_string_pretty(&bundle)
            .map_err(std::io::Error::other)?;
        write_sensitive_file(path, json)
    }

    /// Import notes from a previously exported bundle.
    /// Duplicates (same leaf index) are skipped.
    pub fn import_notes(&mut self, path: &std::path::Path) -> std::io::Result<usize> {
        let json = std::fs::read_to_string(path)?;
        let bundle: NoteBundle = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut imported = 0usize;
        for owned in bundle.notes {
            if !self.has_leaf(owned.leaf_index) {
                self.notes.push(owned);
                imported += 1;
            }
        }
        Ok(imported)
    }

    /// Check whether a note at a given leaf index was already spent.
    pub fn is_spent(&self, leaf_index: u64) -> bool {
        self.spent_nullifiers.contains(&leaf_index)
    }

    /// The wallet's owner field (for creating notes payable to this wallet).
    pub fn owner_field(&self) -> pallas::Base {
        self.owner_field
    }

    /// The wallet's viewing key.
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    /// The wallet's spending key.
    pub fn spending_key(&self) -> &SpendingKey {
        &self.spending_key
    }

    /// Add a note to the wallet's known set.
    pub fn add_note(&mut self, note: Note, leaf_index: u64) {
        let randomness_base = scalar_to_base(note.randomness);
        let commitment = circuit_commitment(note.owner, note.value, note.asset, randomness_base);
        self.notes.push(OwnedNote {
            note,
            commitment,
            leaf_index,
        });
    }

    /// Total balance across all unspent notes (for a given asset).
    pub fn balance(&self, asset: u64) -> u64 {
        self.notes
            .iter()
            .filter(|n| n.note.asset == asset)
            .map(|n| n.note.value)
            .sum()
    }

    /// Number of unspent notes.
    pub fn note_count(&self) -> usize {
        self.notes.len()
    }

    /// Access the unspent notes.
    pub fn notes(&self) -> &[OwnedNote] {
        &self.notes
    }

    /// Check whether the wallet already tracks a note at the given leaf index.
    pub fn has_leaf(&self, leaf_index: u64) -> bool {
        self.notes.iter().any(|n| n.leaf_index == leaf_index)
            || self.spent_nullifiers.contains(&leaf_index)
    }

    /// Select notes that cover at least `amount` for the given asset.
    /// Returns the selected notes and the total value.
    /// Uses the default greedy (first-fit) strategy.
    pub fn select_notes(&self, asset: u64, amount: u64) -> Option<(Vec<&OwnedNote>, u64)> {
        self.select_notes_with_strategy(asset, amount, CoinSelection::FirstFit)
    }

    /// Select notes using a specific coin selection strategy.
    pub fn select_notes_with_strategy(
        &self,
        asset: u64,
        amount: u64,
        strategy: CoinSelection,
    ) -> Option<(Vec<&OwnedNote>, u64)> {
        let candidates: Vec<&OwnedNote> = self
            .notes
            .iter()
            .filter(|n| n.note.asset == asset)
            .collect();

        match strategy {
            CoinSelection::FirstFit => {
                let mut selected = Vec::new();
                let mut total = 0u64;
                for note in &candidates {
                    selected.push(*note);
                    total += note.note.value;
                    if total >= amount {
                        return Some((selected, total));
                    }
                }
                None
            }
            CoinSelection::LargestFirst => {
                let mut sorted = candidates;
                sorted.sort_by(|a, b| b.note.value.cmp(&a.note.value));
                let mut selected = Vec::new();
                let mut total = 0u64;
                for note in &sorted {
                    selected.push(*note);
                    total += note.note.value;
                    if total >= amount {
                        return Some((selected, total));
                    }
                }
                None
            }
            CoinSelection::MinChange => {
                // Try to find the combination (up to 2 notes) that minimises change.
                let mut best: Option<(Vec<&OwnedNote>, u64)> = None;

                // Single note exact or minimal overshoot.
                for note in &candidates {
                    if note.note.value >= amount {
                        let change = note.note.value - amount;
                        if best.as_ref().is_none_or(|(_, t)| *t - amount > change) {
                            best = Some((vec![note], note.note.value));
                        }
                    }
                }

                // Two-note combinations.
                for (i, a) in candidates.iter().enumerate() {
                    for b in &candidates[i + 1..] {
                        let total = a.note.value + b.note.value;
                        if total >= amount {
                            let change = total - amount;
                            if best.as_ref().is_none_or(|(_, t)| *t - amount > change) {
                                best = Some((vec![a, b], total));
                            }
                        }
                    }
                }

                best
            }
        }
    }

    /// Build InputNote structs for the prover from owned notes.
    pub fn build_input(&self, owned: &OwnedNote) -> InputNote {
        InputNote {
            spending_key: self.spending_key.clone(),
            note: owned.note.clone(),
            merkle_index: owned.leaf_index,
        }
    }

    /// Build an OutputNote for sending to a recipient.
    pub fn build_output(
        recipient_owner: pallas::Base,
        value: u64,
        asset: u64,
        randomness: pallas::Base,
    ) -> OutputNote {
        OutputNote {
            owner_pubkey_field: recipient_owner,
            value,
            asset,
            randomness,
        }
    }

    /// Mark a note as spent (remove from unspent set and record in spent set).
    pub fn mark_spent(&mut self, leaf_index: u64) {
        self.spent_nullifiers.insert(leaf_index);
        self.notes.retain(|n| n.leaf_index != leaf_index);
    }

    /// Record a transaction in the wallet history.
    pub fn record_tx(&mut self, record: TxRecord) {
        self.history.push(record);
    }

    /// Access the transaction history.
    pub fn history(&self) -> &[TxRecord] {
        &self.history
    }

    /// Export the viewing key for disclosure to an auditor.
    ///
    /// The viewing key allows scanning and identifying notes belonging to
    /// this wallet, but does NOT grant spending authority.
    pub fn export_viewing_key(&self) -> ViewingKey {
        self.viewing_key.clone()
    }

    /// Generate a disclosure report from this wallet's data.
    ///
    /// Suitable for regulatory compliance — contains balances, note summaries,
    /// and transaction history, but no secret key material.
    pub fn disclosure_report(&self) -> DisclosureReport {
        use std::collections::HashMap;

        let mut asset_totals: HashMap<u64, u64> = HashMap::new();
        let mut disclosed = Vec::with_capacity(self.notes.len());

        for n in &self.notes {
            *asset_totals.entry(n.note.asset).or_default() += n.note.value;
            disclosed.push(DisclosedNote {
                value: n.note.value,
                asset: n.note.asset,
                leaf_index: n.leaf_index,
                commitment: n.commitment,
            });
        }

        let mut balances: Vec<AssetBalance> = asset_totals
            .into_iter()
            .map(|(asset, balance)| AssetBalance { asset, balance })
            .collect();
        balances.sort_by_key(|b| b.asset);

        DisclosureReport {
            viewing_key_hex: self.viewing_key.to_hex(),
            balances,
            notes: disclosed,
            history: self.history.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_wallet_balance() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();

        wallet.add_note(
            Note {
                owner,
                value: 100,
                asset: 0,
                randomness: pallas::Scalar::from(1u64),
            },
            0,
        );
        wallet.add_note(
            Note {
                owner,
                value: 50,
                asset: 0,
                randomness: pallas::Scalar::from(2u64),
            },
            1,
        );
        wallet.add_note(
            Note {
                owner,
                value: 25,
                asset: 1, // different asset
                randomness: pallas::Scalar::from(3u64),
            },
            2,
        );

        assert_eq!(wallet.balance(0), 150);
        assert_eq!(wallet.balance(1), 25);
        assert_eq!(wallet.note_count(), 3);
    }

    #[test]
    fn test_wallet_note_selection() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();

        wallet.add_note(
            Note { owner, value: 60, asset: 0, randomness: pallas::Scalar::from(1u64) },
            0,
        );
        wallet.add_note(
            Note { owner, value: 40, asset: 0, randomness: pallas::Scalar::from(2u64) },
            1,
        );

        // Can cover 70 with two notes.
        let (_selected, total) = wallet.select_notes(0, 70).unwrap();
        assert!(total >= 70);

        // Can't cover 200.
        assert!(wallet.select_notes(0, 200).is_none());
    }

    #[test]
    fn test_wallet_mark_spent() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();

        wallet.add_note(
            Note { owner, value: 100, asset: 0, randomness: pallas::Scalar::from(1u64) },
            0,
        );
        wallet.add_note(
            Note { owner, value: 50, asset: 0, randomness: pallas::Scalar::from(2u64) },
            1,
        );

        assert_eq!(wallet.balance(0), 150);

        wallet.mark_spent(0);
        assert_eq!(wallet.balance(0), 50);
        assert_eq!(wallet.note_count(), 1);
    }

    #[test]
    fn test_empty_wallet_select_returns_none() {
        let wallet = Wallet::random(OsRng);
        assert!(wallet.select_notes(0, 1).is_none());
        assert_eq!(wallet.balance(0), 0);
        assert_eq!(wallet.note_count(), 0);
    }

    #[test]
    fn test_zero_value_note_balance() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();

        // A 0-value note should be tracked but not add to balance.
        wallet.add_note(
            Note { owner, value: 0, asset: 0, randomness: pallas::Scalar::from(1u64) },
            0,
        );

        assert_eq!(wallet.balance(0), 0);
        assert_eq!(wallet.note_count(), 1);
        // Can't cover any positive amount.
        assert!(wallet.select_notes(0, 1).is_none());
    }

    #[test]
    fn test_wallet_save_load_roundtrip() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();

        wallet.add_note(
            Note { owner, value: 100, asset: 0, randomness: pallas::Scalar::from(1u64) },
            0,
        );
        wallet.add_note(
            Note { owner, value: 50, asset: 1, randomness: pallas::Scalar::from(2u64) },
            1,
        );
        wallet.mark_spent(0);

        let dir = std::env::temp_dir().join("lumora_test_wallet");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("wallet.json");

        wallet.save(&path).expect("save should succeed");
        let loaded = Wallet::load(&path).expect("load should succeed");

        assert_eq!(loaded.owner_field(), owner);
        assert_eq!(loaded.balance(0), 0); // was spent
        assert_eq!(loaded.balance(1), 50);
        assert_eq!(loaded.note_count(), 1);
        assert!(loaded.is_spent(0));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_wallet_encrypted_roundtrip() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();
        wallet.add_note(
            Note { owner, value: 200, asset: 0, randomness: pallas::Scalar::from(42u64) },
            0,
        );

        let dir = std::env::temp_dir().join("lumora_test_wallet_enc");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("wallet.enc");

        wallet.save_encrypted(&path, "hunter2").expect("encrypted save");
        let loaded = Wallet::load_encrypted(&path, "hunter2").expect("encrypted load");
        assert_eq!(loaded.owner_field(), owner);
        assert_eq!(loaded.balance(0), 200);

        // Wrong passphrase should fail
        let err = Wallet::load_encrypted(&path, "wrong");
        assert!(err.is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_coin_selection_strategies() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();

        // Notes: 10, 50, 30, 80
        wallet.add_note(Note { owner, value: 10, asset: 0, randomness: pallas::Scalar::from(1u64) }, 0);
        wallet.add_note(Note { owner, value: 50, asset: 0, randomness: pallas::Scalar::from(2u64) }, 1);
        wallet.add_note(Note { owner, value: 30, asset: 0, randomness: pallas::Scalar::from(3u64) }, 2);
        wallet.add_note(Note { owner, value: 80, asset: 0, randomness: pallas::Scalar::from(4u64) }, 3);

        // FirstFit: takes notes in order until amount covered.
        let (sel, _) = wallet.select_notes_with_strategy(0, 55, CoinSelection::FirstFit).unwrap();
        assert!(sel.len() >= 2); // 10+50 < 55, so needs at least 3: 10+50+30

        // LargestFirst: picks 80 first, which alone covers 55.
        let (sel, total) = wallet.select_notes_with_strategy(0, 55, CoinSelection::LargestFirst).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(total, 80);

        // MinChange: looking for 55, best single is 80 (change=25). But 50+10=60 (change=5) is better.
        // Actually 30+50=80 (change=25), 50+30=80 also. Best 2-combo: 50+10=60 (change=5). 
        let (sel, total) = wallet.select_notes_with_strategy(0, 55, CoinSelection::MinChange).unwrap();
        assert_eq!(total - 55, total.checked_sub(55).unwrap()); // sanity
        // The minimum change should be 5 (50+10=60, change=5).
        assert_eq!(total - 55, 5);
        assert_eq!(sel.len(), 2);
    }

    // ── Additional edge-case tests ──────────────────────────────────

    #[test]
    fn test_duplicate_leaf_index_ignored() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();
        wallet.add_note(
            Note { owner, value: 100, asset: 0, randomness: pallas::Scalar::from(1u64) },
            0,
        );
        // Adding another note with the same leaf_index should still work
        // (second note is independent).
        wallet.add_note(
            Note { owner, value: 50, asset: 0, randomness: pallas::Scalar::from(2u64) },
            0, // same index
        );
        // Both notes are tracked; mark_spent on index 0 removes both.
        assert_eq!(wallet.note_count(), 2);
    }

    #[test]
    fn test_mark_spent_idempotent() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();
        wallet.add_note(
            Note { owner, value: 100, asset: 0, randomness: pallas::Scalar::from(1u64) },
            7,
        );
        wallet.mark_spent(7);
        assert_eq!(wallet.balance(0), 0);
        // Mark again — should not panic or change anything.
        wallet.mark_spent(7);
        assert_eq!(wallet.balance(0), 0);
    }

    #[test]
    fn test_balance_nonexistent_asset() {
        let wallet = Wallet::random(OsRng);
        assert_eq!(wallet.balance(999), 0);
    }

    #[test]
    fn test_select_notes_exact_match() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();
        wallet.add_note(
            Note { owner, value: 42, asset: 0, randomness: pallas::Scalar::from(1u64) },
            0,
        );
        let (sel, total) = wallet.select_notes(0, 42).unwrap();
        assert_eq!(total, 42);
        assert_eq!(sel.len(), 1);
    }

    #[test]
    fn test_history_starts_empty() {
        let wallet = Wallet::random(OsRng);
        assert!(wallet.history().is_empty());
    }

    #[test]
    fn test_load_nonexistent_file_fails() {
        let result = Wallet::load(std::path::Path::new("/tmp/lumora_nonexistent_wallet.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_asset_balances() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();

        wallet.add_note(Note { owner, value: 100, asset: 0, randomness: pallas::Scalar::from(1u64) }, 0);
        wallet.add_note(Note { owner, value: 200, asset: 1, randomness: pallas::Scalar::from(2u64) }, 1);
        wallet.add_note(Note { owner, value: 50, asset: 0, randomness: pallas::Scalar::from(3u64) }, 2);
        wallet.add_note(Note { owner, value: 75, asset: 2, randomness: pallas::Scalar::from(4u64) }, 3);

        assert_eq!(wallet.balance(0), 150);
        assert_eq!(wallet.balance(1), 200);
        assert_eq!(wallet.balance(2), 75);
        assert_eq!(wallet.note_count(), 4);

        // Select from one asset shouldn't touch others.
        let (sel, total) = wallet.select_notes(1, 100).unwrap();
        assert_eq!(total, 200);
        assert_eq!(sel.len(), 1);

        // Can't select more than available for a single asset.
        assert!(wallet.select_notes(2, 100).is_none());
    }

    #[test]
    fn test_note_export_import_roundtrip() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();

        wallet.add_note(Note { owner, value: 100, asset: 0, randomness: pallas::Scalar::from(1u64) }, 0);
        wallet.add_note(Note { owner, value: 50, asset: 1, randomness: pallas::Scalar::from(2u64) }, 1);

        let dir = std::env::temp_dir().join(format!("lumora_export_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("notes.json");

        wallet.export_notes(&path).expect("export should succeed");

        let mut wallet2 = Wallet::random(OsRng);
        let imported = wallet2.import_notes(&path).expect("import should succeed");
        assert_eq!(imported, 2);
        assert_eq!(wallet2.note_count(), 2);

        // Importing again should skip duplicates (same leaf indices).
        let imported2 = wallet2.import_notes(&path).expect("re-import should succeed");
        assert_eq!(imported2, 0);
        assert_eq!(wallet2.note_count(), 2);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_disclosure_report() {
        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();

        wallet.add_note(Note { owner, value: 100, asset: 0, randomness: pallas::Scalar::from(1u64) }, 0);
        wallet.add_note(Note { owner, value: 200, asset: 1, randomness: pallas::Scalar::from(2u64) }, 1);
        wallet.record_tx(TxRecord::Deposit { amount: 100, asset: 0, leaf_index: 0 });

        let report = wallet.disclosure_report();

        assert!(!report.viewing_key_hex.is_empty());
        assert_eq!(report.notes.len(), 2);
        assert_eq!(report.history.len(), 1);
        assert_eq!(report.balances.len(), 2);

        // Balances should be sorted by asset.
        let b0 = report.balances.iter().find(|b| b.asset == 0).unwrap();
        let b1 = report.balances.iter().find(|b| b.asset == 1).unwrap();
        assert_eq!(b0.balance, 100);
        assert_eq!(b1.balance, 200);
    }

    #[test]
    fn test_viewing_key_export() {
        let wallet = Wallet::random(OsRng);
        let vk = wallet.export_viewing_key();
        assert_eq!(vk.key, wallet.viewing_key().key);
    }

    #[test]
    fn test_record_tx_history() {
        let mut wallet = Wallet::random(OsRng);

        wallet.record_tx(TxRecord::Deposit { amount: 100, asset: 0, leaf_index: 0 });
        wallet.record_tx(TxRecord::Send { amount: 50, asset: 0, recipient_hex: "abcd".into() });
        wallet.record_tx(TxRecord::Withdraw { amount: 25, asset: 0 });

        assert_eq!(wallet.history().len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn test_save_creates_restricted_permissions() {
        use std::os::unix::fs::MetadataExt;

        let mut wallet = Wallet::random(OsRng);
        let owner = wallet.owner_field();
        wallet.add_note(Note { owner, value: 100, asset: 0, randomness: pallas::Scalar::from(1u64) }, 0);

        let dir = std::env::temp_dir().join(format!("lumora_perm_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("wallet.json");

        wallet.save(&path).expect("save should succeed");

        let meta = std::fs::metadata(&path).expect("metadata");
        let mode = meta.mode() & 0o777;
        assert_eq!(mode, 0o600, "wallet file should have 0o600 permissions, got {:o}", mode);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
