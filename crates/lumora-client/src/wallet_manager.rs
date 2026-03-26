//! Multi-wallet manager — support for per-user wallet contexts.
//!
//! Allows a single node/SDK instance to manage multiple wallets,
//! each identified by a string label (e.g., username or account ID).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use lumora_note::keys::SpendingKey;

use crate::wallet::Wallet;

/// Manages multiple named wallet instances.
///
/// Each wallet is stored in a separate file under a base directory,
/// keyed by a string label.
pub struct WalletManager {
    /// Base directory for wallet files.
    base_dir: PathBuf,
    /// In-memory wallet cache.
    wallets: HashMap<String, Wallet>,
}

impl WalletManager {
    /// Create a new wallet manager with the given base directory.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
            wallets: HashMap::new(),
        }
    }

    /// Create a new wallet with a random spending key.
    ///
    /// Returns an error if a wallet with this label already exists.
    pub fn create_wallet(&mut self, label: &str) -> Result<&Wallet, WalletManagerError> {
        if self.wallets.contains_key(label) || self.wallet_path(label).exists() {
            return Err(WalletManagerError::AlreadyExists(label.to_string()));
        }

        let wallet = Wallet::random(rand::rngs::OsRng);
        self.wallets.insert(label.to_string(), wallet);
        Ok(&self.wallets[label])
    }

    /// Get a wallet by label, loading from disk if not cached.
    pub fn get_wallet(&mut self, label: &str) -> Result<&Wallet, WalletManagerError> {
        if !self.wallets.contains_key(label) {
            self.load_wallet(label)?;
        }
        Ok(&self.wallets[label])
    }

    /// Get a mutable reference to a wallet by label.
    pub fn get_wallet_mut(&mut self, label: &str) -> Result<&mut Wallet, WalletManagerError> {
        if !self.wallets.contains_key(label) {
            self.load_wallet(label)?;
        }
        Ok(self.wallets.get_mut(label).unwrap())
    }

    /// Save a specific wallet to disk.
    pub fn save_wallet(&self, label: &str) -> Result<(), WalletManagerError> {
        let wallet = self.wallets.get(label)
            .ok_or_else(|| WalletManagerError::NotFound(label.to_string()))?;
        let path = self.wallet_path(label);
        let json = serde_json::to_string_pretty(wallet)
            .map_err(|e| WalletManagerError::Io(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| WalletManagerError::Io(e.to_string()))?;
        }
        crate::wallet::write_sensitive_file(&path, json)
            .map_err(|e| WalletManagerError::Io(e.to_string()))?;
        Ok(())
    }

    /// Save all loaded wallets to disk.
    pub fn save_all(&self) -> Result<(), WalletManagerError> {
        for label in self.wallets.keys() {
            self.save_wallet(label)?;
        }
        Ok(())
    }

    /// List all wallet labels (from both cache and disk).
    pub fn list_wallets(&self) -> Result<Vec<String>, WalletManagerError> {
        let mut labels: Vec<String> = self.wallets.keys().cloned().collect();

        // Also check disk for wallets not in cache
        if self.base_dir.exists() {
            let entries = std::fs::read_dir(&self.base_dir)
                .map_err(|e| WalletManagerError::Io(e.to_string()))?;
            for entry in entries {
                let entry = entry.map_err(|e| WalletManagerError::Io(e.to_string()))?;
                let name = entry.file_name();
                if let Some(name_str) = name.to_str() {
                    if let Some(label) = name_str.strip_suffix(".json") {
                        if !labels.contains(&label.to_string()) {
                            labels.push(label.to_string());
                        }
                    }
                }
            }
        }

        labels.sort();
        Ok(labels)
    }

    /// Remove a wallet (from cache and disk).
    pub fn remove_wallet(&mut self, label: &str) -> Result<(), WalletManagerError> {
        self.wallets.remove(label);
        let path = self.wallet_path(label);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| WalletManagerError::Io(e.to_string()))?;
        }
        Ok(())
    }

    /// Number of cached wallets.
    pub fn cached_count(&self) -> usize {
        self.wallets.len()
    }

    // ── Mnemonic-based wallet creation ───────────────────────────

    /// Create a new wallet from a BIP-39 mnemonic phrase and return it
    /// along with the phrase.
    ///
    /// Generates a random 24-word mnemonic, derives a spending key from it,
    /// and registers the wallet under `label`. The caller **must** persist
    /// the returned phrase — it is the only way to recover the wallet.
    pub fn create_wallet_with_mnemonic(
        &mut self,
        label: &str,
    ) -> Result<(String, &Wallet), WalletManagerError> {
        if self.wallets.contains_key(label) || self.wallet_path(label).exists() {
            return Err(WalletManagerError::AlreadyExists(label.to_string()));
        }

        let (phrase, spending_key) = SpendingKey::generate_mnemonic(rand::rngs::OsRng);
        let wallet = Wallet::new(spending_key);
        self.wallets.insert(label.to_string(), wallet);
        Ok((phrase, &self.wallets[label]))
    }

    /// Recover a wallet from a BIP-39 mnemonic phrase.
    ///
    /// The wallet's spending key is deterministically derived from `phrase`.
    /// Returns an error if a wallet with this label already exists.
    pub fn recover_wallet_from_mnemonic(
        &mut self,
        label: &str,
        phrase: &str,
    ) -> Result<&Wallet, WalletManagerError> {
        if self.wallets.contains_key(label) || self.wallet_path(label).exists() {
            return Err(WalletManagerError::AlreadyExists(label.to_string()));
        }

        let spending_key = SpendingKey::from_mnemonic(phrase);
        let wallet = Wallet::new(spending_key);
        self.wallets.insert(label.to_string(), wallet);
        Ok(&self.wallets[label])
    }

    // ── Encrypted backup / restore ───────────────────────────────

    /// Export an encrypted backup of a wallet to the given path.
    ///
    /// Uses AES-256-GCM + Argon2 key derivation (same as `Wallet::save_encrypted`).
    pub fn backup_wallet(
        &mut self,
        label: &str,
        backup_path: &Path,
        passphrase: &str,
    ) -> Result<(), WalletManagerError> {
        if !self.wallets.contains_key(label) {
            self.load_wallet(label)?;
        }
        let wallet = self.wallets.get(label)
            .ok_or_else(|| WalletManagerError::NotFound(label.to_string()))?;
        wallet
            .save_encrypted(backup_path, passphrase)
            .map_err(|e| WalletManagerError::Io(e.to_string()))
    }

    /// Restore a wallet from an encrypted backup file.
    ///
    /// Returns an error if a wallet with this label already exists.
    pub fn restore_wallet(
        &mut self,
        label: &str,
        backup_path: &Path,
        passphrase: &str,
    ) -> Result<&Wallet, WalletManagerError> {
        if self.wallets.contains_key(label) || self.wallet_path(label).exists() {
            return Err(WalletManagerError::AlreadyExists(label.to_string()));
        }
        let wallet = Wallet::load_encrypted(backup_path, passphrase)
            .map_err(|e| WalletManagerError::Io(e.to_string()))?;
        self.wallets.insert(label.to_string(), wallet);
        Ok(&self.wallets[label])
    }

    fn wallet_path(&self, label: &str) -> PathBuf {
        assert!(
            !label.contains('/') && !label.contains('\\')
            && !label.contains("..") && !label.is_empty(),
            "invalid wallet label"
        );
        self.base_dir.join(format!("{}.json", label))
    }

    fn load_wallet(&mut self, label: &str) -> Result<(), WalletManagerError> {
        let path = self.wallet_path(label);
        if !path.exists() {
            return Err(WalletManagerError::NotFound(label.to_string()));
        }
        // Use Wallet::load to ensure derived fields (viewing_key, owner_field)
        // are recomputed after deserialization.
        let wallet = Wallet::load(&path)
            .map_err(|e| WalletManagerError::Io(e.to_string()))?;
        self.wallets.insert(label.to_string(), wallet);
        Ok(())
    }
}

/// Errors from the wallet manager.
#[derive(Debug)]
pub enum WalletManagerError {
    AlreadyExists(String),
    NotFound(String),
    Io(String),
}

impl std::fmt::Display for WalletManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(l) => write!(f, "wallet '{}' already exists", l),
            Self::NotFound(l) => write!(f, "wallet '{}' not found", l),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for WalletManagerError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!("lumora_wm_test_{}", suffix))
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn create_wallet_with_mnemonic_roundtrip() {
        let dir = temp_dir("mnemonic");
        cleanup(&dir);
        let mut mgr = WalletManager::new(&dir);

        let (phrase, wallet) = mgr.create_wallet_with_mnemonic("alice").unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        let owner1 = wallet.owner_field();

        // Save and re-create manager to verify persistence.
        mgr.save_wallet("alice").unwrap();
        let mut mgr2 = WalletManager::new(&dir);
        let wallet2 = mgr2.get_wallet("alice").unwrap();
        assert_eq!(wallet2.owner_field(), owner1);

        cleanup(&dir);
    }

    #[test]
    fn recover_wallet_from_mnemonic() {
        let dir = temp_dir("recover");
        cleanup(&dir);
        let mut mgr = WalletManager::new(&dir);

        let (phrase, wallet) = mgr.create_wallet_with_mnemonic("original").unwrap();
        let owner = wallet.owner_field();

        // Recover in a separate manager (different label)
        let mut mgr2 = WalletManager::new(&dir);
        let recovered = mgr2.recover_wallet_from_mnemonic("restored", &phrase).unwrap();
        assert_eq!(recovered.owner_field(), owner);

        cleanup(&dir);
    }

    #[test]
    fn backup_and_restore_encrypted() {
        let dir = temp_dir("backup");
        cleanup(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let mut mgr = WalletManager::new(&dir);

        mgr.create_wallet("bob").unwrap();
        mgr.save_wallet("bob").unwrap();

        let owner = mgr.get_wallet("bob").unwrap().owner_field();
        let backup_path = dir.join("bob.enc");

        mgr.backup_wallet("bob", &backup_path, "s3cret").unwrap();
        assert!(backup_path.exists());

        // Restore under a new label.
        let mut mgr2 = WalletManager::new(temp_dir("backup_restore"));
        let restored = mgr2.restore_wallet("bob_copy", &backup_path, "s3cret").unwrap();
        assert_eq!(restored.owner_field(), owner);

        cleanup(&dir);
        cleanup(&temp_dir("backup_restore"));
    }

    #[test]
    fn restore_wrong_passphrase_fails() {
        let dir = temp_dir("bad_pass");
        cleanup(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let mut mgr = WalletManager::new(&dir);

        mgr.create_wallet("carol").unwrap();
        let backup_path = dir.join("carol.enc");
        mgr.backup_wallet("carol", &backup_path, "correct").unwrap();

        let mut mgr2 = WalletManager::new(temp_dir("bad_pass2"));
        let err = mgr2.restore_wallet("carol", &backup_path, "wrong");
        assert!(err.is_err());

        cleanup(&dir);
        cleanup(&temp_dir("bad_pass2"));
    }

    #[test]
    fn duplicate_mnemonic_wallet_errors() {
        let dir = temp_dir("dup_mnemonic");
        cleanup(&dir);
        let mut mgr = WalletManager::new(&dir);

        mgr.create_wallet_with_mnemonic("dup").unwrap();
        let err = mgr.create_wallet_with_mnemonic("dup");
        assert!(matches!(err, Err(WalletManagerError::AlreadyExists(_))));

        cleanup(&dir);
    }
}
