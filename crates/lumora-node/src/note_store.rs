//! Encrypted note store for relaying notes to recipients.
//!
//! When a transfer or deposit creates output notes, the sender encrypts
//! the note details so only the recipient (who holds the viewing key) can
//! decrypt them. The note store indexes these by a "tag" derived from the
//! recipient's viewing key, so recipients can download their notes without
//! revealing which notes are theirs to other observers.

use std::collections::HashMap;
use std::io;
use std::path::Path;

/// An encrypted note payload that can be relayed to a recipient.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedNote {
    /// The leaf index of the commitment in the Merkle tree.
    pub leaf_index: u64,
    /// The output commitment (public — already on-chain).
    pub commitment: [u8; 32],
    /// Encrypted note body (value, asset, randomness, owner).
    /// Encrypted with the recipient's viewing key.
    pub ciphertext: Vec<u8>,
    /// Ephemeral public key for ECIES decryption.
    pub ephemeral_pubkey: [u8; 32],
}

/// Tag for note store lookup — derived from recipient's viewing key.
pub type RecipientTag = [u8; 32];

/// Simple in-memory encrypted note store.
///
/// In production this would be backed by a database.
pub struct NoteStore {
    /// Notes indexed by recipient tag.
    notes: HashMap<RecipientTag, Vec<EncryptedNote>>,
}

impl NoteStore {
    pub fn new() -> Self {
        Self {
            notes: HashMap::new(),
        }
    }

    /// Store an encrypted note for a recipient.
    pub fn insert(&mut self, tag: RecipientTag, note: EncryptedNote) {
        self.notes.entry(tag).or_default().push(note);
    }

    /// Retrieve all encrypted notes for a recipient tag.
    pub fn get(&self, tag: &RecipientTag) -> &[EncryptedNote] {
        self.notes.get(tag).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Total number of stored notes.
    pub fn note_count(&self) -> usize {
        self.notes.values().map(|v| v.len()).sum()
    }

    /// Return all stored notes across all tags, ordered by leaf index.
    ///
    /// Used for stealth address scanning — recipients must download all notes
    /// to avoid leaking which tags they are interested in.
    pub fn all_notes_since(&self, min_leaf_index: u64) -> Vec<&EncryptedNote> {
        let mut all: Vec<&EncryptedNote> = self
            .notes
            .values()
            .flat_map(|v| v.iter())
            .filter(|n| n.leaf_index >= min_leaf_index)
            .collect();
        all.sort_by_key(|n| n.leaf_index);
        all
    }

    /// Save the note store to a JSON file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let serializable: Vec<(String, &Vec<EncryptedNote>)> = self
            .notes
            .iter()
            .map(|(tag, notes)| (hex::encode(tag), notes))
            .collect();
        let json = serde_json::to_string_pretty(&serializable)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Load a note store from a JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let entries: Vec<(String, Vec<EncryptedNote>)> = serde_json::from_str(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut notes = HashMap::new();
        for (tag_hex, note_list) in entries {
            let tag_bytes = hex::decode(&tag_hex)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if tag_bytes.len() != 32 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "tag must be 32 bytes"));
            }
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&tag_bytes);
            notes.insert(tag, note_list);
        }
        Ok(Self { notes })
    }
}

impl Default for NoteStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_store_insert_and_retrieve() {
        let mut store = NoteStore::new();
        let tag = [1u8; 32];

        store.insert(tag, EncryptedNote {
            leaf_index: 0,
            commitment: [0u8; 32],
            ciphertext: vec![1, 2, 3],
            ephemeral_pubkey: [0u8; 32],
        });

        assert_eq!(store.get(&tag).len(), 1);
        assert_eq!(store.get(&[2u8; 32]).len(), 0);
        assert_eq!(store.note_count(), 1);
    }

    #[test]
    fn test_note_store_multiple_notes_same_recipient() {
        let mut store = NoteStore::new();
        let tag = [1u8; 32];

        for i in 0..3 {
            store.insert(tag, EncryptedNote {
                leaf_index: i,
                commitment: [0u8; 32],
                ciphertext: vec![i as u8],
                ephemeral_pubkey: [0u8; 32],
            });
        }

        assert_eq!(store.get(&tag).len(), 3);
        assert_eq!(store.note_count(), 3);
    }

    #[test]
    fn test_note_store_save_load_roundtrip() {
        let mut store = NoteStore::new();
        let tag = [0xAB; 32];
        store.insert(tag, EncryptedNote {
            leaf_index: 42,
            commitment: [0xCD; 32],
            ciphertext: vec![1, 2, 3, 4],
            ephemeral_pubkey: [0xEF; 32],
        });

        let dir = std::env::temp_dir().join("lumora_note_store_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("store.json");

        store.save(&path).expect("save");
        let loaded = NoteStore::load(&path).expect("load");
        assert_eq!(loaded.note_count(), 1);

        let notes = loaded.get(&tag);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].leaf_index, 42);
        assert_eq!(notes[0].ciphertext, vec![1, 2, 3, 4]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
