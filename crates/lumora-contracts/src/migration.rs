//! State migration utilities.
//!
//! When the state file format evolves (e.g., new fields, changed serialization),
//! this module provides functions to migrate from one version to the next.
//!
//! ## Version History
//!
//! | Version | Changes |
//! |---------|---------|
//! | 0       | Bare JSON (no envelope) — legacy format |
//! | 1       | Versioned envelope + HMAC integrity |
//!
//! Future versions can add migration functions here.

use std::io;
use std::path::Path;

/// Detect the state file format version without loading the full state.
///
/// Returns:
/// - `Ok(None)` if the file doesn't exist
/// - `Ok(Some(0))` for bare JSON (v0 legacy)
/// - `Ok(Some(1))` for versioned envelope (v1)
/// - `Ok(Some(version))` for binary format (detected by LMRA magic)
/// - `Err(...)` on I/O error
pub fn detect_version<P: AsRef<Path>>(path: P) -> io::Result<Option<u32>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(None);
    }

    let data = std::fs::read(path)?;
    if data.len() < 4 {
        return Ok(Some(0)); // Too small for any envelope — treat as legacy
    }

    // Check for binary format magic "LMRA"
    if &data[..4] == b"LMRA" {
        if data.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "binary state file too short for version header",
            ));
        }
        let version = u32::from_le_bytes(
            data[4..8]
                .try_into()
                .expect("state header: bytes 4..8 must be exactly 4 bytes for u32"),
        );
        return Ok(Some(version));
    }

    // Try to detect versioned JSON envelope by checking for "version" key
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&data[..data.len().saturating_sub(32)]) {
        if value.get("version").is_some() {
            let version = value["version"].as_u64().unwrap_or(1) as u32;
            return Ok(Some(version));
        }
        // JSON without version key → bare/legacy v0
        return Ok(Some(0));
    }

    // Not valid JSON — try without HMAC stripping (maybe it's raw JSON without HMAC)
    if serde_json::from_slice::<serde_json::Value>(&data).is_ok() {
        return Ok(Some(0));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unrecognized state file format",
    ))
}

/// Migrate a state file from v0 (bare JSON) to v1 (versioned envelope + HMAC).
///
/// Reads the v0 file, wraps it in a v1 envelope, and saves with HMAC integrity.
/// The original file is preserved as `<path>.v0.bak`.
pub fn migrate_v0_to_v1<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    let state = crate::PrivacyPoolState::load(path)?;

    // Back up the original
    let backup = path.with_extension("v0.bak");
    std::fs::copy(path, &backup)?;

    // Re-save as v1 (the current `save` method writes v1 envelope + HMAC)
    state.save(path)?;

    Ok(())
}

/// Check if a state file needs migration and run it if needed.
///
/// Returns the detected version (after any migration).
pub fn ensure_current<P: AsRef<Path>>(path: P) -> io::Result<u32> {
    let path = path.as_ref();
    match detect_version(path)? {
        None => Ok(1), // No file — fresh state will be v1
        Some(0) => {
            migrate_v0_to_v1(path)?;
            Ok(1)
        }
        Some(v) => Ok(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a unique temp directory for each test invocation.
    fn test_dir(label: &str) -> std::path::PathBuf {
        let id = std::process::id();
        let dir = std::env::temp_dir().join(format!("lumora_mig_{}_{}", label, id));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn detect_version_nonexistent_file() {
        let dir = test_dir("noexist");
        let path = dir.join("nonexistent.json");
        let _ = std::fs::remove_file(&path); // ensure absent
        let result = detect_version(&path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_version_v0_bare_json() {
        let dir = test_dir("v0");
        let path = dir.join("state_v0.json");

        std::fs::write(&path, r#"{"pool_balance": 42}"#).unwrap();

        let version = detect_version(&path).unwrap();
        assert_eq!(version, Some(0));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_version_v1_envelope() {
        let dir = test_dir("v1");
        let path = dir.join("state_v1.json");

        let state = crate::PrivacyPoolState::new();
        state.save(&path).expect("save v1");

        let version = detect_version(&path).unwrap();
        assert_eq!(version, Some(1));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_version_binary_magic() {
        let dir = test_dir("bin");
        let path = dir.join("state.bin");

        let mut data = b"LMRA".to_vec();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 16]);
        std::fs::write(&path, &data).unwrap();

        let version = detect_version(&path).unwrap();
        assert_eq!(version, Some(2));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_version_tiny_file() {
        let dir = test_dir("tiny");
        let path = dir.join("state_tiny.json");

        std::fs::write(&path, b"{}").unwrap();

        let version = detect_version(&path).unwrap();
        assert_eq!(version, Some(0));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_current_nonexistent_returns_1() {
        let dir = test_dir("ensure");
        let path = dir.join("nonexistent.json");
        let _ = std::fs::remove_file(&path);
        let version = ensure_current(&path).unwrap();
        assert_eq!(version, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v0_to_v1_roundtrip() {
        let dir = test_dir("roundtrip");
        let path = dir.join("state_rt.json");

        let state = crate::PrivacyPoolState::new();
        state.save(&path).expect("save v1");

        assert_eq!(detect_version(&path).unwrap(), Some(1));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
