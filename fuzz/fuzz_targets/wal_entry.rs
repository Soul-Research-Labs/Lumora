//! Fuzz target: WAL entry recovery from corrupted data.
//!
//! The WAL stores length-prefixed JSON entries. This target ensures that
//! arbitrary byte sequences never cause panics during WAL parsing — only
//! clean error paths.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Simulate WAL entry parsing: 4-byte LE length prefix + JSON payload.
    // This mirrors the WAL recovery logic that reads entries sequentially.
    let mut cursor = 0;
    while cursor + 4 <= data.len() {
        let len = u32::from_le_bytes(
            data[cursor..cursor + 4].try_into().unwrap(),
        ) as usize;
        cursor += 4;

        if cursor + len > data.len() {
            // Truncated entry — WAL recovery treats as end of valid data.
            break;
        }

        let entry_bytes = &data[cursor..cursor + len];
        cursor += len;

        // Attempt to parse as JSON (mirrors WAL's serde_json::from_slice).
        let _ = serde_json::from_slice::<serde_json::Value>(entry_bytes);
    }
});
