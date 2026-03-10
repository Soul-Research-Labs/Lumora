# ADR-006: JSON State with HMAC Integrity

## Status

Accepted

## Context

The node must persist its state (Merkle tree, nullifier set, root history, balances, event log) to disk. The persistence format must support:

- Crash safety (no half-written state)
- Integrity detection (corruption or tampering)
- Forward-compatible schema evolution
- Debuggability

## Decision

Serialize state as **JSON** wrapped in a versioned envelope (`StateFileEnvelope`), with an **HMAC-SHA256** integrity tag appended. Use atomic writes (temp file + rename). A separate **binary format** (LMRA magic header) is also available.

## Rationale

### JSON Format

- **Human-readable**: Easy to inspect and debug during development.
- **Serde integration**: Direct use of Rust serde derive macros with custom adapters for field elements (hex encoding).
- **Small state size**: The state file (tree metadata, nullifier set, root history) is small enough that JSON serialization overhead is negligible.

### HMAC Integrity

- **Detects corruption**: HMAC-SHA256 over the serialized bytes catches accidental file corruption and casual tampering.
- **Symmetric**: Fast and appropriate for local file integrity — a digital signature would be overkill since the same process writes and reads the file.
- **Constant-time nullifier comparison**: `NullifierEntry` uses `subtle::ConstantTimeEq` to prevent timing side-channels.

### Atomic Writes

- **Crash safety**: Write to a temp file, then rename — prevents half-written state on crash or power loss.

### Versioned Envelope

- **Schema evolution**: The file includes a format version number, enabling forward-compatible migrations. Load falls back to bare (v0) state for backward compatibility.

### Binary Format (LMRA)

- **Compact**: `[4B "LMRA" magic][4B version LE][JSON payload][32B HMAC]` for cases where a structured binary envelope is preferred.

## Consequences

- State files are larger than a pure binary format but remain trivially small for expected workloads.
- The HMAC key is static — this protects against accidental corruption but not a determined attacker with code access. For deployment security, the state directory should have appropriate file system permissions.
