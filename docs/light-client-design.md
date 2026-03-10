# Light Client Design

This document describes the design for a Lumora light client — a resource-constrained client that can verify state transitions without running a full node.

## Goals

1. Verify ZK proofs without storing full state
2. Track notes belonging to the user via viewing key scanning
3. Sync incrementally from a trusted or semi-trusted full node
4. Minimize bandwidth, storage, and computation

## Architecture

```
┌──────────────┐        ┌────────────────┐
│ Light Client │◄──────►│  Full Node RPC │
│              │  HTTP   │                │
│  - Wallet    │        │  - Full State  │
│  - VK cache  │        │  - Proof Gen   │
│  - Proof ver │        │  - Event Log   │
└──────────────┘        └────────────────┘
```

### Components

| Component               | Responsibility                                           |
| ----------------------- | -------------------------------------------------------- |
| **Wallet**              | Spending/viewing keys, note management, coin selection   |
| **Verifying Key Cache** | Cached transfer + withdraw VKs (one per circuit version) |
| **Sync Engine**         | Pulls signed state deltas from a full node               |
| **Proof Verifier**      | Verifies ZK proofs locally (halo2 IPA verify)            |
| **Note Scanner**        | Uses viewing key to find incoming notes                  |

## Sync Protocol

### Initial Sync

1. Light client requests `SyncStatus` from the full node
2. Fetches `SignedStateDelta` covering all events from height 0
3. Verifies HMAC on the delta (shared sync key)
4. For each event:
   - **Deposit**: Record commitment + leaf index
   - **Transfer**: Verify the ZK proof, record nullifiers + new commitments
   - **Withdraw**: Verify the ZK proof, record nullifiers + change commitments

### Incremental Sync

1. Light client stores its last-synced height
2. Requests delta from `(last_height, current_height)`
3. Applies verified events incrementally
4. Scans new commitments for notes addressed to the wallet's viewing key

## State Requirements

The light client does NOT store:

- The full Merkle tree (stored by full node)
- The full nullifier set (stored by full node)
- Other users' encrypted notes

The light client stores:

- **Wallet state**: spending key (encrypted), viewing key, owned notes
- **Verifying keys**: one per circuit version (~few KB each)
- **Sync checkpoint**: last-synced height and root
- **Root history**: last N roots for proof freshness validation

Estimated storage: < 1 MB for typical usage.

## Proof Verification

The light client can verify proofs locally using cached verifying keys:

```
1. Receive TransferProof { proof_bytes, merkle_root, nullifiers, output_commitments, circuit_version }
2. Look up VerifyingKey for circuit_version
3. Reconstruct public inputs: [merkle_root, nf0, nf1, cm0, cm1]
4. Call halo2 verify(vk, params, proof_bytes, public_inputs)
5. Accept or reject
```

For withdrawal proofs, public inputs include `exit_value` (6 total).

## Trust Model

| Mode                  | Trust Assumption                   | Verification                             |
| --------------------- | ---------------------------------- | ---------------------------------------- |
| **Full verification** | None (trustless)                   | Verify every ZK proof locally            |
| **Header-only**       | Trust full node for event ordering | Verify Merkle root chain + HMAC          |
| **Delegated**         | Trust full node completely         | Accept events without proof verification |

The recommended mode is **full verification** for all transfers/withdrawals the light client cares about (its own notes), with **header-only** mode for events involving other users.

## Bandwidth Estimates

| Operation             | Data per event | Notes                                      |
| --------------------- | -------------- | ------------------------------------------ |
| Deposit event         | ~100 bytes     | commitment + amount + leaf index           |
| Transfer event        | ~2-3 KB        | 2 nullifiers + 2 commitments + proof bytes |
| Withdraw event        | ~2-3 KB        | Similar to transfer + exit value           |
| Signed delta overhead | 32 bytes       | HMAC tag                                   |

For a pool processing 1000 transactions/day, incremental sync costs ~2-3 MB/day.

## API Surface

The light client uses existing RPC endpoints:

| Endpoint                | Purpose                                                      |
| ----------------------- | ------------------------------------------------------------ |
| `GET /v1/status`        | Get current sync status (height, root)                       |
| `GET /v1/sync?from=N`   | Fetch signed delta from height N                             |
| `GET /v1/notes?tag=...` | Fetch encrypted notes by viewing key tag                     |
| `POST /v1/transfer`     | Submit a transfer (proof generated client-side or delegated) |
| `POST /v1/withdraw`     | Submit a withdrawal                                          |
| `GET /v1/health`        | Check node availability                                      |

## Future Extensions

- **Proof delegation**: Light client sends witness data to a prover service; receives proof back. Requires encrypted witness transport (viewing key disclosure to prover).
- **SPV-style headers**: Chain of Merkle roots with signatures, enabling sync without trusting a single node.
- **Recursive proofs**: A single proof attesting to N state transitions, enabling instant sync regardless of history length.

## Stealth Address Scanning

Light clients support stealth-addressed notes. During incremental sync, the
note scanner performs trial decryption of each note's ephemeral public key
against the wallet's spending key:

1. For each note with an ephemeral public key `R`:
   - Compute `S = sk · R` (ECDH shared secret)
   - Derive `owner = H(S) + PK` (expected one-time owner)
   - Check if this matches the note's commitment owner
2. If a match is found, the note belongs to this wallet.

**Privacy consideration**: The light client must download all notes in each
sync batch (not selectively filter) to avoid leaking which notes it is
interested in. The `stealth_receive()` function performs this scan linearly
across the full set of new notes.

**Epoch-based sync optimization**: The `/v1/epoch-roots` endpoint provides
finalized nullifier epoch roots. A light client can use these roots to verify
that its spent notes have been properly nullified without downloading the full
nullifier set — only the epoch root and a Merkle inclusion proof are needed.

**RPC support**: The `/v1/stealth-scan` endpoint accepts a viewing key and a
commitment range, returning matching notes server-side. This is convenient for
bandwidth-constrained clients but requires trusting the server with the viewing
key. For maximum privacy, prefer client-side scanning via `stealth_receive()`
over the full note set.
