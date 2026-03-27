# Cross-Chain Privacy

This document describes how Lumora maintains privacy across multiple rollups
and chains using domain-separated nullifiers and epoch-based state partitioning.

## Problem Statement

When a privacy pool operates across multiple rollups (e.g., Strata L1, Strata
rollup A, Strata rollup B), two critical attacks must be prevented:

1. **Cross-chain replay** — A nullifier spent on chain A is replayed on chain B
   to double-spend the same note.
2. **Cross-chain linkability** — An observer correlates activity across chains
   by matching identical nullifier values.

Lumora solves both problems with **domain-separated nullifiers** (V2) and
**epoch-based state partitioning**.

## Domain-Separated Nullifiers (V2)

### V1 Nullifier (deprecated)

$$\text{nf}_{v1} = H_{\text{Poseidon}}(\text{spending\_key} \| \text{commitment})$$

V1 nullifiers are chain-agnostic: the same note produces the same nullifier on
every chain. This is vulnerable to cross-chain replay and linkability.

### V2 Nullifier (current)

The V2 nullifier uses nested Poseidon hashing for domain separation:

$$\text{nf}_{v2} = H_{\text{Poseidon}}\bigl(H_{\text{Poseidon}}(\text{sk}, \text{cm}),\; H_{\text{Poseidon}}(\text{chain\_id}, \text{app\_id})\bigr)$$

Where:

- `sk` — The spending key scalar, converted to the Pallas base field.
- `cm` — The note commitment.
- `chain_id` — Unique identifier for the chain/rollup (e.g., `1` for Strata mainnet), as a field element.
- `app_id` — Application identifier within the chain (default: `0`), as a field element.

This is equivalent to `poseidon::hash_four(sk, cm, chain_id, app_id)` which
internally computes `hash_two(hash_two(sk, cm), hash_two(chain_id, app_id))`.

### Properties

| Property                | V1 Nullifier | V2 Nullifier                       |
| ----------------------- | ------------ | ---------------------------------- |
| Cross-chain replay safe | No           | Yes                                |
| Cross-chain unlinkable  | No           | Yes                                |
| Backward compatible     | —            | Yes (V1 coexists during migration) |
| Hash inputs             | 2            | 4 (nested Poseidon)                |
| Circuit constraints     | Same         | +2 Poseidon hashes                 |

### SDK Support

The TypeScript SDK supports V2 domain fields in transfer and withdraw requests:

```typescript
const tx = await client.transfer({
  proof_bytes: "0a1b...",
  merkle_root: "abcd...",
  nullifiers: ["1111...", "2222..."],
  output_commitments: ["3333...", "4444..."],
  domain_chain_id: 1, // Strata mainnet
  domain_app_id: 0, // Default application
});
```

When `domain_chain_id` is omitted, the server falls back to V1 nullifier
validation (for backward compatibility during migration).

## Epoch-Based State Partitioning

### Concept

Instead of syncing every individual transaction between chains, Lumora batches
state changes into **epochs** — periodic snapshots of cumulative state that can
be verified cheaply by external parties.

```
Time ─────────────────────────────────────────────────────►

Commitments: c₁ c₂ c₃ c₄ c₅ c₆ c₇ c₈ c₉ c₁₀ c₁₁ c₁₂
             └──batch 1──┘ └──batch 2──┘ └──batch 3──┘
             └────────── epoch 1 ──────────────────────┘
```

### Two-Tier Batching

#### BatchAccumulator (5-second intervals)

The `batch_poll_loop` runs every 5 seconds and:

1. Collects all new note commitments since the last poll.
2. Computes a batch root: $\text{batch\_root} = H_{\text{Poseidon}}(\text{cm}_1 \| \text{cm}_2 \| \ldots)$
3. Stores the batch root in the accumulator.

#### EpochManager (60-second intervals)

The `epoch_finalize_loop` runs every 60 seconds and:

1. Collects all batch roots since the last finalized epoch.
2. Computes an epoch root: $\text{epoch\_root} = H_{\text{Poseidon}}(\text{batch\_root}_1 \| \text{batch\_root}_2 \| \ldots)$
3. Assigns a monotonically increasing `epoch_id`.
4. Publishes the epoch root via `GET /v1/epoch-roots`.

### Epoch Root Response

```json
{
  "current_epoch": 42,
  "roots": [
    { "epoch_id": 40, "root": "abcd..." },
    { "epoch_id": 41, "root": "ef01..." },
    { "epoch_id": 42, "root": "2345..." }
  ]
}
```

### Cross-Chain Sync Protocol

External verifiers (L1 bridge contracts, other rollups) can verify Lumora state
without downloading the full Merkle tree:

```
Lumora Node (Chain A)                    Bridge Contract (Chain B)
       │                                         │
       │  1. Finalize epoch root                  │
       │     epoch_id=42, root=0xABCD            │
       │                                         │
       │  2. POST epoch root + merkle proof ────► │
       │                                         │
       │                         3. Verify Poseidon│
       │                            root matches  │
       │                                         │
       │                         4. Accept state  │
       │                            inclusion     │
       │                                         │
```

1. **Finalization**: The Lumora node finalizes epoch root via `EpochManager`.
2. **Submission**: The bridge submits the epoch root (+ optional Merkle proof of inclusion) to the target chain's bridge contract.
3. **Verification**: The bridge contract verifies the Poseidon hash chain.
4. **Acceptance**: Once verified, the target chain can trust state inclusion proofs anchored to that epoch root.

### Sync Payload

Each epoch root sync requires minimal bandwidth:

| Field       | Size      |
| ----------- | --------- |
| `epoch_id`  | 8 bytes   |
| `root`      | 32 bytes  |
| `height`    | 8 bytes   |
| `timestamp` | 8 bytes   |
| **Total**   | ~56 bytes |

This is orders of magnitude smaller than syncing individual transactions.

## RollupBridge Integration

The `lumora-node` crate includes a `RollupBridge` component for managing
cross-chain nullifier synchronization:

### Remote Nullifier Sync

When a nullifier is spent on chain A, the bridge propagates it to chain B:

1. Chain A spends nullifier $\text{nf}_{v2}$ with domain tag for chain A.
2. Bridge extracts the domain-separated nullifier.
3. Bridge submits the nullifier to chain B's bridge contract.
4. Chain B records the nullifier in its "remote nullifier set."
5. Any attempt to spend the same note on chain B will fail because:
   - V2 nullifiers for chain B have a different domain tag.
   - Even if the attacker constructs a V2 nullifier for chain B, the note's
     commitment is already spent (bridge-synced).

### Configuration

Cross-chain sync parameters:

| Parameter             | Default | Description                         |
| --------------------- | ------- | ----------------------------------- |
| `epoch_interval_secs` | 60      | Seconds between epoch finalizations |
| `batch_interval_secs` | 5       | Seconds between batch accumulations |
| `max_epoch_roots`     | 1000    | Maximum epoch roots kept in memory  |
| `sync_retry_count`    | 3       | Bridge sync retry attempts          |
| `sync_timeout_ms`     | 5000    | Bridge sync timeout per attempt     |

## Security Considerations

### Domain Tag Collision

Two chains must never share the same `(chain_id, app_id)` pair. Chain IDs are
assigned by the Strata network registry. Collisions would reduce V2 to V1
security (cross-chain replay vulnerability).

### Epoch Boundary Leakage

An observer who monitors `/v1/epoch-roots` can learn:

- Approximate transaction rate (from epoch root publication frequency).
- Whether any transactions occurred in an epoch (empty vs. non-empty roots).

**Mitigation**: Empty epochs still produce a root (hash of empty batch set) to
prevent distinguishing active from inactive periods. Relay jitter adds noise to
publication timing.

### Batch Boundary Leakage

An observer who correlates transaction timing with batch boundaries may learn:

- Whether two transactions are in the same batch.
- Approximate timing of individual transactions within a batch.

**Mitigation**: Relay jitter (50–500 ms, configurable) decorrelates transaction
arrival from batch boundaries.

## Migration: V1 → V2

### Timeline

1. **Phase 1 (current)**: Both V1 and V2 nullifiers accepted. New transactions
   default to V2.
2. **Phase 2**: V1 nullifiers deprecated. Warning emitted on V1 usage.
3. **Phase 3**: V1 nullifiers rejected for new transactions. Existing V1
   nullifiers in the spent set remain valid.

### Client Migration

```typescript
// V1 (deprecated) — no domain fields
await client.transfer({
  proof_bytes: "...",
  merkle_root: "...",
  nullifiers: ["...", "..."],
  output_commitments: ["...", "..."],
});

// V2 (recommended) — include domain fields
await client.transfer({
  proof_bytes: "...",
  merkle_root: "...",
  nullifiers: ["...", "..."],
  output_commitments: ["...", "..."],
  domain_chain_id: 1,
  domain_app_id: 0,
});
```

## Related Documents

- [Cryptography](cryptography.md) — Poseidon hash, domain-separated nullifier formulas
- [Architecture](architecture.md) — BatchAccumulator and EpochManager placement
- [Stealth Addresses](stealth-addresses.md) — ECDH one-time key protocol
- [TypeScript SDK](typescript-sdk.md) — SDK reference with domain field support
- [Protocol Specification](../PROTOCOL.md) — Formal protocol spec
- [Threat Model](../THREAT_MODEL.md) — Batch/epoch timing attack analysis
