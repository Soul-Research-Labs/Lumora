# Stealth Addresses

Lumora implements stealth addresses using ECDH (Elliptic Curve Diffie-Hellman)
one-time keys on the Pallas curve. This enables senders to pay recipients
without revealing the recipient's identity on-chain.

## Problem Statement

In a standard privacy pool, the recipient's public key (viewing key) appears in
the note commitment. If a recipient reuses the same key for multiple
transactions, an observer can link all incoming payments to the same entity.

Stealth addresses solve this by generating a **unique one-time address** for
each payment. The recipient can detect and spend these notes, but no external
observer can link them.

## Protocol Overview

```
┌──────────┐                                    ┌──────────────┐
│  Sender  │                                    │  Recipient   │
│          │                                    │              │
│          │  1. Fetch stealth meta-address     │              │
│          │     (spend_pk, view_pk) ◄──────────│ Published    │
│          │                                    │              │
│  2. Gen ephemeral key                         │              │
│     r ← random scalar                        │              │
│     R = r·G                                   │              │
│                                               │              │
│  3. Shared secret                             │              │
│     S = r · view_pk                           │              │
│                                               │              │
│  4. One-time address                          │              │
│     P = spend_pk + H(S)·G                     │              │
│                                               │              │
│  5. Create note with owner = P                │              │
│     Include R in encrypted payload            │              │
│          │                                    │              │
│          │  ───── POST /v1/transfer ─────►    │              │
│          │                                    │              │
│          │                    6. Scan notes    │              │
│          │                    POST /v1/stealth-scan          │
│          │                                    │              │
│          │                    7. For each note:│              │
│          │                    S' = view_sk · R │              │
│          │                    P' = spend_pk + H(S')·G        │
│          │                    If P' == note.owner → match    │
│          │                                    │              │
│          │                    8. Spend with    │              │
│          │                    sk = spend_sk + H(S')          │
└──────────┘                                    └──────────────┘
```

## Cryptographic Construction

### Key Setup

The recipient publishes a **stealth meta-address** consisting of two public keys:

| Key        | Derivation     | Purpose                      |
| ---------- | -------------- | ---------------------------- |
| `spend_pk` | `spend_sk · G` | Base public key for spending |
| `view_pk`  | `view_sk · G`  | Used for ECDH shared secret  |

Both keys are on the Pallas curve $E(\mathbb{F}_p)$.

### Sending (Stealth Address Generation)

1. **Generate ephemeral keypair**: $r \leftarrow \mathbb{F}_q, \quad R = r \cdot G$
2. **Compute shared secret**: $S = r \cdot \text{view\_pk}$
3. **Derive stealth key offset**: $h = H_{\text{Poseidon}}(S_x)$ where $S_x$ is the x-coordinate of $S$
4. **Compute one-time address**: $P = \text{spend\_pk} + h \cdot G$
5. **Create note**: Set `owner = P` in the note commitment
6. **Include ephemeral key**: Attach $R$ in the encrypted note payload

### Receiving (Scanning)

The recipient periodically scans for incoming notes:

1. **Download notes**: Call `POST /v1/stealth-scan` to get encrypted notes in a range.
2. **For each note** with ephemeral public key $R$:
   - Compute shared secret: $S' = \text{view\_sk} \cdot R$
   - Derive stealth key offset: $h' = H_{\text{Poseidon}}(S'_x)$
   - Compute expected address: $P' = \text{spend\_pk} + h' \cdot G$
   - **Match**: If $P' = \text{note.owner}$, this note belongs to the recipient.
3. **Derive spending key**: $\text{stealth\_sk} = \text{spend\_sk} + h'$

### Correctness

The protocol is correct because:

$$S = r \cdot \text{view\_pk} = r \cdot \text{view\_sk} \cdot G = \text{view\_sk} \cdot r \cdot G = \text{view\_sk} \cdot R = S'$$

Therefore:

- Sender's $h = H(S_x) = H(S'_x) = h'$ (recipient's)
- Sender's $P = \text{spend\_pk} + h \cdot G = \text{spend\_pk} + h' \cdot G = P'$ (recipient's)

## Scanning via the RPC API

### Endpoint: `POST /v1/stealth-scan`

The stealth scan endpoint returns encrypted notes without performing any
decryption server-side. This preserves privacy: the server does not learn which
notes belong to which recipients.

**Request**:

```json
{
  "from_leaf_index": 0,
  "limit": 1000
}
```

**Response**:

```json
{
  "notes": [
    {
      "leaf_index": 0,
      "commitment": "aabb...",
      "ciphertext": "ccdd...",
      "ephemeral_pubkey": "eeff..."
    }
  ],
  "count": 1
}
```

### TypeScript SDK

```typescript
import { LumoraClient } from "@lumora/sdk";

const client = new LumoraClient("http://127.0.0.1:3030", "my-api-key");

// Download notes for trial decryption
const scan = await client.stealthScan({
  from_leaf_index: lastScannedIndex,
  limit: 500,
});

for (const note of scan.notes) {
  // 1. Parse ephemeral public key R from note.ephemeral_pubkey
  // 2. Compute S' = view_sk * R
  // 3. Derive h' = Poseidon(S'_x)
  // 4. Compute P' = spend_pk + h' * G
  // 5. Compare P' with note commitment's owner field
  // 6. If match: derive stealth_sk = spend_sk + h', decrypt note.ciphertext
}
```

### Incremental Scanning

Clients should track the last scanned `leaf_index` to avoid re-scanning:

```typescript
let checkpoint = 0;

async function scanForNewNotes() {
  const scan = await client.stealthScan({
    from_leaf_index: checkpoint,
    limit: 1000,
  });

  for (const note of scan.notes) {
    // Trial decryption ...
    checkpoint = Math.max(checkpoint, note.leaf_index + 1);
  }
}

// Poll periodically (e.g., every 30 seconds)
setInterval(scanForNewNotes, 30_000);
```

## Privacy Properties

| Property                    | Guarantee                                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------------------- |
| **Sender privacy**          | Sender identity is hidden by the ZK proof (same as standard transfers).                                       |
| **Recipient unlinkability** | Each payment uses a unique one-time address; no two notes share the same owner.                               |
| **Server privacy**          | The server returns all notes; it does not learn which notes the client owns.                                  |
| **Scan privacy**            | Anyone can scan (no auth needed beyond API key); scanning doesn't reveal interest in specific notes.          |
| **Forward secrecy**         | Ephemeral keys are discarded after use; compromise of a past ephemeral key doesn't affect other transactions. |

## Security Considerations

### Viewing Key Compromise

If an attacker obtains the **viewing key** (`view_sk`), they can:

- Determine which notes belong to the recipient (scanning).
- Read note amounts and metadata.
- **Cannot** spend notes (requires `spend_sk`).

This is the same risk level as standard viewing key disclosure in Lumora.

### Spending Key Compromise

If an attacker obtains the **spending key** (`spend_sk`), they can:

- Derive all stealth spending keys.
- Spend all notes (past and future).

**Mitigation**: Store spending keys in encrypted wallets (Argon2 + AES-256-GCM).

### Ephemeral Key Reuse

If a sender reuses the same ephemeral key $r$ for two payments to the same
recipient, the one-time addresses will be identical, breaking unlinkability.

**Mitigation**: Ephemeral keys are generated from a CSPRNG. The probability of
collision is negligible ($2^{-254}$).

### Scan Timing Side Channel

If a recipient scans immediately after a transaction, an observer correlating
scan timing with deposit/transfer events may infer which notes are of interest.

**Mitigation**:

- Scan on a fixed schedule (not triggered by incoming transactions).
- Download large batches to reduce per-transaction timing information.
- Relay jitter (50–500 ms) adds noise to API response timing.

### Trial Decryption Cost

Scanning is $O(n)$ in the number of notes since `from_leaf_index`. For pools
with millions of notes, clients should:

- Scan incrementally using checkpoints.
- Accept a startup cost for initial sync.
- Consider running a local scanning daemon for heavy wallets.

## Performance

| Operation                      | Approx. Time | Notes                     |
| ------------------------------ | ------------ | ------------------------- |
| Stealth address generation     | < 0.1 ms     | ECDH + Poseidon           |
| Trial decryption (per note)    | < 0.01 ms    | ECDH + Poseidon + compare |
| Stealth scan download (1K)     | < 10 ms      | Server-side linear scan   |
| Full scan (100K notes, client) | ~1 s         | CPU-bound ECDH + hash     |

## Comparison with Other Schemes

| Scheme                  | Setup | Scan Cost | Unlinkable | Notes                    |
| ----------------------- | ----- | --------- | ---------- | ------------------------ |
| **Lumora (ECDH)**       | None  | O(n)      | Yes        | Simple, Pallas-native    |
| EIP-5564 (Ethereum)     | None  | O(n)      | Yes        | Similar ECDH scheme      |
| Zcash diversified addrs | None  | O(1)      | Yes        | Requires in-protocol IVK |
| Monero stealth addrs    | None  | O(n)      | Yes        | Dual-key ECDH            |

Lumora's scheme is most similar to EIP-5564 but operates over Pallas (not
secp256k1) and uses Poseidon for the key offset derivation (not keccak256).

## Related Documents

- [Cryptography](cryptography.md) — Key hierarchy, Poseidon hash, ECDH key agreement
- [Cross-Chain Privacy](cross-chain-privacy.md) — Domain-separated nullifiers and epochs
- [Architecture](architecture.md) — Stealth scanner component placement
- [TypeScript SDK](typescript-sdk.md) — `stealthScan()` method reference
- [Threat Model](../THREAT_MODEL.md) — Stealth scan privacy analysis
