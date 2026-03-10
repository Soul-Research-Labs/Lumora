# Cryptography Reference

## Proof System

| Property            | Value                        |
| ------------------- | ---------------------------- |
| Framework           | Halo2 (zcash fork v0.3)      |
| Commitment scheme   | IPA (Inner Product Argument) |
| Trusted setup       | **None** — transparent SRS   |
| Curve cycle         | Pallas / Vesta               |
| Circuit size        | K = 13 (8192 rows)           |
| Circuit utilization | ~60% (5,200–5,300 rows used) |

### Why Halo2 with IPA?

- No trusted setup ceremony required (transparent parameters).
- Native support for the Pallas/Vesta curve cycle.
- Mature tooling from zcash with battle-tested gadgets.
- Efficient recursive proof composition (future).

## Curves

### Pallas (primary)

- Base field: $\mathbb{F}_p$ where $p = 2^{254} + 45560315531506369815346746415080538113$
- Scalar field: $\mathbb{F}_q$ (= Vesta base field)
- Used for: note commitments, nullifiers, Merkle tree nodes

### Vesta (helper)

- Base field: $\mathbb{F}_q$ (= Pallas scalar field)
- Used for: proof commitments (IPA polynomial commitments)

The Pallas/Vesta cycle means that Pallas's scalar field equals Vesta's base field
and vice versa, enabling efficient in-circuit arithmetic.

## Hash Function: Poseidon

| Parameter   | Value            |
| ----------- | ---------------- |
| Variant     | P128Pow5T3       |
| State width | 3 field elements |
| Rate        | 2                |
| Security    | 128-bit          |
| S-box       | $x^5$ (Pow5)     |

### Usage

- **Note commitment**: $\text{cm} = H(\text{owner} \| \text{value} \| \text{asset} \| \text{randomness})$
- **Nullifier (V1, deprecated)**: $\text{nf} = H(\text{spending\_key} \| \text{commitment})$
- **Nullifier (V2, domain-separated)**: $\text{nf} = H(\text{domain\_tag} \| \text{spending\_key} \| \text{commitment})$
- **Merkle tree**: Internal nodes computed as $H(\text{left} \| \text{right})$
- **Batch root**: $\text{batch\_root} = H(\text{cm}_1 \| \text{cm}_2 \| \ldots)$
- **Epoch root**: $\text{epoch\_root} = H(\text{batch\_root}_1 \| \text{batch\_root}_2 \| \ldots)$

Poseidon is preferred over Pedersen/SHA-256 for in-circuit hashing because it
requires far fewer constraints — approximately 60 rows per hash vs. thousands
for SHA-256.

## Domain-Separated Nullifiers (V2)

V2 nullifiers include a **domain tag** that binds the nullifier to a specific chain/rollup:

$$\text{nf}_{v2} = H(\text{domain\_tag} \| \text{spending\_key} \| \text{commitment})$$

The domain tag is a 32-byte identifier derived from the chain configuration:

$$\text{domain\_tag} = \text{SHA-256}(\text{"lumora-nullifier-v2"} \| \text{chain\_id})$$

### Benefits

- **Cross-chain replay prevention**: A nullifier produced on chain A is invalid on chain B.
- **Forward compatibility**: New chains get unique domain tags automatically.
- **Migration**: V1 nullifiers (no domain tag) remain valid on the original chain. V2 is opt-in during the transition period.

### Migration Path (V1 → V2)

1. V1 nullifiers continue to be accepted during the transition period.
2. New transactions default to V2 format with the active domain tag.
3. After the migration deadline, V1 nullifiers are no longer accepted for new spends.
4. Existing V1 nullifiers in the spent set remain valid (they don't need re-nullifying).

See [Cross-Chain Privacy](cross-chain-privacy.md) for how domain-separated nullifiers enable multi-rollup privacy.

## Key Hierarchy

```
BIP39 Mnemonic (24 words)
  └─ Seed (64 bytes, via PBKDF2-HMAC-SHA512)
       └─ Spending Key (Pallas scalar, via BIP-32 derivation)
            ├─ Viewing Key    = spending_key (as base field element)
            ├─ Note ownership = viewing_key used as "owner" in commitments
            └─ Stealth Meta-Address = (spend_pk, view_pk) published for senders
```

### Spending Key

- Random element of $\mathbb{F}_q$ (Pallas scalar field).
- **Secret**: required to spend notes (produces nullifiers in-circuit).
- Derived from BIP39 mnemonic via BIP-32 path.

### Viewing Key

- Derived from spending key: $\text{vk} = \text{scalar\_to\_base}(\text{sk})$.
- **Semi-secret**: allows reading encrypted notes and computing balances.
- Can be disclosed to auditors for compliance.

### Stealth Meta-Address

- Published pair $(\text{spend\_pk}, \text{view\_pk})$ derived from the spending key.
- Senders use this to generate one-time stealth addresses without interacting with the recipient.
- See [Stealth Addresses](stealth-addresses.md) for the full ECDH construction.

## Encryption

### Note Encryption (ECDH + ChaCha20-Poly1305)

Notes are encrypted for recipients using ECDH key agreement and an industry-standard AEAD:

1. Generate ephemeral keypair $(r, R = r \cdot G)$ on Pallas.
2. Compute shared secret: $S = r \cdot \text{recipient\_pk}$.
3. Derive 32-byte symmetric key: $k = \text{SHA-256}(\text{"lumora-note-encryption-v2"} \| S_x)$.
4. Encrypt note payload with ChaCha20-Poly1305 (nonce = 0, safe because $k$ is unique per message).
5. Ciphertext = $(R_{32}, \text{ciphertext}_{48}, \text{Poly1305-tag}_{16})$ — 96 bytes total.

### Wallet Encryption

User wallets are encrypted at rest:

- **Key derivation**: Argon2id (memory-hard, side-channel resistant)
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Parameters**: 64 MB memory, 3 iterations, 32-byte salt

## Proof Envelopes

Halo2 IPA proofs have variable length depending on circuit complexity. To prevent proof-size
side channels, Lumora wraps all proofs in a **fixed-size proof envelope**:

| Field       | Size (bytes) | Description                    |
| ----------- | ------------ | ------------------------------ |
| `version`   | 1            | Envelope format version (0x01) |
| `proof_len` | 4            | Actual proof length (LE u32)   |
| `proof`     | variable     | Halo2 IPA proof bytes          |
| `padding`   | variable     | Random padding to fixed size   |
| **Total**   | **2048**     | Fixed envelope size            |

### Properties

- All envelopes are exactly 2048 bytes regardless of circuit (transfer/withdraw) or inputs.
- Padding is random bytes to prevent compression-based oracle attacks.
- The RPC server unwraps envelopes before passing proofs to the verifier.
- Proof envelopes are verified at the API boundary (`lumora-rpc`) before deserialization.

## Epoch Root Computation

Epoch roots aggregate batch commitment roots into a single hash for cross-chain verification:

$$\text{epoch\_root} = H_{\text{Poseidon}}(\text{batch\_root}_1 \| \text{batch\_root}_2 \| \ldots \| \text{batch\_root}_n)$$

Where each batch root is:

$$\text{batch\_root} = H_{\text{Poseidon}}(\text{cm}_1 \| \text{cm}_2 \| \ldots \| \text{cm}_m)$$

Epoch roots are finalized by the `EpochManager` and served via `/v1/epoch-roots`. External
verifiers (L1 bridge contracts, other rollups) can use epoch roots to verify state inclusion
without downloading the full Merkle tree.

## Circuit Constraints

### Transfer Circuit (2-in-2-out)

5 public inputs: Merkle root, 2 nullifiers, 2 output commitments.

| ID  | Constraint        | Description                                                                                                  |
| --- | ----------------- | ------------------------------------------------------------------------------------------------------------ |
| C1  | Commitment        | $\text{cm}_i = H(\text{owner}_i \| \text{value}_i \| \text{asset}_i \| r_i)$                                 |
| C2  | Nullifier         | $\text{nf}_i = H(\text{sk}_i \| \text{cm}_i)$ (V1) or $H(\text{domain} \| \text{sk}_i \| \text{cm}_i)$ (V2)  |
| C3  | Merkle proof      | $\text{cm}_i$ is in tree with root $R$                                                                       |
| C4  | Value balance     | $\sum \text{in\_values} = \sum \text{out\_values}$                                                           |
| C5  | Range check       | $0 \leq \text{value} < 2^{64}$                                                                               |
| C6  | Output commitment | $\text{out\_cm}_j = H(\text{out\_owner}_j \| \text{out\_value}_j \| \text{out\_asset}_j \| \text{out\_r}_j)$ |

### Withdraw Circuit

6 public inputs: same as transfer + `exit_value`.

| ID  | Constraint   | Description                                             |
| --- | ------------ | ------------------------------------------------------- |
| C7  | Exit balance | $\sum \text{in} = \sum \text{out} + \text{exit\_value}$ |

### Range Check Gadget

Uses successive halving (bit decomposition) to enforce $0 \leq v < 2^{64}$:

- 65 rows per range check (64 bits + initial value)
- Prevents overflow/underflow attacks on value balance

## Integrity Mechanisms

| Data                  | Mechanism                                |
| --------------------- | ---------------------------------------- |
| State files (JSON)    | HMAC-SHA256 with configurable key        |
| State files (binary)  | LMRA magic header + HMAC-SHA256          |
| State deltas (sync)   | HMAC-SHA256 per delta                    |
| Transaction broadcast | HMAC-SHA256 authentication               |
| WAL entries           | Length-prefixed, partial-write tolerance |
| Snapshots             | Binary format with HMAC integrity        |
| Proof envelopes       | Fixed-size padding + version tag         |
| Epoch roots           | Poseidon hash chain, signed finalization |

## Security Parameters

| Parameter       | Value                         |
| --------------- | ----------------------------- |
| Proof security  | 128-bit (Halo2 IPA)           |
| Hash security   | 128-bit (Poseidon P128Pow5T3) |
| Note encryption | 256-bit (ChaCha20-Poly1305)   |
| Wallet encrypt  | 256-bit (AES-256-GCM)         |
| Key derivation  | Argon2id (64 MB, 3 iter)      |
| Merkle depth    | 32 (4.3 billion leaves)       |
| Root history    | 256 (stale proof tolerance)   |
| Proof envelope  | 2048 bytes (fixed)            |
| Domain tag      | 32 bytes (SHA-256 of chain)   |

## Related Documents

- [Architecture](architecture.md) — System design overview
- [Circuit Constraints](circuit-constraints.md) — Detailed constraint tables
- [Cross-Chain Privacy](cross-chain-privacy.md) — Domain separation and epoch sync
- [Stealth Addresses](stealth-addresses.md) — ECDH one-time key construction
- [Protocol Specification](../PROTOCOL.md) — Formal protocol spec
- [Threat Model](../THREAT_MODEL.md) — Attack surface and mitigations
