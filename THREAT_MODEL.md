# Lumora Threat Model

This document describes the security assumptions, trust boundaries, known risks,
and mitigations for the Lumora ZK privacy coprocessor.

---

## 1. System Overview

Lumora is a UTXO-based privacy pool that uses Halo2 zero-knowledge proofs
(IPA, no trusted setup) on the Pallas/Vesta curve pair. Users deposit
transparent value into the pool, then privately transfer and withdraw using
ZK proofs that enforce value conservation and note ownership without revealing
amounts, senders, or recipients.

### Actors

| Actor                   | Role                                                      |
| ----------------------- | --------------------------------------------------------- |
| **User / Wallet**       | Holds spending key, selects notes, requests transactions  |
| **Node Operator**       | Runs the prover daemon, manages pool state and note store |
| **Verifier / Contract** | Validates ZK proofs, enforces state transitions           |
| **Observer**            | Anyone who can read publicly emitted events or the state  |

### Component Map

```
User (CLI / SDK)
  │  spending key, tx intents
  ▼
LumoraNode (prover + state manager)
  │  proof + public inputs
  ▼
Contract (verifier + state)
  │  events, new root
  ▼
Observer (event log, nullifier set, Merkle root)
```

---

## 2. Trust Boundaries

### TB-1: User ↔ Node

The user passes their spending key to the node for proof generation. The node
has full access to all private witness data (spending keys, note values,
randomness, authentication paths).

**Current status**: _No separation._ The CLI runs everything in-process.

**Risk**: A malicious or compromised node operator can steal spending keys and
drain all notes owned by that key.

**Future mitigation**: Client-side proving (user generates proofs locally) or
a split architecture where the node only sees blinded inputs.

### TB-2: Node ↔ Contract (Verifier)

The node submits `(proof_bytes, merkle_root, nullifiers, output_commitments)`.
The contract verifies the proof against these public inputs before updating
state.

**Protection**: This boundary is well-protected by the Halo2 ZK proof —
soundness guarantees that a verifier will reject invalid state transitions with
overwhelming probability.

### TB-3: Note Store (Encrypted Notes)

Encrypted notes are indexed by a 32-byte `RecipientTag` derived from the
recipient's viewing key. Only the recipient can decrypt note contents
(ECDH + ChaCha20-Poly1305).

**Metadata leakage**: An observer of the note store can see _which tags have
notes_ and _when notes are added_, allowing correlation of deposit/transfer
timing.

---

## 3. Cryptographic Assumptions

| Primitive                | Assumption                                              | Library               |
| ------------------------ | ------------------------------------------------------- | --------------------- |
| Pallas/Vesta curves      | Discrete log hardness in prime-order groups             | pasta_curves 0.5.1    |
| Poseidon P128Pow5T3      | 128-bit collision/preimage resistance                   | halo2_gadgets 0.3.1   |
| Halo2 IPA                | Knowledge soundness of the polynomial commitment scheme | halo2_proofs 0.3.2    |
| AES-256-GCM              | IND-CCA2 security for wallet encryption                 | aes-gcm 0.10          |
| Argon2                   | Memory-hard key derivation                              | argon2 0.5            |
| ECDH + ChaCha20-Poly1305 | IND-CCA2 of the hybrid encryption scheme                | chacha20poly1305 0.10 |

### Note Encryption

Note encryption uses Pallas-curve ECDH for key agreement, SHA-256 for key
derivation, and ChaCha20-Poly1305 (RFC 8439) as the AEAD cipher. This is an
industry-standard construction backed by extensive cryptanalysis. Poseidon
remains in use for in-circuit operations (commitments, nullifiers, Merkle tree)
where algebraic efficiency matters.

---

## 4. Attack Surface

### 4.1 Double-Spend Attacks

**Vector**: Submit a proof that re-spends an already-nullified note.

**Mitigation**: The contract checks each nullifier against the
`HashSet<NullifierEntry>` registry before accepting a transaction. Nullifier
equality uses `subtle::ConstantTimeEq` to prevent timing side-channels.

**Residual risk**: None under correct implementation — the circuit constrains
`nf = Poseidon(sk, commitment)`, so a valid proof with a previously-unseen
nullifier guarantees a fresh spend.

### 4.2 Balance Inflation

**Vector**: Forge a proof where `sum(outputs) > sum(inputs)`.

**Mitigation**: The transfer circuit enforces `sum(input_values) ==
sum(output_values)` and the withdraw circuit enforces
`sum(inputs) == sum(outputs) + exit_value`. All values are range-checked to
u64 within the circuit, preventing field-wrapping attacks.

**Residual risk**: Circuit bug. Mitigated by test coverage and formal review.

### 4.3 Merkle Root Manipulation

**Vector**: Submit a proof against a fabricated Merkle root that includes a
note the attacker never deposited.

**Mitigation**: The contract maintains a rolling history of 256 recent Merkle
roots. The proof's anchor root is checked against this history. Only roots
produced by genuine `insert_commitment` calls are admitted.

### 4.4 Spending Key Theft

**Vector**: Compromise the node or wallet to obtain a user's spending key.

**Current exposure points**:

1. Node holds spending key in-memory during proof generation
2. Plaintext wallet save writes key to unencrypted JSON
3. CLI `export-key` prints key to stdout
4. Mnemonic entered via stdin (no echo suppression)

**Mitigations**:

- `SpendingKey` implements `Drop` with `zeroize` (manual zeroing)
- Wallet supports AES-256-GCM encryption (Argon2 KDF)
- BIP39 mnemonic allows recovery without storing the key in plaintext

**Recommendation**: Default to encrypted wallet save. Add terminal echo
suppression for passphrase/mnemonic input. Consider client-side proving.

### 4.5 Note Metadata Leakage

**Vector**: Observe the note store to correlate senders and recipients by
timing and recipient tag patterns.

**Current state**: Encrypted notes are indexed by `RecipientTag =
viewing_key.to_repr()`. An observer can see:

- Which tags receive notes and when
- The number of notes per tag
- Timing correlation between deposits and note appearances

**Mitigation**: Note contents are encrypted (ECIES). Values, assets, and
randomness are hidden.

**Recommendation**: Consider decoy notes, batched delivery, or PIR for
stronger metadata resistance.

### 4.6 State File Integrity

**Vector**: Tamper with `pool_state.json`, `note_store.json`, or `srs.bin`
on disk to corrupt or manipulate the node's view of the pool.

**Mitigations**:

- The SRS is deterministic (can be re-derived)
- State deserialization is validated by serde

**Gaps**:

- No integrity MAC on state files — a local attacker can silently modify
  pool state or nullifier registry
- SRS file has no integrity check on load

**Recommendation**: Add HMAC or signature over state files. Verify SRS hash
after loading.

### 4.7 Timing Side-Channels

**Vector**: Measure nullifier lookup time to learn whether a nullifier exists
without authorization.

**Mitigation**: `NullifierEntry` uses `subtle::ConstantTimeEq` for the
equality comparison within `HashSet` buckets. The hash function (SipHash on
32-byte fixed-size input) runs in effectively constant time.

**Residual risk**: Cache-line and branch-predictor side-channels in the Rust
`HashSet` implementation are beyond the scope of this mitigation.

### 4.8 Note Encryption

**Vector**: Exploit weaknesses in the note encryption construction.

**Mitigations**:

- Uses ChaCha20-Poly1305 (RFC 8439), an industry-standard AEAD with
  extensive cryptanalysis and wide adoption
- Key derived via SHA-256 from the ECDH shared secret x-coordinate
  with a domain-separation tag
- Fixed nonce (all zeros) is safe: each message uses a fresh ephemeral
  key, so the (key, nonce) pair is never reused
- Decryption returns `None` on authentication failure — no padding
  oracles or partial plaintext leakage

### 4.9 Circuit Soundness

**Vector**: Find a satisfying assignment that violates the intended semantics
(e.g., value conservation) but passes all constraints.

**Mitigations**:

- Constraint system follows established patterns from Zcash (Orchard)
- Range checks enforce u64 bounds to prevent field arithmetic overflow
- Poseidon hash is constrained in-circuit (Pow5Chip from halo2_gadgets)
- Public inputs (root, nullifiers, commitments, exit_value) are enforced by
  instance column equality constraints

**Residual risk**: Under-constrained witness. Requires formal audit.

### 4.10 Stealth Address Privacy

**Vector**: Link stealth-addressed transactions back to a known recipient
by exploiting timing, scanning patterns, or ephemeral public key reuse.

**Construction**: Stealth addresses use a Diffie-Hellman key exchange on
the Pallas curve. The sender generates an ephemeral keypair `(r, R = r·G)`,
computes the shared secret `S = r·PK_recipient`, derives a one-time owner
`owner = H(S) + PK_recipient`, and publishes `R` alongside the encrypted
note.

**Threat vectors**:

1. **Ephemeral PK linkability**: The ephemeral public key `R` is published
   in plaintext with each stealth note. If a sender reuses `R` (implementation
   bug), all transactions with the same `R` are linked to the same sender.
   **Mitigation**: Each `stealth_send()` call generates a fresh ephemeral
   keypair from `OsRng`. Code review should verify no caching of `r`.

2. **Scanning timing leakage**: Recipients must trial-decrypt all stealth
   notes to find their own. A light client that selectively downloads notes
   leaks which notes belong to it.
   **Mitigation**: Recipients should download all notes in each sync batch,
   not selectively filter. The `stealth_receive()` function scans linearly.

3. **Shared-secret side channel**: The DH computation `r·PK` uses
   `pasta_curves` scalar multiplication, which is variable-time on some
   platforms.
   **Mitigation**: Pallas scalar multiplication in `pasta_curves 0.5` uses
   a constant-time implementation. On non-standard targets, timing
   measurements may still leak information.

4. **Intersection attacks**: If only a few users use stealth addresses,
   stealth transactions stand out in the anonymity set.
   **Recommendation**: Encourage stealth address adoption so that the
   anonymity set grows. Consider making stealth the default send path.

---

## 5. Denial of Service

| Vector                                                    | Impact                    | Mitigation                                                        |
| --------------------------------------------------------- | ------------------------- | ----------------------------------------------------------------- |
| Spam deposits (zero-value disallowed but 1-value allowed) | Tree growth, storage cost | Future: minimum deposit threshold, fee market                     |
| Large number of notes for one recipient                   | Note store bloat          | Future: per-tag rate limiting                                     |
| Malformed proofs                                          | CPU cost of verification  | Proof deserialization is cheap; invalid proofs fail fast in Halo2 |
| State file corruption                                     | Node crash on recovery    | Serde deserialization catches structural corruption               |

---

## 6. Privacy Guarantees

### What IS hidden (by ZK proofs)

- Specific input notes being spent (hidden behind nullifiers)
- Output note values and recipients (hidden behind commitments)
- The connection between sender and recipient
- Transfer amounts

### What IS NOT hidden

- Deposit amounts (public inputs to the deposit function)
- Withdrawal amounts (public `exit_value`)
- The fact that a transaction occurred (public nullifiers and commitments)
- Timing of transactions
- Recipient tag patterns in the note store
- Pool balance (public state)

---

## 7. Recommendations (Priority Order)

1. **Formal circuit audit** — The transfer and withdraw circuits are the
   security-critical core. An independent audit is essential before production use.
2. **Client-side proving** — Eliminate TB-1 by generating proofs on the user's
   device, keeping spending keys off the node.
3. **State file integrity** — Add HMAC authentication to persisted state files.
4. ~~**Replace custom ECIES**~~ — ✅ Done. Note encryption now uses
   ChaCha20-Poly1305 with ECDH key agreement and SHA-256 KDF.
5. **Default encrypted wallet** — Make `save_encrypted()` the default save
   method and deprecate plaintext save.
6. **Echo suppression** — Suppress terminal echo for passphrase and mnemonic
   input in the CLI.
7. **Metadata resistance** — Investigate decoy notes, batched note delivery,
   or PIR for the note store.
8. **Stealth address adoption** — Default to stealth-addressed sends to
   maximize the anonymity set. Audit ephemeral key generation for reuse bugs.
9. **Relay jitter tuning** — The relay jitter middleware (50–500ms, env-configurable)
   decorrelates POST response timing. Profile production latency to tighten the
   range without harming UX.

---

## 8. Scope Limitations

This threat model covers the current architecture including the RPC server
and cross-chain privacy features. The following are **not yet in scope**
(planned for future phases):

- P2P network-level attacks (eclipse, Sybil)
- Transaction mempool manipulation (front-running, censorship)
- Cross-node state synchronization integrity (Byzantine leaders)
- Rollup integration security (Strata/Alpen Labs bridge contracts)
- MEV and transaction ordering attacks
- Client-side proving (when implemented, removes TB-1)
- Light client trust model attacks

This document should be updated as new components are added.

---

## 9. RPC Server Attack Surface

### 9.1 Authentication Bypass

**Vector**: Access authenticated endpoints without a valid API key.

**Mitigation**: When `LUMORA_API_KEY` is set, the auth middleware checks
`X-API-Key` on all endpoints except `/health` and `/metrics`. Returns 401
on mismatch. The comparison uses constant-time equality to prevent timing
attacks on the API key.

**Residual risk**: API key is a shared secret. If leaked, all clients are
compromised. Rotate keys and deploy behind mTLS for production.

### 9.2 Request Amplification

**Vector**: Submit expensive proof verifications to exhaust CPU/memory.

**Mitigations**:

- Semaphore-based concurrency limiter (128 concurrent requests, returns 503)
- Global body size limit (2 MB)
- Per-proof size limit (512 KB)
- Proof deserialization fails fast on malformed input

### 9.3 Information Disclosure

**Vector**: Extract pool state details through error messages or timing.

**Mitigations**:

- Error responses use generic messages without internal state details
- Nullifier lookups use constant-time comparison
- Relay jitter (50–500ms) decorrelates request/response timing

### 9.4 Stealth Scan Privacy

**Vector**: Correlate stealth-scan requests with specific users by monitoring
request patterns (timing, `from_leaf_index`, frequency).

**Mitigation**: The `/v1/stealth-scan` endpoint returns all notes in a range,
not specific notes. The client does trial decryption locally. However, the
server can observe scanning frequency and index ranges.

**Recommendation**: Clients should scan at regular intervals with consistent
parameters to avoid leaking activity patterns.

---

## 10. Batch Accumulator Timing

### 10.1 Batch Boundary Leakage

**Vector**: Observe batch flush timing to estimate transaction volume or link
co-batched transactions.

**Mitigation**: The `BatchAccumulator` pads under-sized batches with dummy
transactions so that every emitted batch has between `min_batch_size` (4) and
`max_batch_size` (32) transactions, making batch sizes uninformative.

**Residual risk**: Batch flush timing reveals when the accumulator receives
enough transactions or when `max_wait_time` expires. An observer monitoring
flush intervals can estimate transaction rate.

### 10.2 Epoch Boundary Leakage

**Vector**: Monitor epoch finalization timing to correlate nullifier sets with
time ranges.

**Mitigation**: Epochs are time-bounded (default 1 hour). The `epoch_finalize_loop`
runs on a fixed 60-second interval. Epoch roots are only published after
finalization, so the exact set of nullifiers per epoch is only revealed via
the root (which is opaque without the underlying nullifiers).

**Residual risk**: The epoch boundary is predictable, allowing an observer to
assign nullifiers to approximate time ranges.
