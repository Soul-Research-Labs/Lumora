# Lumora Protocol Specification

Version 0.1 — Draft

---

## 1. Overview

Lumora is a UTXO-based privacy pool using Halo2 zero-knowledge proofs
(IPA commitment scheme, transparent SRS) on the Pallas/Vesta curve pair.
It provides three operations:

- **Deposit** — Shield public value into a private note commitment.
- **Transfer** — Privately spend two input notes and create two output notes.
- **Withdraw** — Spend two input notes, create two change notes, and exit
  a public amount from the pool.

All transfers and withdrawals are proven in zero knowledge. An external
verifier can validate state transitions without learning amounts, senders,
or recipients.

---

## 2. Notation

| Symbol           | Meaning                                              |
| ---------------- | ---------------------------------------------------- |
| $\mathbb{F}_p$   | Pallas base field ($p \approx 2^{255}$)              |
| $\mathbb{F}_q$   | Pallas scalar field                                  |
| $G$              | Pallas generator point                               |
| $H(a, b)$        | Poseidon hash (P128Pow5T3, width=3, rate=2)          |
| $\textsf{sk}$    | Spending key ($\in \mathbb{F}_q$)                    |
| $\textsf{pk}$    | Public key ($\textsf{sk} \cdot G \in \mathbb{G}$)    |
| $\textsf{owner}$ | Owner field ($\textsf{sk} \bmod p \in \mathbb{F}_p$) |
| $\textsf{vk}$    | Viewing key ($H(\textsf{owner}) \in \mathbb{F}_p$)   |
| $v$              | Note value ($\in [0, 2^{64})$)                       |
| $a$              | Asset ID ($\in [0, 2^{64})$, native = 0)             |
| $r$              | Randomness / blinding factor ($\in \mathbb{F}_q$)    |

---

## 3. Primitives

### 3.1 Poseidon Hash

Configuration: P128Pow5T3 — $x^5$ S-box, width 3, rate 2, $R_F = 8$ full
rounds, $R_P = 56$ partial rounds, targeting 128-bit security.

Two-input hash:
$$H(a, b) : \mathbb{F}_p \times \mathbb{F}_p \to \mathbb{F}_p$$

### 3.2 Note Commitment

A note $n = (\textsf{owner}, v, a, r)$ has commitment:
$$\textsf{cm} = H(H(H(\textsf{owner},\; v),\; a),\; r)$$

where $v$ and $a$ are embedded in $\mathbb{F}_p$ via their u64 representation.

### 3.3 Nullifier

Given spending key $\textsf{sk}$ and note commitment $\textsf{cm}$:
$$\textsf{nf} = H(\textsf{owner},\; \textsf{cm})$$

where $\textsf{owner} = \textsf{sk} \bmod p$.

A nullifier uniquely identifies a spent note. Publishing a nullifier reveals
nothing about the note's contents but prevents double-spending.

### 3.4 Merkle Tree

- Incremental append-only binary tree, depth 32 (~4 billion leaves)
- Internal nodes: $H(\textsf{left},\; \textsf{right})$
- Empty leaves: $\mathbb{F}_p\text{::zero}$
- Empty subtree hashes precomputed for each level

### 3.5 Key Derivation

```
BIP-39 mnemonic (256-bit entropy)
  └─ PBKDF2 seed (512 bits)
      └─ first 32 bytes → sk ∈ F_q
          ├─ pk = sk · G                (ECIES encryption)
          ├─ owner = sk mod p           (commitment owner field)
          ├─ vk = H(owner)              (note scanning)
          └─ tag = vk.to_repr()         (32-byte recipient tag)
```

### 3.6 Note Encryption (ECIES)

To encrypt a note for recipient with public key $\textsf{pk}_R$:

1. Sample ephemeral key $e \xleftarrow{\$} \mathbb{F}_q$
2. Compute $E = e \cdot G$ (ephemeral public key)
3. Compute shared point $S = e \cdot \textsf{pk}_R$
4. Derive key stream: $k_i = H(S_x,\; i)$ for $i = 0, 1$
5. Plaintext: $m = v \;\|\; a \;\|\; r_{\text{bytes}}$ (48 bytes)
6. Ciphertext: $c = m \oplus (k_0 \;\|\; k_1)$
7. MAC: $\textsf{tag} = H(S_x,\; H(c_{\text{left}},\; c_{\text{right}}))$
8. Wire format: $E \;\|\; c \;\|\; \textsf{tag}$ (112 bytes)

Decryption verifies MAC before decrypting (authenticate-then-decrypt).

### 3.7 Domain-Separated Nullifier (V2)

V2 nullifiers include a domain tag $(c, a)$ where $c$ is the chain ID and
$a$ is the application ID, both encoded as $\mathbb{F}_p$ elements:

$$\textsf{nf}_{\text{v2}} = H\bigl(H(\textsf{owner},\; \textsf{cm}),\; H(c,\; a)\bigr)$$

This ensures the same note produces distinct nullifiers on different chains
or applications, preventing cross-domain replay.

**Child nullifiers.** A parent nullifier can derive a child on a different
domain without revealing the parent:

$$\textsf{nf}_{\text{child}} = H\bigl(H(\textsf{nf}_{\text{parent}},\; c'),\; H(a',\; \textsf{nonce})\bigr)$$

The in-circuit path selects V1 or V2 based on whether domain fields are
present in the witness (`None` → V1, `Some` → V2).

**Migration path.** Existing V1 notes remain spendable indefinitely. To
upgrade a V1 note to V2, the owner performs a self-transfer with
`domain_chain_id` and `domain_app_id` set, burning the V1 nullifier and
producing new commitments bound to the target domain. No coordinated
upgrade is required — V1 and V2 coexist in the same Merkle tree.

### 3.8 Stealth Addresses

Stealth addresses allow a sender to create a one-time note owner that only
the intended recipient can detect and spend.

**Send (sender side):**

1. Sample ephemeral secret $r \xleftarrow{\$} \mathbb{F}_q$
2. Compute ephemeral public key $R = r \cdot G$
3. Compute shared point $S = r \cdot \textsf{pk}_{\text{recipient}}$
4. Compute tweak $t = H(S_x)$
5. Compute one-time owner $o = H(\textsf{pk}_{\text{recipient},x},\; t)$
6. Use $o$ as the note's owner field; publish $(R, o)$ as `StealthMeta`

**Receive (recipient side):**

1. Compute $S = \textsf{sk} \cdot R$
2. Compute $t = H(S_x)$, then $o' = H(\textsf{pk}_x,\; t)$
3. If $o' = o$, the note is addressed to this recipient

### 3.9 Proof Envelopes

All proofs are padded to a fixed 2048-byte `ProofEnvelope` before
transmission:

```
[ 4-byte LE length | payload (≤ 2044 bytes) | random padding ]
```

This prevents observers from inferring the operation type (transfer vs.
withdraw) based on proof size.

### 3.10 Epoch-Based Nullifier Partitioning

Nullifiers are grouped into time-bounded epochs (default 1 hour). At each
epoch boundary the set of nullifiers accumulated during that epoch is
finalized into a Merkle root:

$$\textsf{epoch\_root} = \text{BinaryMerkleRoot}(\textsf{nf}_1, \dots, \textsf{nf}_n)$$

The tree is padded to the next power of 2 with $\mathbb{F}_p\text{::zero}$
leaves. A bounded history of 256 epoch roots is maintained; older epochs
are pruned.

These epoch roots can be committed to the host chain via `RollupBridge::commit_nullifier_epoch_root()` and fetched from remote chains via `fetch_remote_nullifier_roots()` to enable cross-chain nullifier verification.

#### Cross-Chain Verification Workflow

When a note is spent on **Chain B** that was originally deposited on **Chain A**:

1. **Client** derives a V2 nullifier with `domain_chain_id = B`, `domain_app_id` set
   to the target application. The ZK proof attests to correct derivation.
2. **Chain B server** verifies the proof (which covers the domain-separated
   nullifier) and appends the nullifier to the current epoch set.
3. At epoch boundary, `epoch_root` is finalized and committed to Chain B's
   host-chain anchor via `commit_nullifier_epoch_root()`.
4. **Chain A** (or any observer) calls `fetch_remote_nullifier_roots(chain_b)` to
   obtain Chain B's finalized epoch roots.
5. The bridged epoch roots are imported into Chain A's bounded history, enabling
   Chain A to detect that the note has been spent on Chain B.

This ensures a note cannot be double-spent across chains as long as epoch roots
are relayed within the 256-epoch history window.

---

## 4. State

The privacy pool maintains:

| Field          | Type                    | Description                        |
| -------------- | ----------------------- | ---------------------------------- |
| `tree`         | Incremental Merkle tree | All note commitments (append-only) |
| `nullifiers`   | Set of $\mathbb{F}_p$   | Spent nullifier registry           |
| `root_history` | List of $\mathbb{F}_p$  | Last 256 Merkle roots              |
| `pool_balance` | u64                     | Total shielded value               |
| `event_log`    | List of events          | Append-only audit log              |

---

## 5. Operations

### 5.1 Deposit

**Input**: Note commitment $\textsf{cm} \in \mathbb{F}_p$, amount $v \in \mathbb{N}^+$.

**No proof required.** The depositor publicly shields value.

**Steps**:

1. Reject if $v = 0$.
2. Append $\textsf{cm}$ to the Merkle tree → leaf index $\ell$.
3. Record new Merkle root in `root_history`.
4. $\textsf{pool\_balance} \mathrel{+}= v$ (overflow check).
5. Emit `Deposit { cm, v, ℓ }`.

**Output**: $(\ell,\; \textsf{new\_root})$.

### 5.2 Transfer (2-in-2-out)

**Request**: $(π,\; \textsf{root},\; [\textsf{nf}_0, \textsf{nf}_1],\; [\textsf{cm}_0', \textsf{cm}_1'])$

where $\pi$ is a Halo2 proof.

**Public inputs** (instance column, 5 rows):

| Row | Value               |
| --- | ------------------- |
| 0   | Merkle root         |
| 1   | Nullifier 0         |
| 2   | Nullifier 1         |
| 3   | Output commitment 0 |
| 4   | Output commitment 1 |

**Circuit constraints** (for each input $i \in \{0, 1\}$):

1. **Commitment**: $\textsf{cm}_i = H(H(H(\textsf{sk}_i,\; v_i),\; a_i),\; r_i)$
2. **Merkle membership**: Recompute root from $\textsf{cm}_i$ + 32-level
   authentication path; constrain equal to public root.
3. **Nullifier**: $\textsf{nf}_i = H(\textsf{sk}_i,\; \textsf{cm}_i)$;
   constrain equal to public nullifier.
4. **Range check**: $0 \le v_i < 2^{64}$ (decomposition into bits).

For each output $j \in \{0, 1\}$:

5. **Commitment**: $\textsf{cm}_j' = H(H(H(\textsf{owner}_j,\; v_j'),\; a_j'),\; r_j')$;
   constrain equal to public output commitment.
6. **Range check**: $0 \le v_j' < 2^{64}$.

Global constraint:

7. **Value conservation**: $v_0 + v_1 = v_0' + v_1'$

**Verification steps**:

1. Check $\textsf{root} \in \textsf{root\_history}$.
2. Check $\textsf{nf}_0, \textsf{nf}_1 \notin \textsf{nullifiers}$.
3. Verify proof $\pi$ against public inputs.
4. Insert $\textsf{nf}_0, \textsf{nf}_1$ into `nullifiers`.
5. Append $\textsf{cm}_0', \textsf{cm}_1'$ to tree.
6. Emit `Transfer { nullifiers, output_commitments, leaf_indices }`.

**Pool balance is unchanged** (private-to-private).

### 5.3 Withdraw (2-in-2-out + exit)

**Request**: $(π,\; \textsf{root},\; [\textsf{nf}_0, \textsf{nf}_1],\; [\textsf{cm}_0', \textsf{cm}_1'],\; v_{\text{exit}},\; \textsf{recipient})$

**Public inputs** (instance column, 6 rows):

| Row | Value                        |
| --- | ---------------------------- |
| 0   | Merkle root                  |
| 1   | Nullifier 0                  |
| 2   | Nullifier 1                  |
| 3   | Output commitment 0 (change) |
| 4   | Output commitment 1 (change) |
| 5   | Exit value                   |

**Circuit constraints**: Same as transfer, except:

7'. **Value conservation with exit**: $v_0 + v_1 = v_0' + v_1' + v_{\text{exit}}$

8. **Exit range check**: $0 \le v_{\text{exit}} < 2^{64}$

**Verification steps**:

1. Reject if $v_{\text{exit}} = 0$.
2. Check $v_{\text{exit}} \le \textsf{pool\_balance}$.
3. Check $\textsf{root} \in \textsf{root\_history}$.
4. Check nullifier freshness.
5. Verify proof.
6. Insert nullifiers.
7. Append change commitments to tree.
8. $\textsf{pool\_balance} \mathrel{-}= v_{\text{exit}}$.
9. Emit `Withdraw { nullifiers, change_commitments, v_exit, recipient, leaf_indices }`.

---

## 6. Circuit Configuration

| Parameter               | Value                                           |
| ----------------------- | ----------------------------------------------- |
| Proof system            | Halo2 (IPA, zcash fork v0.3.2)                  |
| Curve                   | Pallas (proof witness) / Vesta (IPA commitment) |
| Circuit size ($k$)      | 13 (8192 rows)                                  |
| Advice columns          | 4                                               |
| Instance columns        | 1                                               |
| Fixed columns           | 6 (Poseidon round constants)                    |
| Planner                 | `SimpleFloorPlanner`                            |
| Transcript              | Blake2b (Challenge255)                          |
| Inputs per transaction  | 2                                               |
| Outputs per transaction | 2                                               |
| Merkle depth            | 32                                              |

---

## 7. Events

All state transitions emit public events:

```
Deposit  { commitment: F_p, amount: u64, leaf_index: u64 }
Transfer { nullifiers: [F_p; 2], output_commitments: [F_p; 2], leaf_indices: [u64; 2] }
Withdraw { nullifiers: [F_p; 2], change_commitments: [F_p; 2], amount: u64, recipient: [u8; 32], leaf_indices: [u64; 2] }
```

Events are appended to an immutable log and serialized with the pool state.

---

## 8. Security Properties

1. **Soundness**: A valid proof implies the prover knows spending keys for
   the input notes, the notes exist in the tree, nullifiers are correctly
   derived, and value is conserved.

2. **Zero-knowledge**: The proof reveals nothing about input notes, values,
   owners, or authentication paths beyond the public inputs.

3. **Double-spend prevention**: Each note can be spent exactly once —
   the nullifier is deterministic ($H(\textsf{sk}, \textsf{cm})$) and
   checked against a global registry.

4. **Balance integrity**: The pool balance equals the sum of all deposits
   minus the sum of all withdrawals. No private transfer can inflate or
   deflate the balance.

---

## 9. Wire Formats

### Proof bytes

Raw Halo2 IPA proof serialization (`create_proof` → `Vec<u8>`).
Deserialized via `verify_proof` with `Blake2bRead` transcript.

### Encrypted note (112 bytes)

```
[0..32]   Ephemeral public key (compressed Pallas point, x-coordinate)
[32..80]  Ciphertext (48 bytes: 8B value + 8B asset + 32B randomness)
[80..112] MAC tag (Poseidon-based, 32 bytes)
```

### State serialization

JSON format via serde. Field elements serialized as hex strings via custom
`serde_field` module. Merkle tree serialized as leaf array + filled subtrees.

---

## 10. BitVM2 Bridge Protocol

### Overview

The BitVM2 bridge enables trustless withdrawals from the Lumora privacy pool
to Bitcoin L1 using an optimistic verification protocol. An operator posts
a bonded assertion claiming the validity of a withdrawal proof. If no
challenger disputes the assertion within a timeout window, the withdrawal
is finalized and the operator reclaims their bond.

### Assertion Lifecycle

```
Pending ──► Challenged ──► Responded ──► Finalized
   │             │                          │
   │             └──► Slashed               │
   └────────────────────────────────────────┘
              (timeout → Finalized)
```

### Components

| Component         | Role                                                                  |
| ----------------- | --------------------------------------------------------------------- |
| `BitvmBridge`     | `RollupBridge` impl: poll deposits, execute withdrawals, commit roots |
| `BitvmVerifier`   | `OnChainVerifier` impl: verifies assertion reached Finalized state    |
| `Operator`        | Posts bonded assertions, responds to challenges                       |
| `Challenger`      | Monitors assertions, issues dispute at specific step                  |
| `ProtocolManager` | Assertion state machine (register/challenge/respond/slash/finalize)   |

### Adapters

14 adapters implement `RollupBridge` for chain-specific RPC communication:
Citrea, BOB, BitLayer, Merlin, BEVM, Babylon, Stacks/sBTC, RGB, Lightning,
Liquid, Ark, Rooch, Bison, and EMVCo QR.
