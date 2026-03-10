# Lumora Circuit Constraints Reference

This document describes every constraint enforced by Lumora's Halo2 ZK circuits.

## Curve & Field

- **Curve:** Pallas (`pasta_curves::pallas`)
- **Base field:** F_p (Pallas base field, ~255 bits)
- **Circuit size:** k = 13 → 2^13 = 8192 rows

## Poseidon Hash Specification

Defined in `crates/lumora-primitives/src/poseidon.rs`.

| Parameter      | Value        |
| -------------- | ------------ |
| Spec           | `P128Pow5T3` |
| Width (t)      | 3            |
| Rate           | 2            |
| S-box          | x^5          |
| Full rounds    | 8            |
| Partial rounds | 56           |
| Security       | 128-bit      |

Two primitives:

- `hash_two(left, right)` — Poseidon with `ConstantLength<2>` (Merkle nodes, nullifiers, commitments)
- `hash_one(input)` — Poseidon with `ConstantLength<1>` (single element, zero-padded)

The same spec is used both natively and in-circuit (via `Pow5Chip`), ensuring consistency.

---

## 1. Transfer Circuit

Source: `crates/lumora-circuits/src/transfer.rs`

A **2-input, 2-output** private transfer.

### Public Inputs (Instance Column) — 5 total

| Row | Field               | Meaning                                            |
| --- | ------------------- | -------------------------------------------------- |
| 0   | Merkle root         | Current state root of the note commitment tree     |
| 1   | Nullifier 0         | Nullifier for input note 0 (prevents double-spend) |
| 2   | Nullifier 1         | Nullifier for input note 1                         |
| 3   | Output commitment 0 | Commitment for the first output note               |
| 4   | Output commitment 1 | Commitment for the second output note              |

Constant: `NUM_PUBLIC_INPUTS = 1 + 2 + 2 = 5`

### Private Inputs (Witness)

**Per input note (×2):**

| Witness              | Description                                        |
| -------------------- | -------------------------------------------------- |
| `spending_key`       | Owner's secret spending key (scalar in base field) |
| `value`              | Note value (constrained to u64)                    |
| `asset`              | Asset type identifier                              |
| `randomness`         | Blinding factor for the commitment                 |
| `commitment`         | Note's Poseidon commitment (verified in-circuit)   |
| `merkle_path[0..32]` | Sibling hashes on the authentication path          |
| `merkle_index`       | Leaf position (decomposed into 32 direction bits)  |

**Per output note (×2):**

| Witness      | Description                         |
| ------------ | ----------------------------------- |
| `owner`      | Recipient's public key (base field) |
| `value`      | Note value (constrained to u64)     |
| `asset`      | Asset type identifier               |
| `randomness` | Blinding factor for the commitment  |

### Column Layout

| Column Type | Count | Purpose                                                                                      |
| ----------- | ----- | -------------------------------------------------------------------------------------------- |
| Advice      | 4     | Witness assignment; `[0..2]` Poseidon state, `[3]` partial S-box                             |
| Instance    | 1     | Public inputs                                                                                |
| Fixed       | 6     | `[0..2]` round constants `rc_a`, `[3..5]` round constants `rc_b`; `[3]` also constant column |

### Constraint Gates

**C1 — Note Commitment Verification** (per input):

```
commitment = H(H(H(spending_key, value), asset), randomness)
```

Three nested Poseidon hashes:

1. `inner = Poseidon(spending_key, value)`
2. `content = Poseidon(inner, asset)`
3. `computed = Poseidon(content, randomness)`

Then: `constrain_equal(computed, provided_commitment)`

**C2 — Output Commitment Computation** (per output):

```
commitment = H(H(H(owner, value), asset), randomness)
```

Same structure as input commitment but uses `owner` (public key) instead of `spending_key`.

**C3 — Merkle Path Verification** (per input, 32 levels):

For each level i (0..31):

```
left_i  = current + bit_i * (sibling - current)
right_i = sibling + bit_i * (current - sibling)
current_{i+1} = H(left_i, right_i)
```

Where `bit_i` is the i-th bit of `merkle_index`. Both input roots are constrained equal to instance row 0.

**C4 — Nullifier Derivation** (per input):

```
nullifier = H(spending_key, commitment)
```

Exposed as instance rows 1 and 2.

**C4' — V2 Nullifier Derivation (Domain-Separated)**:

When domain fields are provided, the nullifier uses a 4-input Poseidon hash
for cross-chain replay protection:

```
nullifier = H4(spending_key, commitment, chain_id, app_id)
```

Where `H4` is the Poseidon `ConstantLength<4>` variant. This ensures nullifiers
are unique per (chain, application) pair, preventing cross-domain replay. The
V1 derivation (`H(sk, cm)`) remains the default when domain fields are absent.

**C5 — Value Conservation**:

```
input_value_0 + input_value_1 = output_value_0 + output_value_1
```

Computed via running addition in `sum_values`, then `constrain_equal(input_sum, output_sum)`.

**C6 — Range Checks (u64)**:

All 4 values (2 input + 2 output) are range-checked to 64 bits. See Range Check Gadget below.

---

## 2. Withdraw Circuit

Source: `crates/lumora-circuits/src/withdraw.rs`

A **2-input, 2-output** withdrawal where value can exit the shielded pool.

### Public Inputs (Instance Column) — 6 total

| Row | Field               | Meaning                               |
| --- | ------------------- | ------------------------------------- |
| 0   | Merkle root         | Current state root                    |
| 1   | Nullifier 0         | Input note 0 nullifier                |
| 2   | Nullifier 1         | Input note 1 nullifier                |
| 3   | Output commitment 0 | Output note 0 commitment (change)     |
| 4   | Output commitment 1 | Output note 1 commitment (change)     |
| 5   | Exit value          | Amount leaving the pool (public, u64) |

Constant: `NUM_WITHDRAW_PUBLIC_INPUTS = 1 + 2 + 2 + 1 = 6`

### Shared Logic

Reuses the same `TransferConfig`, `synthesize_input`, and `synthesize_output` functions. Gates C1, C2, C3, C4, and C6 apply identically.

### Modified Constraint — Value Conservation with Exit

**C5' — Value Conservation (Withdraw)**:

```
input_value_0 + input_value_1 = output_value_0 + output_value_1 + exit_value
```

`exit_value` is also range-checked to u64 (5 range checks total).

---

## 3. Range Check Gadget

Source: `crates/lumora-circuits/src/gadgets/range_check.rs`

**Strategy:** Successive halving (bit decomposition from LSB).

Custom gate with two constraints per row:

```
Boolean:       b_i * (1 - b_i) = 0        (forces b_i ∈ {0, 1})
Decomposition: q_i = 2 * q_{i+1} + b_i
```

Where:

- q_0 = value (copy-constrained from the value cell)
- q_64 = 0 (constrained via constant column)
- b_i = the i-th bit

**Layout:** 65 rows per range check. After 64 halvings reaching zero, value = Σ(b_i · 2^i) < 2^64.

This prevents **overflow attacks** — without this check, a prover could use negative field values (wrapping around in F_p) to satisfy value conservation while creating value out of nothing.

---

## 4. Poseidon Chip (In-Circuit)

Source: `crates/lumora-circuits/src/gadgets/poseidon_chip.rs`

Wraps `halo2_gadgets::poseidon::Pow5Chip` with the same `P128Pow5T3` spec used natively.

- 3 advice columns (state) + 1 advice column (partial S-box)
- 6 fixed columns (round constants `rc_a[3]` + `rc_b[3]`)
- Exposes `hash_two(layouter, left, right) → AssignedCell`

---

## 5. Merkle Tree Parameters

- **Depth:** 32
- **Capacity:** 2^32 ≈ 4.3 × 10^9 notes
- Each path verification: 32 Poseidon hashes + 32 conditional swaps

---

## 6. Summary of All Enforced Constraints

| #   | Constraint                 | Equation                                 | Scope           |
| --- | -------------------------- | ---------------------------------------- | --------------- |
| C1  | Input commitment           | cm = H(H(H(sk, v), a), r)                | Per input (×2)  |
| C2  | Output commitment          | cm = H(H(H(owner, v), a), r)             | Per output (×2) |
| C3  | Merkle membership          | 32-level path hashing yields public root | Per input (×2)  |
| C4  | Nullifier derivation       | nf = H(sk, cm)                           | Per input (×2)  |
| C5  | Value conservation (xfer)  | Σv_in = Σv_out                           | Global          |
| C5' | Value conservation (wdraw) | Σv_in = Σv_out + v_exit                  | Global          |
| C6  | Value range (u64)          | 0 ≤ v < 2^64 via 64-bit decomposition    | Per value       |
| C7  | Bit boolean                | b_i(1 - b_i) = 0 for Merkle index bits   | Per bit (×32×2) |
| C8  | Root equality              | Both input roots == instance[0]          | Global          |
| C9  | Nullifier exposure         | nf → instance[1], instance[2]            | Per input       |
| C10 | Commitment exposure        | cm → instance[3], instance[4]            | Per output      |
| C11 | Exit value exposure        | exit_value → instance[5]                 | Withdraw only   |

## 7. Circuit Size Estimate

With k = 13 (8192 rows):

- **Poseidon hashes per transfer:** 2×(3 commitment + 32 Merkle + 1 nullifier) + 2×(3 commitment) = 78 invocations
- **Range checks:** 4 × 65 = 260 rows (transfer), 5 × 65 = 325 rows (withdraw)
- Each Poseidon hash ≈ 64 rows (8 full + 56 partial rounds)
- Total Poseidon rows ≈ 78 × 64 ≈ 4,992 rows

Fits comfortably in 2^13 with room for advice assignment regions and value summation logic.
