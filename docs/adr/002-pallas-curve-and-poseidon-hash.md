# ADR-002: Pallas Curve and Poseidon Hash

## Status

Accepted

## Context

The proving system requires a base field and a hash function. The hash function is used for:

- Merkle tree internal nodes (32 levels)
- Note commitments: `cm = H(H(H(owner, value), asset), randomness)`
- Nullifier derivation: `nf = H(spending_key, commitment)`
- Key derivation (BIP-32 style child keys)

The hash must be efficient both natively and inside the Halo2 circuit.

## Decision

Use **Pallas** (`pasta_curves::pallas`) as the primary curve and **Poseidon** with the `P128Pow5T3` spec (width 3, rate 2, x^5 S-box, 8 full rounds, 56 partial rounds, 128-bit security).

## Rationale

### Pallas Curve

- Native to Halo2-IPA — all arithmetic operates directly in the Pallas base field with no conversion overhead.
- Part of the Pasta cycle (Pallas/Vesta), enabling the scalar field of one curve to equal the base field of the other, making key and signature integration natural.
- Supported by `group 0.13` and `ff 0.13` for generic field/group operations.

### Poseidon Hash

- **ZK-circuit-efficient**: Far fewer multiplicative constraints per hash compared to SHA-256 or Blake2 in a finite field circuit.
- **Consistent**: The same `P128Pow5T3` spec is used both natively (for Merkle tree computation, prover-side) and in-circuit (via `Pow5Chip` from `halo2_gadgets`).
- **Gadget support**: `halo2_gadgets 0.3` provides a ready-made `Pow5Chip` implementation, avoiding custom circuit code.
- **128-bit security** with well-analyzed round counts.

## Consequences

- All note values, commitments, nullifiers, and tree nodes are `pallas::Base` field elements.
- Hash computation uses ~64 rows per invocation in the circuit (8 full + 56 partial rounds).
- Interoperability with non-Pallas systems requires field element encoding/decoding.
