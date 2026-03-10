# ADR-001: Halo2 with IPA Proving System

## Status

Accepted

## Context

Lumora requires a zero-knowledge proof system for private transfers and withdrawals. The proof system must:

- Support custom arithmetic circuits over a prime field
- Avoid trusted setup ceremonies (transparent SRS)
- Have a mature, audited implementation
- Support batch verification for throughput

## Decision

Use **halo2_proofs 0.3** (Zcash fork) with the **Inner Product Argument (IPA)** polynomial commitment scheme over the Pallas/Vesta curve cycle.

## Rationale

- **No trusted setup**: IPA is transparent — the structured reference string is deterministic from public randomness, eliminating trust assumptions and deployment bottlenecks.
- **Recursive-friendly**: The Pallas/Vesta curve cycle enables efficient recursive proof composition, future-proofing for batched or incremental verification.
- **Production-proven**: The Zcash Halo2 fork is battle-tested in the Orchard shielded pool.
- **Batch verification**: The `batch` feature enables amortized verification across multiple proofs (used by `/batch-verify`).
- **Linear SRS**: IPA SRS is K group elements (8192 at K=13), trivial to generate and store compared to KZG ceremonies.

## Consequences

- Circuit development uses the Halo2 API (advice/instance/fixed columns, custom gates, chip pattern).
- Proof size is larger than SNARK systems with KZG (~O(sqrt(n)) vs O(1)), but verification is still fast.
- K=13 (8192 rows) is sufficient for 2-in-2-out circuits with depth-32 Merkle paths, keeping proving time low.
