# ADR-003: 2-Input 2-Output Circuit Design

## Status

Accepted

## Context

The circuit must prove private transfers within a UTXO-based shielded pool. The key question is how many inputs and outputs per transaction.

## Decision

Use a fixed **2-input, 2-output** circuit for both transfers and withdrawals.

## Rationale

- **Covers the common case**: One input is the "spent note," the second is a padding/change note; one output goes to the recipient, the other is change back to the sender.
- **Value conservation**: The circuit enforces `Σ(input values) = Σ(output values)` (or `= Σ(output values) + exit_value` for withdrawals).
- **Minimal public surface**: 5 public inputs for transfers (root, 2 nullifiers, 2 commitments), 6 for withdrawals (+exit_value).
- **Circuit proves 5 properties simultaneously**: Merkle membership, ownership, value conservation, nullifier correctness, output well-formedness.
- **Production precedent**: Mirrors Zcash Sapling/Orchard's approach, proven in production.
- **Fits in K=13**: The 2-in-2-out design with depth-32 Merkle paths requires ~5,500 rows, fitting within 8,192.

## Consequences

- Transactions requiring more than 2 inputs need multiple rounds (the `consolidate` function handles this for dust notes).
- Padding notes with zero value are used when fewer inputs/outputs are needed.
- Consistency across transfer and withdrawal circuits — `WithdrawCircuit` reuses `TransferConfig` and `synthesize_input`/`synthesize_output` functions.
