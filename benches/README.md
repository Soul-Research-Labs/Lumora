# Benchmarks

Criterion benchmarks live in each crate's `benches/` directory:

| Crate              | Bench            | What it measures                                 |
| ------------------ | ---------------- | ------------------------------------------------ |
| `lumora-prover`    | `proof_bench`    | SRS setup, transfer proof generation             |
| `lumora-tree`      | `tree_bench`     | Poseidon hash, Merkle insert, root computation   |
| `lumora-contracts` | `contract_bench` | Deposit execution, sequential deposit throughput |

## Running

```sh
# Run all benchmarks
cargo bench

# Run a specific benchmark
cargo bench --bench tree_bench
cargo bench --bench proof_bench
cargo bench --bench contract_bench
```

Results are saved in `target/criterion/` with HTML reports.
