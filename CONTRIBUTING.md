# Contributing to Lumora

Thank you for your interest in contributing to Lumora!

## Getting started

```sh
git clone https://github.com/lumora/lumora.git
cd lumora
cargo build --workspace
cargo test --workspace --lib -- --test-threads=1
```

**Requirements**:

- Rust 1.75+ (stable toolchain)
- 4 GB RAM minimum (ZK proving is memory-intensive; 8 GB recommended)
- Node.js 18+ and npm (for TypeScript SDK development)

## Project Layout

| Crate               | Purpose                                                            |
| ------------------- | ------------------------------------------------------------------ |
| `lumora-primitives` | Poseidon hash, Pedersen commitments, proof envelopes, field types  |
| `lumora-note`       | Note model, spending/viewing keys, ECIES encryption, stealth addrs |
| `lumora-tree`       | Incremental Merkle tree (depth 32, Poseidon hash)                  |
| `lumora-circuits`   | Halo2 ZK circuits (transfer, withdraw, wealth proof, aggregation)  |
| `lumora-prover`     | Proof generation, setup, async proving pipeline                    |
| `lumora-verifier`   | Proof verification, batch verification                             |
| `lumora-contracts`  | Privacy pool state machine, WAL, snapshots, epoch/compliance/gov   |
| `lumora-node`       | Prover daemon, note store, batch accumulator, mempool, peer sync   |
| `lumora-client`     | Client wallet, key management, coin selection                      |
| `lumora-sdk`        | High-level SDK combining client + prover                           |
| `lumora-cli`        | Interactive CLI wallet (binary)                                    |
| `lumora-rpc`        | Axum HTTP server, handlers, middleware, background tasks (binary)  |

TypeScript SDK: `sdks/typescript/` — see [docs/typescript-sdk.md](docs/typescript-sdk.md).

## Development Workflow

### Branch naming

- `feat/<short-name>` — new features
- `fix/<short-name>` — bug fixes
- `docs/<short-name>` — documentation changes
- `refactor/<short-name>` — code restructuring

### Making changes

1. **Create a branch** from `main`.
2. **Write tests** for any new functionality.
3. **Run the full suite** before opening a PR:

   ```sh
   # Rust checks
   cargo fmt --all -- --check
   cargo clippy --workspace -- -D warnings
   cargo test --workspace --lib -- --test-threads=1

   # TypeScript SDK (if modified)
   cd sdks/typescript && npm run build && npm test
   ```

4. **Keep commits focused** — one logical change per commit.
5. **Update documentation** if you change public APIs or add features.

### Commit messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
feat(rpc): add stealth-scan endpoint
fix(contracts): prevent balance overflow on deposit
docs: update API guide with epoch-roots endpoint
test(circuits): add V2 nullifier domain separation tests
```

### Pull request checklist

- [ ] Tests pass locally (`cargo test --workspace --lib`)
- [ ] No clippy warnings (`cargo clippy --workspace -- -D warnings`)
- [ ] Code formatted (`cargo fmt --all -- --check`)
- [ ] Documentation updated (if public API changed)
- [ ] CHANGELOG.md updated (for non-trivial changes)
- [ ] TypeScript SDK updated (if RPC types changed)

## Code style

- Follow standard `rustfmt` defaults.
- Keep `clippy` warnings at zero (`-D warnings`).
- Use `tracing` for structured logging, not `println!` or `eprintln!`.
- Prefer returning `Result` over panicking.
- Use `subtle::ConstantTimeEq` for security-sensitive comparisons.
- Use `zeroize` for key material cleanup.

## Security

If you discover a security vulnerability, **do not open a public issue**.
Please follow the process described in [SECURITY.md](SECURITY.md).

## Testing

| Type              | Location                             | Run Command                                         |
| ----------------- | ------------------------------------ | --------------------------------------------------- |
| Unit tests        | `#[cfg(test)]` modules in each crate | `cargo test --lib`                                  |
| RPC tests         | `crates/lumora-rpc/src/rpc_tests.rs` | `cargo test -p lumora-rpc --lib`                    |
| Integration tests | `tests/` directory                   | `cargo test -p lumora-contracts --test cross_crate` |
| Property tests    | `proptest` in lumora-contracts       | `cargo test -p lumora-contracts proptest`           |
| Benchmarks        | `benches/` directory                 | `cargo bench -p lumora-contracts`                   |
| TypeScript SDK    | `sdks/typescript/src/lumora.test.ts` | `cd sdks/typescript && npm test`                    |

ZK proof generation tests are slow (~60-240s each). These run automatically
in CI with a 30-minute timeout. Locally you can run them with:

```sh
cargo test -p lumora-node daemon -- --test-threads=1
```

### Fuzz testing

Lumora includes [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets
in the `fuzz/` directory. Install cargo-fuzz and run a target:

```sh
cargo install cargo-fuzz
# List available targets
cargo +nightly fuzz list
# Run a specific target for 60 seconds
cargo +nightly fuzz run fuzz_envelope_seal_open -- -max_total_time=60
```

Available fuzz targets:

- `fuzz_envelope_seal_open` — proof envelope padding/extract roundtrip
- `fuzz_field_hex_parse` — hex → field element parsing (DoS resistance)
- `fuzz_transfer_json` — TransferRequest/WithdrawRequest JSON parsing
- `fuzz_wal_entry` — WAL entry recovery from corrupted data

### Adding tests

- Place unit tests in the same file as the code under `#[cfg(test)]`.
- Use `tracing_subscriber` in test setup for debugging.
- For RPC tests, follow the pattern in `rpc_tests.rs` — create a test node,
  build the router, and use `axum::body::to_bytes` for assertions.

## Debugging Tips

- **Proof generation failures**: Check that the witness satisfies all
  constraints by running with `MockProver::run()` first. It gives detailed
  constraint error messages that `create_proof` does not.
- **State inconsistencies**: Enable `RUST_LOG=lumora_contracts=debug` to see
  every state transition (deposit, transfer, withdraw) with nullifiers and
  root changes.
- **RPC issues**: Use `RUST_LOG=lumora_rpc=trace` to see request/response
  details including proof sizes and handler timing.

## Documentation Contributions

- API changes → update `docs/api-guide.md`
- New features → add to CHANGELOG.md and relevant docs
- Architecture changes → update `docs/architecture.md`
- Circuit changes → update `docs/circuit-constraints.md` and `PROTOCOL.md`

## Licensing

Lumora is dual-licensed under MIT and Apache 2.0. By contributing, you
agree that your contributions will be licensed under the same terms.
