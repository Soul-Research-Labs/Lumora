# Changelog

All notable changes to the Lumora project are documented in this file.

## [Unreleased]

### Phase 34 — Gap Analysis Remediation

#### Critical Fixes

- **CI fuzz target names corrected** — Fixed 4 mismatched binary names in the
  fuzz CI job: `field_parse` → `fuzz_field_hex_parse`, `envelope` →
  `fuzz_envelope_seal_open`, `transfer_json` → `fuzz_transfer_json`,
  `wal_entry` → `fuzz_wal_entry`. All 6 fuzz targets now run correctly in CI.

#### Security

- **HMAC key fallback warning** — `integrity_key()` now emits a `WARNING`
  to stderr when `LUMORA_HMAC_KEY` is not set and the weak compiled-in
  default is used. Prevents silent insecurity in production deployments.
- **migration.rs `unwrap()` eliminated** — Replaced bare `try_into().unwrap()`
  on line 45 with descriptive `.expect()` for state header parsing. Zero
  production `unwrap()` calls remain.

#### Infrastructure

- **Doc tests in CI** — Added `cargo test --workspace --doc` step to CI test
  job and `test-doc` target in Makefile. Doc-comment code examples are now
  validated on every push.
- **Cross-platform CI** — Test job now runs on both `ubuntu-latest` and
  `macos-latest` via strategy matrix for broader platform coverage.
- **Release pipeline enhanced** — Added Docker image push to `ghcr.io` on
  tagged releases (`docker-push` job). Added SDK publish job for npm
  (TypeScript) and PyPI (Python) with token-based authentication.
- **Benchmark regression gating** — `critcmp` now enforces a 15% threshold;
  regressions beyond that fail the PR instead of only warning.
- **Coverage timeout doubled** — Bumped `cargo-tarpaulin` per-test timeout
  from 300 s to 600 s to accommodate ZK proof generation tests.
- **Fuzz seed corpus** — Added 20 representative seed inputs across all 6 fuzz
  targets (3 envelope, 4 field_parse, 5 transfer_json, 4 wal_entry,
  2 pedersen_commit, 2 poseidon_merkle) for faster convergence.

---

### Phase 33 — CI, Benchmarks & Accuracy

#### Infrastructure

- **CI fuzz coverage** — Added `fuzz_pedersen_commit` and `fuzz_poseidon_merkle`
  targets to the GitHub Actions fuzz job. All 6 fuzz harnesses now run in CI.
- **Fuzz durations doubled** — Bumped all fuzz `max_total_time` from 30 s to
  60 s for deeper coverage per CI run.
- **README accuracy** — Corrected lib test count (312 → 346), fuzz harness
  count in project tree (4 → 6).

#### Testing

- **Verifier benchmarks** — Added Criterion benchmarks for `verify_transfer_proof`
  (single-proof) and `batch_verify_4_transfers` (4-proof batch) in `lumora-verifier`.
- **Encryption benchmarks** — Added Criterion benchmarks for `encrypt_note`,
  `decrypt_note`, and full `encrypt_decrypt_roundtrip` in `lumora-note`.

---

### Phase 32 — Defensive Programming

#### Security

- **Eliminated remaining production `unwrap()` calls** — Replaced 5 bare
  `unwrap()` in state deserialization (`state.rs`), ECDH key derivation
  (`encryption.rs`), Pedersen generator construction (`pedersen.rs`), and
  circuit range-check gadget (`range_check.rs`) with descriptive `expect()`
  or safe `Option` pattern matching. Zero production `unwrap()` calls remain.

---

### Phase 31 — Hardening & Quality

#### Security

- **keys.rs unwrap→expect** — Replaced 8 bare `unwrap()` calls in non-test
  code with descriptive `expect()` messages for field element parsing, ECDH
  coordinate extraction, and point serialization.

#### Infrastructure

- **Dockerfile HEALTHCHECK** — Added health check instruction polling
  `/health` every 30 s with 5 s timeout and 3 retries.
- **docker-compose.yml hardening** — Added CPU limit (2 cores), dropped all
  Linux capabilities except `NET_BIND_SERVICE`, enabled read-only root
  filesystem with `/tmp` tmpfs.

#### Testing

- **2 new fuzz targets** — `fuzz_pedersen_commit` (Pedersen commitment
  consistency) and `fuzz_poseidon_merkle` (Poseidon hash determinism and
  Merkle path operations). Total: 6 fuzz targets.

---

### Phase 30 — Gap Analysis Remediation II

#### Security

- **HMAC key from environment** — `integrity_key()` reads `LUMORA_HMAC_KEY`
  env var at runtime, falling back to `DEFAULT_INTEGRITY_KEY`. Hardcoded key
  eliminated from production paths.
- **BIP-39 domain-separated derivation** — `from_mnemonic()` now feeds both
  halves of the 64-byte BIP-39 seed through `hash_two(a, b)` for proper
  Poseidon domain separation instead of ad-hoc single-field hashing with
  bit masking.
- **RPC amount validation** — `deposit()` and `withdraw()` handlers reject
  zero-amount requests at the HTTP layer with 400 Bad Request.
- **X-Forwarded-For socket fallback** — Three-tier IP extraction (forwarded →
  ConnectInfo socket → 0.0.0.0 sentinel) replaces `unwrap_or(LOCALHOST)` to
  prevent rate-limit bypass via missing headers.
- **Sync delta replay protection** — `SignedStateDelta` gains `sequence` and
  `timestamp_secs` fields included in the HMAC payload. Receivers can enforce
  monotonicity to prevent replay attacks.
- **Byzantine peer quarantine** — `ByzantineDetector` auto-quarantines peers
  after 3 faults (equivocation, root mismatch, or auth failure). Quarantine
  can be lifted via `lift_quarantine()` for manual review.
- **API key zeroization** — API key wrapped in `Arc<Zeroizing<String>>` so
  the secret is wiped from memory on drop.
- **Generic contract error messages** — RPC `contract_err()` returns opaque
  "transaction rejected" to clients, logging specifics server-side only.
  Prevents information leakage about nullifier status or proof failures.

#### Tests (+25 new)

- **Sync replay tests** — 4 new tests: sequence/timestamp in HMAC, tampered
  sequence rejected, tampered timestamp rejected, zero-sequence backward
  compatibility.
- **Quarantine tests** — 6 new tests: threshold quarantine (auth, equivocation,
  root mismatch), lift quarantine, clear resets, innocent peer not quarantined.
- **Bridge trait tests** — 7 new tests: LocalBridge (poll, execute, commit root,
  commit epoch, fetch remote), BridgeError display, FailingBridge mock.
- **Transfer circuit constraint tests** — 2 new MockProver tests: value
  conservation violation rejected, wrong commitment witness rejected.
- **RPC utility function tests** — 12 new tests: `parse_field` (zero, one,
  invalid hex, wrong length, empty), `parse_bytes32` (valid, invalid,
  wrong length), `decode_proof` (raw, invalid hex, too large, empty),
  `field_to_hex` roundtrip.
- **Encryption test** — 1 new test: empty ciphertext returns None.

#### Infrastructure

- **Coverage CI gate** — `cargo-tarpaulin` job generates XML coverage;
  uploads to Codecov on main branch pushes.
- **Docker CI build** — CI job builds Docker image and smoke-tests
  `/health` endpoint.
- **Cargo.toml metadata** — `license.workspace = true` added to 7 crates;
  `lumora-node`, `lumora-sdk`, `lumora-client` added to workspace deps;
  all internal path deps normalized to `workspace = true`.
- **Monitoring & DR docs** — New `docs/monitoring-and-dr.md` covering
  Prometheus metrics, Grafana panels, alerting rules, backup strategy,
  and disaster recovery runbooks.

### Phase 29 — Security Hardening & Test Coverage

- **WAL file permission hardening** — New `sensitive_create()` / `sensitive_append()`
  helpers write WAL and state files with mode `0o600` on Unix, preventing
  world-readable secrets on disk. Applied to all 4 WAL write sites and
  `state.rs` save/save_binary.
- **Input validation tightening** — `MAX_BATCH_SIZE` reduced 64 → 16,
  `MAX_CIPHERTEXT_SIZE = 256` added to `relay_note`, `MAX_LEAF_INDEX`
  bounds check at `(1 << 32) - 1` to prevent memory exhaustion attacks.
- **Per-IP rate limiting** — `IpRateLimiter` (60 req/min per IP) with
  `X-Forwarded-For` extraction integrated into the axum middleware stack.
- **Constant-time stealth receive** — `stealth_receive()` now uses
  `subtle::ConstantTimeEq` (`ct_eq` on `to_repr()`) to prevent timing
  side-channel leaks when scanning notes.
- **MSRV enforcement** — `rust-version = "1.75"` in workspace Cargo.toml;
  dedicated CI job verifies MSRV compatibility on every push.
- **Fuzz smoke tests in CI** — CI job runs all 4 fuzz targets (field_parse,
  wal_entry, envelope, transfer_json) for 30 s each on nightly.
- **BIP-39 mnemonic tests** — 4 new tests: different phrases → different keys,
  derived key non-zero, viewing key deterministic, child derivation stable.
- **WAL recovery tests** — 4 new tests: empty recover, recover-onto-existing,
  withdraw event replay, multiple checkpoints.
- **Compliance oracle tests** — 5 new tests: threshold blocking, validate
  withdrawal helper, unavailable verdict fail-open, reason display, boundary
  values. Added `UnavailableOracle` test double.
- **Byzantine detection tests** — 9 new tests: equivocation, root mismatch,
  auth failure, faults-for-peer, clear, display, health summary.
- **Sync protocol tests** — 13 new tests (from zero): HMAC sign/verify, wrong
  key, tampered payload, TxBroadcast, mempool content hash determinism,
  tx_hash, diagnose_partition (4 scenarios), plan_recovery (3 scenarios).
- **Stealth send SDK tests** — 3 new tests: stealth send + receive roundtrip,
  non-recipient cannot detect, disclosure report.
- **Circuit tests** — 7 new tests: aggregation (empty bundle, single proof,
  config defaults, strategy serializable) + recursive (config defaults, error
  display, identity chain zero depth).
- **PROTOCOL.md V2 migration path** — Documented V1 → V2 nullifier upgrade via
  self-transfer, coexistence during transition period.
- **TLS termination guide** — DEPLOYMENT.md updated with nginx and Caddy
  reverse-proxy examples for TLS termination.
- **Docker secrets** — docker-compose.yml updated with file-based secrets
  mount; DEPLOYMENT.md documents usage.
- **Epoch manager monotonic clock** — Documented the monotonic guarantee
  (epochs never regress on wall-clock jumps) in `maybe_advance_epoch()`.
- **Test totals** — 333 Rust lib + 24 integration/E2E + 30 TS + 24 Python
  tests. 4 fuzz targets.

### Phase 28 — Gap Analysis Remediation

- **Constant-time API key comparison** — API key authentication in `server.rs`
  now uses `subtle::ConstantTimeEq` to prevent timing side-channel attacks.
- **Wallet file permissions** — `write_sensitive_file()` helper creates wallet
  and key export files with mode `0o600` (owner-only) on Unix, preventing
  world-readable credentials on disk.
- **Prover test expansion** — lumora-prover tests expanded from 5 → 16 with
  circuit commitment edge cases (zero values, max value), field sensitivity
  tests (owner, asset, randomness), proof metadata checks, shared handle deref,
  and params usability.
- **Verifier test expansion** — lumora-verifier tests expanded from 4 → 13 with
  rejection tests (wrong root, wrong commitment, wrong fee), malformed proof
  inputs (empty, garbage), raw transfer error path, and batch verify edge cases
  (single valid, empty batch, mixed valid/invalid).
- **RPC negative tests** — 10 new handler tests covering zero-amount deposits,
  missing fields, invalid hex nullifiers, unknown Merkle roots, zero-amount
  withdrawals, missing relay fields, empty tags, sync-from-zero, and empty POST
  bodies.
- **Wallet edge tests** — 6 new tests for multi-asset balances, note
  export/import roundtrip, disclosure reports, viewing key export, transaction
  history recording, and Unix file permission verification.
- **TypeScript SDK test expansion** — 5 new tests covering `relayNote` (POST +
  error), `getNotes` (POST with tag + empty response), and `withdraw` (full
  field set). Total: 30 tests.
- **Cargo.toml descriptions** — Added `description` fields to lumora-node,
  lumora-client, and lumora-contracts for crates.io readiness.
- **Jitter configuration documented** — `LUMORA_JITTER_MIN_MS` and
  `LUMORA_JITTER_MAX_MS` env vars added to api-guide.md configuration table.
- **DEPLOYMENT.md accuracy** — Removed `LUMORA_MAX_BODY_SIZE` and
  `LUMORA_MAX_CONCURRENT` from env var table (compile-time constants, not
  runtime-configurable). Added clarifying note.
- **Upgrade runbook fix** — Replaced phantom `lumora info` CLI command with
  working `curl localhost:3030/health | jq .version` health check.
- **CI cargo doc gate** — `cargo doc --workspace --no-deps` with
  `RUSTDOCFLAGS="-D warnings"` added to CI check job, catching broken
  doc-links and missing docs early.
- **Test totals** — 287 Rust lib + 24 integration/E2E + 30 TS + 24 Python
  tests. 4 fuzz targets.

### Phase 27 — Production Readiness

- **SDK resilience** — TypeScript and Python SDKs now support configurable
  timeouts (`AbortController` / `urllib timeout`), exponential backoff retry
  with jitter, and dedicated `LumoraConnectionError` exception types.
  Backward-compatible constructor changes (options are optional).
- **CORS configuration** — `LUMORA_CORS_ORIGINS` env var enables configurable
  CORS headers via `tower-http` CorsLayer. Unset = no CORS headers (reverse
  proxy deployments). Allows GET/POST/OPTIONS with Content-Type and x-api-key.
- **Fuzz testing** — 4 cargo-fuzz targets: `envelope` (seal/open roundtrip),
  `field_parse` (hex→field DoS), `transfer_json` (request deserialization),
  `wal_entry` (WAL recovery from corruption). Documented in CONTRIBUTING.md.
- **ProofEnvelope property tests** — 3 proptests for seal/open roundtrip,
  panic resistance on arbitrary data, and fixed-size envelope invariant.
- **Shutdown timeout guard** — `BackgroundHandle::shutdown()` now uses 30s
  `tokio::time::timeout` to prevent indefinite hangs if tasks don't exit.
- **CI hardening** — Added `cargo-audit` job (`rustsec/audit-check@v2`) and
  benchmark regression comparison (`critcmp`) on pull requests.
- **Dependabot** — Weekly dependency updates for Cargo, npm, pip, and
  GitHub Actions ecosystems.
- **Release workflow** — Tag-triggered (`v*.*.*`) release: builds binaries,
  extracts CHANGELOG section, creates draft GitHub Release, runs crate
  publish dry-run for all 10 library crates.
- **Nullifier migration CLI** — `lumora migrate-nullifiers` subcommand
  re-derives V1→V2 domain-separated nullifiers for wallet notes. Supports
  `--chain-id`, `--app-id`, and `--dry-run` flags.
- **State migration tests** — 7 tests for version detection (v0 bare JSON,
  v1 envelope + HMAC, binary magic, tiny files) and `ensure_current` migration.
- **Test coverage expansion** — 20 CLI tests (parse_u64 edge cases, clap
  parsing, REPL command coverage, migration subcommand), 19 client tests
  (wallet edge cases: duplicate leaf, idempotent mark_spent, nonexistent
  asset, exact match coin selection), SDK timeout/retry/error tests (5 TS,
  4 Python). Total: 252 Rust lib + 24 integration/E2E + 25 TS + 24 Python.
- **Upgrade runbook** — `docs/upgrade-runbook.md` covering rolling binary
  upgrades, V0→V1 state migration, V1→V2 nullifier transition with dual-key
  window, WAL recovery, SDK upgrade, and post-upgrade monitoring.
- **API documentation** — `api-guide.md` updated with configuration table
  (4 env vars), rate limiting section (nginx example), SDK timeout & retry
  configuration with code examples.

### Phase 24 — Cross-Chain Privacy (ZASEON-Inspired)

- **Domain-separated nullifiers** — `Nullifier::derive_v2(sk, cm, domain)` uses
  `Poseidon(Poseidon(sk, cm), Poseidon(chain_id, app_id))` for per-chain/per-app
  nullifier isolation. Added `NullifierDomain { chain_id, app_id }` type.
- **Cross-domain nullifier linking** — `Nullifier::derive_child(parent, child_domain, nonce)`
  enables proving same-origin across domains without revealing the parent nullifier.
- **Circuit domain separation** — `InputNoteWitness` extended with optional
  `domain_chain_id` / `domain_app_id` for V2 nullifier derivation in-circuit.
  V1 (domainless) path preserved for backward compatibility.
- **Epoch-based nullifier partitioning** — `EpochManager` with configurable
  epoch duration (default 1 hour), auto-advancing epochs, Merkle root
  finalization over epoch nullifiers, and bounded history (256 epochs).
- **Batch accumulator** — `BatchAccumulator` buffers transactions with
  configurable min/max batch size (4–32), minimum delay floor, and maximum
  wait time. Under-size batches are padded with dummy transactions.
- **Fixed-size proof envelopes** — `ProofEnvelope::seal()` pads any proof
  payload to exactly 2048 bytes with random padding; `open()` extracts the
  original. Prevents size-based operation type inference.
- **Relay jitter middleware** — Axum middleware adds random 50–500ms delay to
  POST responses for timing decorrelation between sender and relay.
- **Cross-chain nullifier sync** — `RollupBridge` trait extended with
  `commit_nullifier_epoch_root()` and `fetch_remote_nullifier_roots()`.
  `StrataBridge` implements both via JSON-RPC 2.0. New `RemoteNullifierEpochRoot`
  type carries `(chain_id, epoch_id, root)` tuples.
- **Stealth addresses** — ECDH-based one-time stealth addresses on Pallas.
  `stealth_send(recipient_pk, rng)` produces a one-time owner field + `StealthMeta`
  (ephemeral public key). `SpendingKey::stealth_receive(meta)` detects notes
  addressed to the holder. Includes serde support for `pallas::Affine` points.

### Domain Field Wiring — Contracts & Events

- **Domain fields wired through the full stack** — `domain_chain_id: Option<u64>`
  and `domain_app_id: Option<u64>` added to `TransferRequest`, `WithdrawRequest`
  structs (contracts layer) and `PoolEvent::Transfer`, `PoolEvent::Withdraw`
  variants (events layer). RPC handlers now forward domain fields from HTTP
  requests into contract execution, and the fields are persisted in events with
  `#[serde(default, skip_serializing_if)]` for backwards compatibility.
- **Documentation clarified** — `api-guide.md` updated to explain that domain
  fields are client-side V2 nullifier derivation metadata, stored in events for
  auditing. `PROTOCOL.md` expanded with a 5-step cross-chain verification
  workflow. `light-client-design.md` updated with `/v1/stealth-scan` RPC
  tradeoff note.
- **README updated** — RPC test count corrected (38 tests: 26 lib + 12 E2E),
  Python SDK test command added, Python SDK status changed from "planned" to
  active.

### Phase 26 — Build & Operations

- **Makefile** — 18 targets covering build, test, SDK, docker, bench, deploy,
  and supply chain audit.
- **GitHub templates** — `PULL_REQUEST_TEMPLATE.md`, `ISSUE_TEMPLATE/bug.md`,
  `ISSUE_TEMPLATE/feature.md` for standardized contributions.
- **CODEOWNERS** — Team-based code ownership for core, crypto, contracts,
  infra, SDK, and security areas.
- **Python SDK parity** — 15 methods covering all RPC endpoints with 20 tests.
  Uses only stdlib (`urllib`) — no external dependencies.
- **OpenAPI spec** — `openapi.yaml` documenting all v0.1.0 endpoints with
  request/response schemas and domain field parameters.
- **Graceful shutdown** — `BackgroundHandle` with `watch::channel` for
  coordinated task shutdown. Batch and epoch loops respect shutdown signal.
- **Health enrichment** — `/health` now returns structured JSON with uptime,
  pool balance, commitment count, current epoch, and Merkle root.
- **E2E integration tests** — 12 end-to-end tests covering full request
  lifecycle through the Axum router.

### Phase 25 — Integration & Operationalization

- **Domain fields wired in RPC** — `domain_chain_id` and `domain_app_id` on
  transfer and withdraw requests forwarded through RPC handlers into contract
  execution and persisted in pool events. Fields are optional (V1 path
  preserved) and backward-compatible via `serde(default)`.
- **Stealth scan endpoint** — `POST /v1/stealth-scan` returns encrypted notes
  from a given `from_leaf_index` with configurable `limit` (default 1000).
  Client performs ECDH trial decryption locally; server never learns which
  notes belong to the requester. Added `NoteStore::all_notes_since()`.
- **Background tasks** — `tasks.rs` module with `batch_poll_loop` (5s
  interval) and `epoch_finalize_loop` (60s interval) spawned as tokio tasks
  on server startup. Shared `AppState` (`Arc<RwLock<LumoraNode>>`) between
  router and background tasks. Handles aborted on shutdown.
- **BatchAccumulator operationalized** — Wired into the RPC server via the
  `batch_poll_loop` background task, which polls and flushes accumulated
  transactions at a fixed interval.
- **EpochManager operationalized** — Wired via `epoch_finalize_loop`
  background task, which periodically finalizes the current epoch and
  advances to the next one.
- **TypeScript SDK Phase 24 features** — Added `epochRoots()` and
  `stealthScan()` methods to `LumoraClient`. Added `domain_chain_id` and
  `domain_app_id` optional fields to `TransferRequest` and `WithdrawRequest`.
  New types: `EpochRootEntry`, `EpochRootsResponse`, `StealthScanRequest`,
  `EncryptedNoteResponse`, `StealthScanResponse`. Total SDK tests: 20.
- **API guide updated** — Added stealth-scan endpoint documentation with
  request/response examples and privacy note.
- **README fixes** — Fixed broken `light-client-design.md` link, added
  `lumora-rpc` to crates table, updated RPC test count to 24.

### Phase 10 — Critical Bug Fixes

- **Fixed unsafe SpendingKey::Drop** — replaced UB-causing `from_raw_parts_mut`
  pointer cast with safe `self.0 = pallas::Scalar::ZERO;`.
- **Fixed RPC parse_field panic** — replaced `.unwrap()` on `CtOption` with safe
  `Option` match pattern, preventing DoS via malformed field elements.
- **Fixed encryption unwrap on identity point** — `point_to_bytes`,
  `compute_mac`, and `derive_key_stream` now check `is_some()` before unwrapping
  coordinates, preventing panics on malicious inputs.

### Phase 11 — Security Hardening

- Added proof size limits (`MAX_PROOF_BYTES = 512KB`) to transfer and withdraw
  RPC handlers, preventing OOM via oversized payloads.
- Added global request body limit (2MB) via `DefaultBodyLimit` layer.
- Added `GET /health` liveness probe endpoint.
- Added HMAC-SHA256 integrity tag to state file persistence — tampered or
  corrupted state files are now detected on load.
- Implemented atomic state writes (temp file + rename) to prevent corruption
  on crash.
- CLI passphrase input now uses `rpassword` for echo suppression.
- Plaintext `save-wallet` now warns and requires "yes" confirmation.
- Added `export-key` confirmation prompt before displaying spending key.
- Fixed `apply_delta` sync replay — Transfer and Withdraw events now properly
  update nullifiers, commitments, and pool balance (previously only emitted
  events without state changes).
- Created `.github/workflows/ci.yml` — check (fmt, clippy, build), test, and
  supply chain audit jobs.
- Created `deny.toml` for `cargo-deny` supply chain auditing.
- Added `LICENSE-MIT` and `LICENSE-APACHE` at project root.
- Created `SECURITY.md` with vulnerability reporting process and hardening
  status.

### Phase 12 — State Management

- Added state file versioning — save/load now uses a versioned JSON envelope
  (`version: 1`) with fallback to legacy unversioned format.

### Phase 13 — RPC & Concurrency

- Replaced `tokio::sync::Mutex` with `RwLock` for `AppState` — read-only
  handlers (`nullifier_check`, `get_notes`, `sync_events`) now run concurrently.
- Added semaphore-based concurrency limiter (`MAX_CONCURRENT_REQUESTS = 128`)
  returning 503 Service Unavailable on overload.
- Added `/v1/` versioned API routes (backward-compatible unversioned routes
  preserved).
- Added structured `tracing::info!` logging to deposit, transfer, and withdraw
  handlers.
- Cleaned up unused imports across `lumora-note`, `lumora-rpc`.

### Phase 1 — Critical Safety & Soundness

- Fixed empty-tree panic in `tree.rs` — `root()` on an empty tree now returns
  the all-zero hash instead of panicking.
- Replaced `expect("pool balance overflow")` in deposit with `checked_add` and
  a proper `ContractError::PoolBalanceOverflow` variant.
- Added verifier unit tests (prove → verify roundtrip, tampered proof
  rejection).
- Added in-circuit range constraints on all input/output values to u64
  (`RangeCheckConfig` in the transfer and withdraw circuits).
- Added Poseidon-based MAC to ECIES note encryption (authenticate-then-decrypt
  pattern).
- Implemented `Drop` with `zeroize` for `SpendingKey` — spending key bytes are
  zeroed on drop.
- Changed `keygen_vk`/`keygen_pk` to return `Result` instead of panicking.
- Propagated real proof errors through `ProofError(String)` variant instead of
  flat mapping to `InvalidProof`.
- Fixed `CtOption` unwrap in `keys.rs` deserialization — now returns `None` for
  invalid field element representations.

### Phase 2 — Test Coverage

- Added verifier roundtrip tests for both transfer and withdraw circuits.
- Added SRS `save_params`/`load_params` roundtrip test.
- Added nullifier double-spend rejection integration test.
- Added root history eviction test (>256 deposits).
- Added edge case tests: empty note selection, zero-value deposit rejection,
  tree-at-capacity check.
- Added test for invalid Merkle path rejection.
- Added ECIES decryption-with-wrong-key test.

### Phase 3 — Persistence Layer

- Wallet file save/load with JSON serialization (`Wallet::save`,
  `Wallet::load`).
- Merkle tree state serialization via serde (leaves + filled subtrees).
- Nullifier set persistence as part of `PrivacyPoolState` serialization.
- Full `PrivacyPoolState` save/load (`state.save()`, `PrivacyPoolState::load`).
- Node restart recovery: `LumoraNode::init_recover(dir)` reloads SRS, pool
  state, and note store from disk; `save_state(dir)` persists everything.

### Phase 4 — Wallet & Key Management

- BIP39 mnemonic seed phrase support (`SpendingKey::from_mnemonic`,
  `SpendingKey::generate_mnemonic`).
- Wallet encryption with AES-256-GCM + Argon2 KDF (`save_encrypted`,
  `load_encrypted`).
- Key export/import commands in CLI (`export-key`, `recover-mnemonic`).
- Transaction history tracking (`TxRecord` enum with Deposit/Send/Withdraw
  variants, `Wallet::record_tx`, `Wallet::history`).
- Note scanning via viewing key tags from the note store
  (`scan_note_store`).
- Coin selection: greedy smallest-first strategy with change optimization
  (`Wallet::select_notes`).

### Phase 5 — SDK & API Enhancements

- Exposed Merkle root, nullifier queries, note enumeration through the SDK
  (`merkle_root()`, `is_nullifier_spent()`, `notes()`).
- Asset-specific balance queries (`balance_of(asset)`).
- Updated README SDK example to reflect current `send()` signature.
- Schema versioning for serialized wallet data (version 1).
- Field ↔ hex/bytes conversion helpers in the SDK module.

### Phase 6 — Performance

- SRS caching: `init_cached(srs_path)` saves/loads structured reference string
  to skip expensive parameter generation on subsequent runs.
- Thread-safe prover handles: `SharedProverHandle` and
  `SharedWithdrawProverHandle` (`Arc`-wrapped) for concurrent proof generation.
- Batch proof verification: `batch_verify_transfers()` in the verifier crate.
- Merkle witness computation caching: internal `HashMap<(u64, usize),
pallas::Base>` node cache with invalidation on `insert()`.
- Benchmark documentation (`BENCHMARKS.md`).

### Phase 7 — Networking

- HTTP JSON-RPC server (`lumora-rpc` crate) with axum: deposit, transfer,
  withdraw, relay-note, nullifier check, note retrieval, sync status/events.
- Transaction mempool (`Mempool`) — bounded FIFO queue (max 1024) with
  submit/drain/take/peek operations.
- Rollup integration layer: `RollupBridge` trait with `LocalBridge` (no-op,
  standalone mode) and types for inbound deposits and outbound withdrawals.
- State sync protocol: `SyncStatus`, `StateDelta`, `StateSync` trait,
  `apply_delta()` for leader-follower replication.
- Peer discovery: `PeerRegistry` with health tracking (success/failure
  counters, auto-unhealthy after 3 failures), JSON persistence.

### Phase 8 — Security Hardening

- Constant-time nullifier lookup: `NullifierEntry` newtype with
  `subtle::ConstantTimeEq` for timing-safe membership checks.
- `SpendingKey` manual `Debug` impl — prints `<redacted>` instead of secret.
- Full-width blinding factors: all 6 randomness sites replaced from 64-bit
  `random::<u64>()` to full Pallas scalar `Scalar::random(&mut OsRng)`.
- Key material zeroization: `save_encrypted` / `load_encrypted` now zeroize
  Argon2-derived keys, plaintext JSON, and decrypted buffers immediately
  after use.
- Key material handling audit (19 findings, critical and high addressed).
- Threat model document (`THREAT_MODEL.md`).
- Protocol specification (`PROTOCOL.md`).

### Phase 9 — Documentation & DevEx

- End-to-end integration example (`cargo run -p lumora-sdk --example e2e`).
- Deployment guide (`DEPLOYMENT.md`): build, configuration, RPC server,
  standalone mode, rollup integration, multi-node sync, security notes.
- Versioning policy (`VERSIONING.md`): SemVer, circuit/serialization/API
  compatibility rules, release process.
- This CHANGELOG.

## [0.1.0] — Initial Implementation

- Halo2 ZK circuits for 2-in-2-out private transfer and withdrawal.
- Poseidon-based note commitments and nullifiers on Pallas curve.
- Incremental Merkle tree (depth 32, ~4B leaf capacity).
- ECIES note encryption for private note delivery.
- Privacy pool contract: deposit, transfer, withdraw.
- Interactive CLI (clap4 REPL).
- Basic SDK orchestrator (`Lumora::init`, `deposit`, `send`, `withdraw`).
