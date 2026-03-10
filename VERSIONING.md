# Versioning Policy

Lumora follows [Semantic Versioning 2.0.0](https://semver.org/).

## Version Format

```
MAJOR.MINOR.PATCH
```

| Component | Incremented when                                                           |
| --------- | -------------------------------------------------------------------------- |
| **MAJOR** | Breaking changes to public APIs, circuit layouts, or serialization formats |
| **MINOR** | New features added in a backward-compatible manner                         |
| **PATCH** | Backward-compatible bug fixes and security patches                         |

## Current Status

All crates are at **0.x.y** (pre-1.0). During the 0.x series:

- MINOR bumps may include breaking changes.
- PATCH bumps are always backward-compatible.
- No stability guarantees are provided for internal or unstable APIs.

## Workspace Versioning

All crates in the workspace share a single version number defined in
`Cargo.toml` under `[workspace.package]`. When a release is made, every crate
is published at the same version.

The TypeScript SDK (`@lumora/sdk`) follows the same version number and is
published to npm alongside Rust crate releases.

## What Constitutes a Breaking Change

### Circuit / Proof (always MAJOR)

- Changes to the Halo2 circuit layout (column count, gate definitions, row
  assignments).
- Changes to the structured reference string parameters (k value).
- Changes to the Poseidon configuration (P128Pow5T3 parameters, rate, width).
- Changes to the note commitment or nullifier derivation scheme.
- Changes to domain-separated nullifier format (V2 hash structure).

**Example**: Changing the nullifier derivation from `H(sk, cm)` to
`H(sk, cm, nonce)` invalidates all existing proofs and nullifiers.

These changes invalidate existing proofs and Merkle tree state.

### Serialization (always MAJOR)

- Changes to the wire format of encrypted notes.
- Changes to the wallet save/load format (plaintext or encrypted).
- Changes to the `PrivacyPoolState` persistence format.
- Changes to the WAL or snapshot binary format.
- Changes to the peer registry JSON schema.

**Example**: Adding a new field to the binary snapshot header that old
versions cannot parse.

### Public API (MAJOR if 1.0+, MINOR if 0.x)

- Removing or renaming public types, functions, or methods.
- Changing method signatures (parameters, return types).
- Changing the semantics of existing API calls.

**Example**: Renaming `Lumora::send()` to `Lumora::transfer()`.

### RPC API (MAJOR if 1.0+, MINOR if 0.x)

- Removing or renaming RPC endpoints.
- Changing request/response JSON schemas for existing endpoints.
- Changing HTTP status codes for existing error cases.

**Example**: Changing the `/v1/transfer` response from `{ leaf_indices }`
to `{ indices }`.

### Non-Breaking (MINOR or PATCH)

- Adding new public types or methods.
- Adding new RPC endpoints.
- Adding optional fields to existing RPC requests.
- Performance improvements that don't change outputs.
- Internal refactoring with no public API change.

## RPC API Versioning

All HTTP endpoints are available under the `/v1/` version prefix:

```
/v1/deposit
/v1/transfer
/v1/stealth-scan
```

Unversioned routes (e.g., `/deposit`) are preserved for backward compatibility.
When a breaking change to request/response schemas is necessary, a new version
prefix (`/v2/`) will be introduced while preserving the previous version for at
least one MAJOR release cycle.

## SDK Versioning

| SDK         | Package                 | Versioning                          |
| ----------- | ----------------------- | ----------------------------------- |
| Rust crates | `lumora-*` on crates.io | Same as workspace version           |
| TypeScript  | `@lumora/sdk` on npm    | Same as workspace version           |
| Python      | `lumora-sdk` on PyPI    | Same as workspace version (planned) |

SDK releases are made simultaneously with Rust crate releases.

## Release Process

1. Update `version` in `[workspace.package]` in the root `Cargo.toml`.
2. Update `version` in `sdks/typescript/package.json`.
3. Update `CHANGELOG.md` with the new version, date, and changes.
4. Run full test suite: `cargo test --workspace --lib && cd sdks/typescript && npm test`.
5. Commit and tag: `git tag v0.x.y`.
6. Publish crates to crates.io: `cargo publish -p lumora-primitives` (in dependency order).
7. Publish TypeScript SDK: `cd sdks/typescript && npm publish`.
8. Create GitHub release with changelog excerpt.

## Deprecation

Deprecated APIs are marked with `#[deprecated]` and documented in the
CHANGELOG. Deprecated items are removed no sooner than the next MAJOR version
(or next MINOR during 0.x).
