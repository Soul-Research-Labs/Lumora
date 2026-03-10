# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Lumora, **do not** open a public
GitHub issue. Instead, please report it responsibly:

1. **Email**: Send a detailed report to **security@lumora.dev** (or the
   maintainer email listed in the repository).
2. **Include**:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment (severity: critical / high / medium / low)
   - Suggested fix (if any)
   - Affected version(s) and component(s)

We aim to acknowledge reports within **48 hours** and provide an initial
assessment within **5 business days**.

### Disclosure Timeline

| Step               | Target                                          |
| ------------------ | ----------------------------------------------- |
| Acknowledgement    | 48 hours                                        |
| Initial assessment | 5 business days                                 |
| Patch development  | 30 days (critical: 7 days)                      |
| Public disclosure  | After patch is released, or 90 days from report |

We follow coordinated disclosure. If you need a CVE identifier, we will
coordinate with MITRE once the issue is confirmed.

## Scope

The following are in scope for security reports:

- **ZK circuit soundness** — under-constrained values, missing range checks,
  public input binding issues
- **Cryptographic weaknesses** — key leakage, weak randomness, broken
  encryption, ECDH/ECIES issues
- **Double-spend vulnerabilities** — nullifier bypass, Merkle root manipulation,
  cross-chain replay
- **Memory safety** — use-after-free, buffer overflows, unsafe code issues
- **RPC attack surface** — injection, DoS vectors, information disclosure,
  authentication bypass
- **State integrity** — corruption vectors, deserialization attacks, WAL/snapshot
  tampering
- **Cross-chain security** — domain separation bypass, epoch root forgery,
  nullifier sync manipulation
- **Stealth address privacy** — ephemeral key reuse, scanning pattern leakage,
  linkability attacks

## Out of Scope

- Denial of service via resource exhaustion on unprotected endpoints (we
  recommend deploying behind a reverse proxy with rate limiting)
- Social engineering
- Issues in dependencies (report upstream; we track via `cargo-deny`)
- Theoretical attacks requiring quantum computers

## Security Hardening Status

| Area                                                  | Status                | Phase |
| ----------------------------------------------------- | --------------------- | ----- |
| Spending key zeroization (`Drop` + `zeroize`)         | Implemented           | 1     |
| Wallet encryption (AES-256-GCM + Argon2id)            | Implemented           | 4     |
| Full-width blinding factors (Pallas `Scalar::random`) | Implemented           | 8     |
| Constant-time nullifier comparison (`subtle`)         | Implemented           | 8     |
| State file HMAC-SHA256 integrity                      | Implemented           | 11    |
| RPC body size limits (2 MB global, 512 KB proof)      | Implemented           | 11    |
| CLI passphrase echo suppression (`rpassword`)         | Implemented           | 11    |
| Atomic state writes (temp + rename)                   | Implemented           | 11    |
| Note encryption (ChaCha20-Poly1305 AEAD)              | Implemented           | 8     |
| Fixed-size proof envelopes (2048 bytes)               | Implemented           | 24    |
| Relay jitter middleware (timing decorrelation)        | Implemented           | 24    |
| Transaction batch padding (dummy txs)                 | Implemented           | 24    |
| Domain-separated nullifiers (V2)                      | Implemented           | 24    |
| Epoch nullifier partitioning                          | Implemented           | 24    |
| RPC concurrency limiter (semaphore)                   | Implemented           | 13    |
| API key authentication middleware                     | Implemented           | 13    |
| WAL + snapshot crash recovery                         | Implemented           | 20    |
| Supply chain audit (`cargo-deny`)                     | Configured            | 11    |
| Formal circuit audit                                  | **Not yet completed** | —     |

## Dependency Security

Dependencies are monitored via:

- **`cargo-deny`** — configured in `deny.toml` for license compliance, advisory
  database checks, and duplicate detection. Run via `cargo deny check`.
- **GitHub Dependabot** — automated alerts for known CVEs in dependencies.
- **CI pipeline** — `cargo deny` runs on every pull request.

## Known Limitations

1. **No formal circuit audit.** The Halo2 transfer and withdraw circuits have
   **not undergone a formal third-party audit**. Do not deploy to mainnet
   until an audit is complete.

2. **No built-in TLS.** The RPC server communicates over plaintext HTTP.
   Deploy behind a reverse proxy (nginx, Caddy) with TLS termination for
   production use.

3. **API key is bearer-token only.** The `X-API-Key` header provides basic
   access control but is not a substitute for mutual TLS or OAuth2 in
   production environments.

4. **Single-process architecture.** The prover holds spending keys in memory
   during proof generation. A compromised node process can exfiltrate keys.
   Future: client-side proving.

5. **Variable-time DH on non-standard targets.** Pallas scalar multiplication
   is constant-time on standard platforms but may leak timing on non-standard
   targets. See `THREAT_MODEL.md` §4.10.

## Related Documents

- [THREAT_MODEL.md](THREAT_MODEL.md) — Detailed threat model and attack surface
- [PROTOCOL.md](PROTOCOL.md) — Protocol specification
- [docs/cryptography.md](docs/cryptography.md) — Cryptographic primitives reference
