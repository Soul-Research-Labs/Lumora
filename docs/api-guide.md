# Lumora API Guide

The Lumora RPC server exposes a set of HTTP/JSON endpoints for interacting with
the Lumora privacy pool. By default the server listens on **127.0.0.1:3030**.
Override with the `LUMORA_RPC_ADDR` environment variable.

All endpoints are available at the root (`/deposit`) and under the versioned
prefix (`/v1/deposit`). Prefer the `/v1/` prefix for forward-compatibility.

---

## Configuration

| Variable               | Default          | Description                                                                       |
| ---------------------- | ---------------- | --------------------------------------------------------------------------------- |
| `LUMORA_RPC_ADDR`      | `127.0.0.1:3030` | Listen address                                                                    |
| `LUMORA_API_KEY`       | _(unset)_        | API key for request authentication                                                |
| `LUMORA_CORS_ORIGINS`  | _(unset)_        | Comma-separated CORS origins (e.g. `https://app.lumora.io,http://localhost:5173`) |
| `LUMORA_JITTER_MIN_MS` | `50`             | Relay jitter minimum delay in milliseconds                                        |
| `LUMORA_JITTER_MAX_MS` | `500`            | Relay jitter maximum delay in milliseconds                                        |
| `RUST_LOG`             | `info`           | Log level filter                                                                  |

---

## Rate Limiting

The server uses a concurrency semaphore (128 max concurrent requests). When
the limit is reached, new requests receive **503 Service Unavailable**.

For IP-based rate limiting, deploy behind a reverse proxy:

**nginx** example:

```nginx
limit_req_zone $binary_remote_addr zone=lumora:10m rate=100r/s;

server {
    location / {
        limit_req zone=lumora burst=50 nodelay;
        proxy_pass http://127.0.0.1:3030;
    }
}
```

The `http_requests_rejected_total{reason="overload"}` Prometheus counter
tracks shed requests.

---

## Authentication

If the `LUMORA_API_KEY` environment variable is set, every request (except
`/health` and `/metrics`) must include:

```
X-API-Key: <your-key>
```

Requests without a valid key receive **401 Unauthorized**.

---

## Common conventions

| Item           | Format                                                     |
| -------------- | ---------------------------------------------------------- |
| Field elements | 64-char lowercase hex (32 bytes, Pallas base field)        |
| Proofs         | Hex-encoded byte string (max 512 KB), raw or enveloped     |
| Amounts        | `u64` (minimum deposit: 100, minimum withdraw: 100)        |
| Errors         | `{ "error": "<message>" }` with an appropriate HTTP status |

### Proof Envelope Format

Proofs may be submitted either as raw hex bytes or wrapped in a fixed-size
**2048-byte envelope** for traffic-analysis resistance. The server automatically
detects enveloped proofs and unwraps them.

Envelope structure: `[4 bytes: payload_len LE][payload][random padding]` →
always 2048 bytes. Create with `lumora_primitives::envelope::seal()`.
Raw proofs (non-envelope) are accepted for backward compatibility.

---

## Endpoints

## Bridge Adapter Contract (Internal)

The BitVM bridge layer includes an EMVCo QR adapter (`EmvBridge`) for payment
rail interoperability. This is an internal bridge interface (not an HTTP route
on `lumora-rpc`) and communicates via adapter JSON-RPC methods.

For full request/response examples and mapping details, see
`docs/emv-bridge.md`.

Expected EMV gateway methods:

- `emv_getSettledQrPayments`
- `emv_getPaymentStatus`
- `emv_submitPayout`
- `emv_commitStateRoot`
- `emv_commitNullifierEpochRoot`
- `emv_getRemoteNullifierRoots`
- `emv_verifyProof`

Common required request fields:

- `network_id` (string, non-empty)
- `merchant_id` (string, non-empty)
- `currency` (string, non-empty)

Adapter behavior guarantees:

- Local config validation rejects empty `network_id`, `merchant_id`, or
  `currency`.
- Deposit polling applies a local `min_finality` filter even if the remote
  endpoint returns low-finality records.
- Withdrawal accepts payout status values `accepted` and `settled`
  case-insensitively; all other statuses are rejected.
- Nullifier root parsing uses strict validation and returns
  `BridgeError::NullifierSyncFailed` on malformed records.

---

### Health

```
GET /health
```

Returns `200 OK` with body `ok`. No authentication required.

---

### Pool status

```
GET /v1/status
```

**Response**

```json
{
  "pool_balance": 5000,
  "commitment_count": 12,
  "merkle_root": "0a1b2c..."
}
```

---

### Fee estimate

```
GET /v1/fees
```

**Response**

```json
{
  "transfer_fee": 10,
  "withdraw_fee": 20,
  "min_deposit": 100,
  "min_withdraw": 100
}
```

---

### Deposit (shield)

Convert public funds into a private note commitment.

```
POST /v1/deposit
Content-Type: application/json
```

**Request**

```json
{
  "commitment": "aabb...",
  "amount": 500
}
```

**Response**

```json
{
  "leaf_index": 0,
  "new_root": "1234..."
}
```

| Status | Meaning                         |
| ------ | ------------------------------- |
| 200    | Success                         |
| 400    | Invalid hex / bad commitment    |
| 422    | Amount is zero or below minimum |

---

### Transfer (private → private)

Spend two input notes and produce two new output notes, proven with a ZK proof.

```
POST /v1/transfer
Content-Type: application/json
```

**Request**

```json
{
  "proof": "deadbeef...",
  "merkle_root": "1234...",
  "nullifiers": ["aaa...", "bbb..."],
  "output_commitments": ["ccc...", "ddd..."],
  "domain_chain_id": 1,
  "domain_app_id": 42
}
```

`domain_chain_id` and `domain_app_id` are optional. When provided, the server
stores them in the pool event for auditing. Clients use these fields for V2
domain-separated nullifier derivation (cross-chain replay protection); the server
verifies the ZK proof that covers the derived nullifiers. Omit both fields (or
set to `null`) for default (V1) nullifiers.

**Response**

```json
{
  "leaf_indices": [2, 3],
  "new_root": "5678..."
}
```

| Status | Meaning                                                |
| ------ | ------------------------------------------------------ |
| 200    | Success                                                |
| 400    | Invalid hex                                            |
| 413    | Proof exceeds 512 KB                                   |
| 422    | Nullifier already spent / invalid proof / unknown root |

---

### Withdraw (unshield)

Convert a private note back to public funds, proven with a ZK proof.

```
POST /v1/withdraw
Content-Type: application/json
```

**Request**

```json
{
  "proof": "deadbeef...",
  "merkle_root": "1234...",
  "nullifiers": ["aaa...", "bbb..."],
  "output_commitments": ["ccc...", "ddd..."],
  "amount": 250,
  "recipient": "ee00...",
  "domain_chain_id": 1,
  "domain_app_id": 42
}
```

`recipient` is a 32-byte hex-encoded address. Domain fields are optional and
stored in the event for auditing (same client-side V2 derivation semantics as
Transfer above).

**Response**

```json
{
  "change_leaf_indices": [4, 5],
  "new_root": "9abc...",
  "amount": 250
}
```

| Status | Meaning                                                       |
| ------ | ------------------------------------------------------------- |
| 200    | Success                                                       |
| 400    | Invalid hex                                                   |
| 413    | Proof exceeds 512 KB                                          |
| 422    | Nullifier spent / invalid proof / below minimum / zero amount |

---

### Nullifier check

Check whether a nullifier has already been spent.

```
POST /v1/nullifier
Content-Type: application/json
```

**Request**

```json
{ "nullifier": "ff00..." }
```

**Response**

```json
{ "spent": false }
```

---

### Relay encrypted note

Store an encrypted note for a recipient so they can discover it later.

```
POST /v1/relay-note
Content-Type: application/json
```

**Request**

```json
{
  "recipient_tag": "abcd...",
  "leaf_index": 0,
  "commitment": "1111...",
  "ciphertext": "2222...",
  "ephemeral_pubkey": "3333..."
}
```

Returns **201 Created** on success.

---

### Get notes

Retrieve encrypted notes addressed to a recipient tag.

```
POST /v1/notes
Content-Type: application/json
```

**Request**

```json
{ "recipient_tag": "abcd..." }
```

**Response**

```json
[
  {
    "leaf_index": 0,
    "commitment": "1111...",
    "ciphertext": "2222...",
    "ephemeral_pubkey": "3333..."
  }
]
```

---

### Sync status

```
GET /v1/sync/status
```

**Response**

```json
{
  "height": 12,
  "root": "aabb...",
  "nullifier_count": 4,
  "pool_balance": 5000
}
```

---

### Sync events

Fetch state-change events starting from a given height.

```
POST /v1/sync/events
Content-Type: application/json
```

**Request**

```json
{ "from_height": 5 }
```

**Response**

```json
{
  "from_height": 5,
  "events": [ ... ]
}
```

---

### Epoch Roots

Return all finalized nullifier-epoch Merkle roots. These roots represent
epoch-partitioned nullifier sets used for efficient cross-chain synchronization.

```
GET /v1/epoch-roots
```

**Response**

```json
{
  "current_epoch": 28613,
  "roots": [
    { "epoch_id": 28610, "root": "aabb..." },
    { "epoch_id": 28611, "root": "ccdd..." },
    { "epoch_id": 28612, "root": "eeff..." }
  ]
}
```

The `roots` array contains only finalized epochs (at most 256). The
`current_epoch` is the currently-active epoch that has not yet been finalized.

---

### Stealth Scan

Download encrypted notes for local trial decryption (stealth address scanning).
The server returns all notes from a given leaf index onward — the client
performs ECDH trial decryption locally to discover notes addressed to it.

```
POST /v1/stealth-scan
Content-Type: application/json
```

**Request**

```json
{
  "from_leaf_index": 100,
  "limit": 500
}
```

Both fields are optional. `from_leaf_index` defaults to `0` and `limit`
defaults to `1000`.

**Response**

```json
{
  "notes": [
    {
      "leaf_index": 100,
      "commitment": "aabb...",
      "ciphertext": "ccdd...",
      "ephemeral_pubkey": "eeff..."
    }
  ]
}
```

> **Privacy note**: The server does not learn which notes belong to the
> requester. All notes are returned in bulk; the client tries each one
> against its spending key locally.

---

## Prometheus metrics

```
GET /metrics
```

Returns Prometheus-format metrics including:

- `http_requests_total` — counter by method, path, status
- `http_request_duration_seconds` — histogram of request latency
- `http_requests_rejected_total` — counter by rejection reason (overload / auth)

---

## Error responses

All error responses use the shape:

```json
{ "error": "description of the problem" }
```

Common HTTP status codes:

| Code | Meaning                                                         |
| ---- | --------------------------------------------------------------- |
| 400  | Malformed request (bad hex, missing fields)                     |
| 401  | Missing or invalid API key                                      |
| 413  | Proof too large (>512 KB)                                       |
| 422  | Contract-level rejection (nullifier spent, invalid proof, etc.) |
| 503  | Server overloaded (concurrency limit reached)                   |

---

## SDK Timeout & Retry Configuration

Both the TypeScript and Python SDKs support configurable timeouts and
automatic retry with exponential backoff.

### TypeScript

```typescript
import { LumoraClient } from "@lumora/sdk";

const client = new LumoraClient("http://127.0.0.1:3030", "my-api-key", {
  timeoutMs: 15_000, // 15 second timeout (default: 30s)
  maxRetries: 3, // retry up to 3 times on transient errors
  retryBaseMs: 500, // base delay 500ms (exponential backoff with jitter)
});
```

### Python

```python
from lumora import LumoraClient

client = LumoraClient(
    "http://127.0.0.1:3030",
    api_key="my-api-key",
    timeout=15.0,     # 15 second timeout (default: 30s)
    max_retries=3,    # retry up to 3 times on transient errors
    retry_base=0.5,   # base delay 0.5s (exponential backoff with jitter)
)
```

### Retry behavior

- **Retryable status codes**: 429 (rate limited), 502, 503, 504 (server errors)
- **Backoff formula**: `base * 2^(attempt-1) * jitter` where jitter ∈ [0.5, 1.5)
- **Non-retryable errors**: 400, 401, 413, 422 are never retried
- **Connection errors**: Timeouts and network failures are retried if retries are configured
- **Default**: No retries (maxRetries=0) — opt-in only
