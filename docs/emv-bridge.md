# EMVCo QR Bridge Integration

This document describes the internal EMVCo QR bridge adapter used by Lumora's
BitVM integration layer. The adapter is implemented in
`crates/lumora-bitvm/src/adapters/emv.rs` as `EmvBridge`.

The EMV adapter is not exposed through `lumora-rpc` HTTP endpoints. Instead,
it communicates with an upstream EMV gateway using JSON-RPC and maps gateway
objects into Lumora's `RollupBridge` interface.

## Scope

Included in the current integration:

- Polling settled EMV QR payment events as `InboundDeposit`
- Submitting payouts for verified Lumora withdrawals
- Committing Lumora state roots to the EMV-integrated environment
- Committing nullifier epoch roots for cross-domain sync
- Fetching remote nullifier epoch roots
- Optional proof verification via gateway boolean response

Excluded from the current integration:

- EMV certification/conformance artifacts
- Terminal-side QR generation UX
- ISO 8583 message translation
- Card-present APDU flows

## Configuration

`EmvConfig` fields:

```rust
pub struct EmvConfig {
    pub rpc_url: String,
    pub network_id: String,
    pub merchant_id: String,
    pub min_finality: u64,
    pub currency: String,
}
```

Default values:

- `rpc_url`: `http://127.0.0.1:9400`
- `network_id`: `sandbox`
- `merchant_id`: `sandbox-merchant`
- `min_finality`: `1`
- `currency`: `BTC`

The adapter rejects empty `network_id`, `merchant_id`, and `currency` values
before attempting any RPC call.

## JSON-RPC Methods

The gateway is expected to support the following methods:

### `emv_getSettledQrPayments`

Returns a list of settled QR payment records.

Example result:

```json
[
  {
    "commitment": "2a00000000000000000000000000000000000000000000000000000000000000",
    "amount": 25000,
    "payment_id": "abababababababababababababababababababababababababababababababab",
    "finality": 3
  }
]
```

Adapter rules:

- `amount` must be greater than zero
- `payment_id` must be non-empty hex
- `finality` must be greater than or equal to configured `min_finality`

### `emv_getPaymentStatus`

Checks the status of a payment previously observed or referenced.

Example result:

```json
{
  "payment_id": "abababababababababababababababababababababababababababababababab",
  "status": "settled",
  "finality": 4
}
```

### `emv_submitPayout`

Submits an outbound payout corresponding to a verified Lumora withdrawal.

Example request payload:

```json
{
  "network_id": "sandbox",
  "merchant_id": "sandbox-merchant",
  "currency": "BTC",
  "amount": 100000,
  "recipient": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "proof_bytes": "01020304",
  "nullifiers": [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0200000000000000000000000000000000000000000000000000000000000000"
  ]
}
```

Example result:

```json
{
  "payout_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "status": "accepted"
}
```

Adapter rules:

- withdrawal `amount` must be greater than zero
- `proof_bytes` must be non-empty
- payout status must be `accepted` or `settled` (case-insensitive)
- `payout_id` must be non-empty hex

### `emv_commitStateRoot`

Commits the current Lumora Merkle root.

Example request payload:

```json
{
  "network_id": "sandbox",
  "merchant_id": "sandbox-merchant",
  "root": "0900000000000000000000000000000000000000000000000000000000000000"
}
```

### `emv_commitNullifierEpochRoot`

Commits a finalized nullifier epoch root.

Example request payload:

```json
{
  "network_id": "sandbox",
  "merchant_id": "sandbox-merchant",
  "epoch_id": 7,
  "root": "0500000000000000000000000000000000000000000000000000000000000000"
}
```

### `emv_getRemoteNullifierRoots`

Returns remote nullifier roots for cross-domain double-spend prevention.

Example result:

```json
[
  {
    "chain_id": 1,
    "epoch_id": 3,
    "root": "0900000000000000000000000000000000000000000000000000000000000000"
  }
]
```

Malformed entries are rejected; the adapter does not silently coerce invalid
fields.

### `emv_verifyProof`

Returns a boolean indicating whether the gateway accepts a proof hash.

Example result:

```json
true
```

## Mapping to Lumora Types

Gateway payment records map to `InboundDeposit`:

- `commitment` -> `InboundDeposit.commitment`
- `amount` -> `InboundDeposit.amount`
- `payment_id` -> `InboundDeposit.tx_id`

Gateway payout requests map from `OutboundWithdrawal`:

- `amount` -> payout `amount`
- `recipient` -> payout `recipient`
- `proof_bytes` -> payout `proof_bytes`
- `nullifiers` -> payout `nullifiers`

## Validation Summary

The adapter currently applies the following local checks in addition to gateway
responses:

- non-empty config fields
- non-empty hex identifiers
- zero-value deposit rejection
- zero-value withdrawal rejection
- empty proof rejection
- minimum-finality deposit filtering
- strict nullifier root parsing

## Testing

Current test coverage includes:

- default config and accessors
- config rejection paths
- deposit mapping success/failure
- payout success/failure
- proof verification true/false
- payment status lookup
- state-root and nullifier-root commit calls
- remote nullifier root success/error parsing

Run the focused adapter test suite with:

```bash
cargo test -p lumora-bitvm adapters::emv::tests
```