# Lumora TypeScript SDK

TypeScript/JavaScript client for the Lumora privacy coprocessor RPC API.

## Installation

```bash
npm install @lumora/sdk
```

## Usage

```typescript
import { LumoraClient } from "@lumora/sdk";

const client = new LumoraClient("http://127.0.0.1:3030", "my-api-key");

// Check pool status
const status = await client.status();
console.log(`Pool balance: ${status.pool_balance}`);

// Get fee estimates
const fees = await client.fees();
console.log(`Transfer fee: ${fees.transfer_fee}`);

// Deposit
const receipt = await client.deposit({
  commitment: "0x...",
  amount: 1000,
});
console.log(`Leaf index: ${receipt.leaf_index}`);

// Check nullifier
const result = await client.checkNullifier("0x...");
console.log(`Spent: ${result.spent}`);

// Query history
const history = await client.history({ offset: 0, limit: 10 });
for (const event of history.events) {
  console.log(event);
}

// Batch verify
const batch = await client.batchVerify([proof1, proof2]);
console.log(`All valid: ${batch.all_valid}`);
```

## Requirements

- Node.js 18+ (uses native `fetch`)
- TypeScript 5+ (for type definitions)

## Building

```bash
npm install
npm run build
```

## License

MIT OR Apache-2.0
