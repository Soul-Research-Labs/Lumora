# Lumora Python SDK

Python client for the Lumora privacy coprocessor RPC API.

## Installation

```bash
pip install lumora-sdk
```

Or from source:

```bash
cd sdks/python
pip install -e .
```

## Usage

```python
from lumora import LumoraClient

client = LumoraClient("http://127.0.0.1:3030", api_key="my-secret-key")

# Check pool status
status = client.status()
print(f"Pool balance: {status['pool_balance']}")
print(f"Commitments:  {status['commitment_count']}")

# Get fee estimates
fees = client.fees()
print(f"Transfer fee: {fees['transfer_fee']}")

# Deposit
receipt = client.deposit(commitment="0x...", amount=1000)
print(f"Leaf index: {receipt['leaf_index']}")

# Check nullifier
result = client.check_nullifier("0x...")
print(f"Spent: {result['spent']}")

# Query history
history = client.history(offset=0, limit=10)
for event in history["events"]:
    print(event)
```

## Requirements

- Python 3.10+
- No external dependencies (uses `urllib` from the standard library)

## License

MIT OR Apache-2.0
