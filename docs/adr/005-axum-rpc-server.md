# ADR-005: Axum RPC Server

## Status

Accepted

## Context

Lumora needs an HTTP/JSON API for clients to submit transactions (deposit, transfer, withdraw) and query state (nullifier checks, sync events, status). The server must support:

- Request size limits
- Concurrency control
- Authentication
- Metrics/observability
- Versioned routing

## Decision

Use **Axum 0.8** with Tokio as the async runtime.

## Rationale

- **Async-native, tower-based**: Built on tower middleware and tokio, enabling composable middleware (auth, rate limiting, concurrency) without framework lock-in.
- **Production features**: DefaultBodyLimit (2 MB), semaphore-based concurrency control (128 max), API key auth via `X-API-Key`, Prometheus metrics at `/metrics`, versioned routes under `/v1/`.
- **Shared state**: `Arc<RwLock<LumoraNode>>` allows read-heavy endpoints to run concurrently while write operations acquire exclusive locks.
- **Lightweight**: Minimal overhead compared to heavier frameworks (actix-web, warp).
- **Ecosystem alignment**: Axum is the most actively maintained Rust web framework, well-integrated with the tokio/tower ecosystem.

## Consequences

- JSON-RPC over HTTP: POST for writes (`/deposit`, `/transfer`, `/withdraw`), GET for reads (`/status`, `/fees`, `/health`).
- Load shedding returns HTTP 503 when concurrent requests exceed the semaphore limit.
- The server is single-process; horizontal scaling requires an external load balancer.
