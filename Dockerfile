# ── Stage 1: build ──────────────────────────────────────────────
FROM rust:1.82-bookworm AS builder

WORKDIR /build

# Cache dependency builds by copying manifests first.
COPY Cargo.toml Cargo.lock ./
COPY crates crates

# Build release binaries (lumora CLI + lumora-rpc server).
RUN cargo build --release --workspace \
    && strip target/release/lumora target/release/lumora-rpc

# ── Stage 2: runtime ───────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for the daemon.
RUN groupadd --gid 1000 lumora \
    && useradd --uid 1000 --gid lumora --create-home lumora

COPY --from=builder /build/target/release/lumora     /usr/local/bin/lumora
COPY --from=builder /build/target/release/lumora-rpc /usr/local/bin/lumora-rpc

# Data directory for wallet / state files.
RUN mkdir -p /data && chown lumora:lumora /data
VOLUME ["/data"]

USER lumora
WORKDIR /data

ENV RUST_LOG=info
# Bind 0.0.0.0 inside the container; put a reverse proxy in front.
ENV LUMORA_RPC_ADDR=0.0.0.0:3030

EXPOSE 3030

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:3030/health || exit 1

ENTRYPOINT ["lumora-rpc"]
