# ─── Lumora — Developer Task Runner ─────────────────────────────────
.PHONY: build test test-slow test-all lint fmt clean bench docs \
        sdk-ts sdk-py docker docker-compose help

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ─── Build ──────────────────────────────────────────────────────────

build: ## Build all workspace crates
	cargo build --workspace

release: ## Build optimised release binaries
	cargo build --workspace --release

# ─── Test ───────────────────────────────────────────────────────────

test: ## Run all unit tests
	cargo test --workspace --lib

test-doc: ## Run documentation tests
	cargo test --workspace --doc

test-int: ## Run integration tests
	cargo test --workspace --test '*'

test-slow: ## Run proof-heavy integration tests (single-threaded)
	cargo test --workspace --test '*' -- --test-threads=1

test-all: test test-doc test-int sdk-ts sdk-py ## Run every test suite

# ─── Lint / Format ──────────────────────────────────────────────────

lint: ## Run clippy with strict warnings
	cargo clippy --workspace --all-targets -- -D warnings

fmt: ## Check formatting
	cargo fmt --all -- --check

fmt-fix: ## Auto-fix formatting
	cargo fmt --all

# ─── SDKs ───────────────────────────────────────────────────────────

sdk-ts: ## Build & test TypeScript SDK
	cd sdks/typescript && npm ci && npm run build && npm test

sdk-py: ## Run Python SDK tests
	cd sdks/python && python3 -m pytest tests/ -v

# ─── Bench / Docs ───────────────────────────────────────────────────

bench: ## Compile and run benchmarks
	cargo bench --workspace

bench-check: ## Compile benchmarks (no run)
	cargo bench --workspace --no-run

docs: ## Build Rust documentation
	cargo doc --workspace --no-deps --open

# ─── Docker ─────────────────────────────────────────────────────────

docker: ## Build Docker image
	docker build -t lumora:latest .

docker-compose: ## Start full stack via docker-compose
	docker compose up -d

# ─── Supply Chain Audit ─────────────────────────────────────────────

deny: ## Run cargo-deny supply chain audit
	cargo deny check

# ─── Clean ──────────────────────────────────────────────────────────

clean: ## Remove build artefacts
	cargo clean
