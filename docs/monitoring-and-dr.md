# Monitoring & Disaster Recovery

## Prometheus Metrics

Lumora exposes metrics on `GET /metrics` in Prometheus exposition format.

### Key Metrics

| Metric                          | Type      | Description                                              |
| ------------------------------- | --------- | -------------------------------------------------------- |
| `http_requests_total`           | Counter   | Total HTTP requests by method, path, status              |
| `http_requests_rejected_total`  | Counter   | Rejected requests by reason (overload, rate_limit, auth) |
| `http_request_duration_seconds` | Histogram | Request latency by method and path                       |
| `lumora_pool_balance`           | Gauge     | Current pool balance (via `/v1/status`)                  |
| `lumora_commitment_count`       | Gauge     | Total note commitments in the Merkle tree                |

### Grafana Dashboard (recommended panels)

1. **Request rate** — `rate(http_requests_total[5m])` by path
2. **Error rate** — `rate(http_requests_total{status=~"4..|5.."}[5m])`
3. **P99 latency** — `histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))`
4. **Rate-limit rejections** — `rate(http_requests_rejected_total{reason="rate_limit"}[5m])`
5. **Pool balance** — direct gauge from `/v1/status`

### Alerting Rules (examples)

```yaml
groups:
  - name: lumora
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning

      - alert: RateLimitSpike
        expr: rate(http_requests_rejected_total{reason="rate_limit"}[5m]) > 10
        for: 2m
        labels:
          severity: info

      - alert: HealthDown
        expr: up{job="lumora"} == 0
        for: 1m
        labels:
          severity: critical
```

## Health Check

`GET /health` returns 200 with JSON status. Use this for load-balancer health probes and container liveness/readiness checks.

## State Persistence

Lumora persists state to disk via HMAC-authenticated JSON or binary files
(see [state-persistence.md](state-persistence.md) for format details).

### Backup Strategy

| Data                  | Location                 | Backup Frequency | Method                   |
| --------------------- | ------------------------ | ---------------- | ------------------------ |
| State file            | `$LUMORA_STATE_DIR/`     | Every epoch      | File copy / snapshot     |
| WAL (Write-Ahead Log) | `$LUMORA_STATE_DIR/wal/` | Continuous       | rsync or volume snapshot |
| SRS parameters        | `$LUMORA_SRS_DIR/`       | Once (immutable) | Object storage           |
| Peer list             | `peers.json`             | On change        | File copy                |

### Backup Procedure

```bash
# 1. Create an atomic snapshot of the state directory
cp -a "$LUMORA_STATE_DIR" "/backups/lumora-$(date +%s)"

# 2. Verify HMAC integrity of the backup
lumora-cli verify-state --path "/backups/lumora-<timestamp>/state.json"
```

## Disaster Recovery

### Scenario: State File Corruption

1. Stop the Lumora node.
2. Restore the most recent verified backup to `$LUMORA_STATE_DIR`.
3. Replay WAL entries since the backup checkpoint.
4. Restart the node — it will sync remaining deltas from peers.

### Scenario: Full Node Loss

1. Provision a new machine with the same `LUMORA_HMAC_KEY` and `LUMORA_API_KEY` environment variables.
2. Restore the SRS parameters (these are deterministic and can be regenerated, but restoring is faster).
3. Restore the latest state backup.
4. Configure `peers.json` with healthy peers.
5. Start the node — state sync will catch up to the current height.

### Scenario: Key Compromise

1. Rotate `LUMORA_API_KEY` immediately and redeploy.
2. If `LUMORA_HMAC_KEY` is compromised, rotate it, re-sign the state file, and redeploy.
3. User spending keys are never stored server-side — no action needed for user keys.

## Environment Variables Reference

| Variable          | Required | Description                                    |
| ----------------- | -------- | ---------------------------------------------- |
| `LUMORA_API_KEY`  | No       | API key for authenticated endpoints            |
| `LUMORA_HMAC_KEY` | No       | HMAC key for state file integrity (base64)     |
| `LUMORA_BIND`     | No       | Listen address (default `0.0.0.0:3030`)        |
| `RUST_LOG`        | No       | Tracing filter (e.g. `lumora=info,tower=warn`) |
