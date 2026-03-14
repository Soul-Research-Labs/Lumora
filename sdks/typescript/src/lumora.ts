/**
 * Lumora TypeScript SDK — HTTP client for the Lumora RPC API.
 *
 * @example
 * ```typescript
 * import { LumoraClient } from './lumora';
 *
 * const client = new LumoraClient('http://127.0.0.1:3030', 'my-api-key');
 * const status = await client.status();
 * console.log(`Pool balance: ${status.pool_balance}`);
 * ```
 */

export interface StatusResponse {
  pool_balance: number;
  commitment_count: number;
  merkle_root: string;
  circuit_version: string;
}

export interface FeeEstimate {
  transfer_fee: number;
  withdraw_fee: number;
  deposit_fee: number;
}

export interface DepositRequest {
  commitment: string;
  amount: number;
}

export interface DepositReceipt {
  leaf_index: number;
  merkle_root: string;
}

export interface TransferRequest {
  proof_bytes: string;
  merkle_root: string;
  nullifiers: [string, string];
  output_commitments: [string, string];
  /** Optional V2 domain chain ID for cross-chain nullifier isolation. */
  domain_chain_id?: number;
  /** Optional V2 domain app ID for cross-chain nullifier isolation. */
  domain_app_id?: number;
}

export interface TransferReceipt {
  nullifiers: [string, string];
  output_commitments: [string, string];
  new_root: string;
}

export interface WithdrawRequest {
  proof_bytes: string;
  merkle_root: string;
  nullifiers: [string, string];
  output_commitments: [string, string];
  amount: number;
  recipient: string;
  /** Optional V2 domain chain ID for cross-chain nullifier isolation. */
  domain_chain_id?: number;
  /** Optional V2 domain app ID for cross-chain nullifier isolation. */
  domain_app_id?: number;
}

export interface WithdrawReceipt {
  amount: number;
  recipient: string;
  new_root: string;
}

export interface NullifierCheck {
  nullifier: string;
}

export interface NullifierResult {
  spent: boolean;
}

export interface RelayNoteRequest {
  tag: string;
  ciphertext: string;
}

export interface NotesRequest {
  tag: string;
}

export interface HistoryRequest {
  offset?: number;
  limit?: number;
}

export interface HistoryResponse {
  events: PoolEvent[];
  total: number;
}

export interface PoolEvent {
  type: "Deposit" | "Transfer" | "Withdraw";
  [key: string]: unknown;
}

export interface SyncStatus {
  height: number;
  merkle_root: string;
  nullifier_count: number;
}

export interface SyncEventsRequest {
  from_height: number;
}

export interface StateDelta {
  from_height: number;
  events: PoolEvent[];
}

export interface BatchVerifyRequest {
  proofs: TransferRequest[];
}

export interface BatchVerifyResponse {
  results: boolean[];
  all_valid: boolean;
}

export interface EpochRootEntry {
  epoch_id: number;
  root: string;
}

export interface EpochRootsResponse {
  current_epoch: number;
  roots: EpochRootEntry[];
}

export interface StealthScanRequest {
  /** Minimum leaf index to scan from (default: 0). */
  from_leaf_index?: number;
  /** Maximum number of notes to return (default: 1000). */
  limit?: number;
}

export interface EncryptedNoteResponse {
  leaf_index: number;
  commitment: string;
  ciphertext: string;
  ephemeral_pubkey: string;
}

export interface StealthScanResponse {
  notes: EncryptedNoteResponse[];
  count: number;
}

// ── BitVM Bridge ───────────────────────────────────────────────────

export interface BitvmStatusResponse {
  bridge_active: boolean;
  deposits_processed: number;
  roots_committed: number;
}

export interface BitvmPollResponse {
  new_deposits: number;
}

export interface BitvmCommitRootResponse {
  committed_root: string;
}

export class LumoraError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
  ) {
    super(`Lumora API error (${status}): ${body}`);
    this.name = "LumoraError";
  }
}

/** Connection/network error (timeout, DNS failure, etc.). */
export class LumoraConnectionError extends Error {
  constructor(
    message: string,
    public readonly cause?: Error,
  ) {
    super(message);
    this.name = "LumoraConnectionError";
  }
}

/** Options for configuring the LumoraClient. */
export interface LumoraClientOptions {
  /** Request timeout in milliseconds (default: 30000). */
  timeoutMs?: number;
  /** Maximum number of retry attempts for transient failures (default: 0 = no retries). */
  maxRetries?: number;
  /** Base delay for exponential backoff in milliseconds (default: 500). */
  retryBaseMs?: number;
}

export class LumoraClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly headers: Record<string, string>;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBaseMs: number;

  constructor(baseUrl: string, apiKey?: string, options?: LumoraClientOptions) {
    // Remove trailing slash
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.headers = {
      "Content-Type": "application/json",
      ...(apiKey ? { "X-API-Key": apiKey } : {}),
    };
    this.timeoutMs = options?.timeoutMs ?? 30_000;
    this.maxRetries = options?.maxRetries ?? 0;
    this.retryBaseMs = options?.retryBaseMs ?? 500;
  }

  // ---- Internal ----

  /** Returns true for status codes that are safe to retry. */
  private isRetryable(status: number): boolean {
    return status === 429 || status === 502 || status === 503 || status === 504;
  }

  /** Sleep for a given number of milliseconds. */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = `${this.baseUrl}/v1${path}`;

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff with jitter: base * 2^(attempt-1) * (0.5..1.5)
        const jitter = 0.5 + Math.random();
        const delay = this.retryBaseMs * Math.pow(2, attempt - 1) * jitter;
        await this.sleep(delay);
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const init: RequestInit = {
          method,
          headers: this.headers,
          signal: controller.signal,
        };
        if (body !== undefined) {
          init.body = JSON.stringify(body);
        }

        const res = await fetch(url, init);
        const text = await res.text();

        if (!res.ok) {
          if (this.isRetryable(res.status) && attempt < this.maxRetries) {
            lastError = new LumoraError(res.status, text);
            continue;
          }
          throw new LumoraError(res.status, text);
        }
        return JSON.parse(text) as T;
      } catch (err) {
        if (err instanceof LumoraError) {
          throw err;
        }
        const error = err as Error;
        if (error.name === "AbortError") {
          lastError = new LumoraConnectionError(
            `Request timed out after ${this.timeoutMs}ms: ${method} ${path}`,
          );
        } else {
          lastError = new LumoraConnectionError(
            `Network error: ${error.message}`,
            error,
          );
        }
        if (attempt >= this.maxRetries) {
          throw lastError;
        }
      } finally {
        clearTimeout(timer);
      }
    }

    // Should not be reached, but satisfy the type system.
    throw lastError ?? new LumoraConnectionError("request failed");
  }

  // ---- Public API ----

  /** Check server health (unauthenticated). */
  async health(): Promise<string> {
    const res = await fetch(`${this.baseUrl}/health`);
    return res.text();
  }

  /** Get pool status. */
  async status(): Promise<StatusResponse> {
    return this.request<StatusResponse>("GET", "/status");
  }

  /** Get fee estimates. */
  async fees(): Promise<FeeEstimate> {
    return this.request<FeeEstimate>("GET", "/fees");
  }

  /** Deposit a commitment into the pool. */
  async deposit(req: DepositRequest): Promise<DepositReceipt> {
    return this.request<DepositReceipt>("POST", "/deposit", req);
  }

  /** Submit a private transfer proof. */
  async transfer(req: TransferRequest): Promise<TransferReceipt> {
    return this.request<TransferReceipt>("POST", "/transfer", req);
  }

  /** Submit a withdrawal proof. */
  async withdraw(req: WithdrawRequest): Promise<WithdrawReceipt> {
    return this.request<WithdrawReceipt>("POST", "/withdraw", req);
  }

  /** Check if a nullifier has been spent. */
  async checkNullifier(nullifier: string): Promise<NullifierResult> {
    return this.request<NullifierResult>("POST", "/nullifier", { nullifier });
  }

  /** Store an encrypted note for a recipient. */
  async relayNote(req: RelayNoteRequest): Promise<void> {
    await this.request<unknown>("POST", "/relay-note", req);
  }

  /** Fetch encrypted notes by recipient tag. */
  async getNotes(tag: string): Promise<string[]> {
    return this.request<string[]>("POST", "/notes", { tag });
  }

  /** Query paginated event history. */
  async history(req?: HistoryRequest): Promise<HistoryResponse> {
    return this.request<HistoryResponse>("POST", "/history", req ?? {});
  }

  /** Get node sync status. */
  async syncStatus(): Promise<SyncStatus> {
    return this.request<SyncStatus>("GET", "/sync/status");
  }

  /** Fetch state delta (events) from a given height for syncing. */
  async syncEvents(req: SyncEventsRequest): Promise<StateDelta> {
    return this.request<StateDelta>("POST", "/sync/events", req);
  }

  /** Batch verify transfer proofs. */
  async batchVerify(proofs: TransferRequest[]): Promise<BatchVerifyResponse> {
    return this.request<BatchVerifyResponse>("POST", "/batch-verify", {
      proofs,
    });
  }

  /** Get finalized nullifier epoch roots for cross-chain sync. */
  async epochRoots(): Promise<EpochRootsResponse> {
    return this.request<EpochRootsResponse>("GET", "/epoch-roots");
  }

  /**
   * Scan all encrypted notes for stealth address detection.
   *
   * Downloads all notes since `from_leaf_index` so the client can perform
   * trial decryption locally without revealing which notes it owns.
   */
  async stealthScan(req?: StealthScanRequest): Promise<StealthScanResponse> {
    return this.request<StealthScanResponse>(
      "POST",
      "/stealth-scan",
      req ?? {},
    );
  }

  // ---- BitVM Bridge ----

  /** Check BitVM bridge status. */
  async bitvmStatus(): Promise<BitvmStatusResponse> {
    return this.request<BitvmStatusResponse>("GET", "/bitvm/status");
  }

  /** Poll the host chain for new deposits via the BitVM bridge. */
  async bitvmPollDeposits(): Promise<BitvmPollResponse> {
    return this.request<BitvmPollResponse>("POST", "/bitvm/poll");
  }

  /** Commit the current Merkle root to the host chain. */
  async bitvmCommitRoot(): Promise<BitvmCommitRootResponse> {
    return this.request<BitvmCommitRootResponse>("POST", "/bitvm/commit-root");
  }
}
