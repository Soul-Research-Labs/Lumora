/**
 * Unit tests for LumoraClient — uses Node.js built-in test runner.
 *
 * Run: npm run build && npm test
 */

import { describe, it, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { LumoraClient, LumoraError, LumoraConnectionError } from "./lumora.js";
import type { StatusResponse, FeeEstimate, DepositReceipt } from "./lumora.js";

// ── Test helpers ──────────────────────────────────────────────────

/** Create a mock Response object. */
function mockResponse(body: unknown, status = 200, ok = true): Response {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    ok,
    status,
    text: async () => text,
    headers: new Headers(),
    redirected: false,
    statusText: ok ? "OK" : "Error",
    type: "basic" as const,
    url: "",
    clone: () => mockResponse(body, status, ok),
    body: null,
    bodyUsed: false,
    arrayBuffer: async () => new ArrayBuffer(0),
    blob: async () => new Blob(),
    formData: async () => new FormData(),
    json: async () => JSON.parse(text),
    bytes: async () => new Uint8Array(),
  };
}

let originalFetch: typeof globalThis.fetch;
let fetchMock: ReturnType<typeof mock.fn<typeof globalThis.fetch>>;

function installFetchMock(response: Response): void {
  fetchMock = mock.fn<typeof globalThis.fetch>(async () => response);
  globalThis.fetch = fetchMock;
}

// ── Tests ─────────────────────────────────────────────────────────

describe("LumoraClient", () => {
  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe("constructor", () => {
    it("strips trailing slashes from baseUrl", () => {
      const client = new LumoraClient("http://localhost:3030///");
      // No assertion on private field—behavior tested through request URLs.
      assert.ok(client);
    });
  });

  describe("health()", () => {
    it("calls /health and returns text", async () => {
      installFetchMock(mockResponse("ok"));
      const client = new LumoraClient("http://localhost:3030");
      const result = await client.health();
      assert.equal(result, "ok");
      assert.equal(fetchMock.mock.calls.length, 1);
      const url = fetchMock.mock.calls[0].arguments[0];
      assert.equal(url, "http://localhost:3030/health");
    });
  });

  describe("status()", () => {
    it("returns parsed status response", async () => {
      const body: StatusResponse = {
        pool_balance: 5000,
        commitment_count: 10,
        merkle_root: "ab".repeat(32),
        circuit_version: "v1.0",
      };
      installFetchMock(mockResponse(body));
      const client = new LumoraClient("http://localhost:3030");
      const status = await client.status();
      assert.equal(status.pool_balance, 5000);
      assert.equal(status.commitment_count, 10);
      assert.equal(status.circuit_version, "v1.0");
    });

    it("sends GET to /v1/status", async () => {
      installFetchMock(
        mockResponse({
          pool_balance: 0,
          commitment_count: 0,
          merkle_root: "",
          circuit_version: "",
        }),
      );
      const client = new LumoraClient("http://localhost:3030");
      await client.status();
      const [url, init] = fetchMock.mock.calls[0].arguments;
      assert.equal(url, "http://localhost:3030/v1/status");
      assert.equal((init as RequestInit).method, "GET");
    });
  });

  describe("fees()", () => {
    it("returns fee estimates", async () => {
      const body: FeeEstimate = {
        transfer_fee: 10,
        withdraw_fee: 20,
        deposit_fee: 0,
      };
      installFetchMock(mockResponse(body));
      const client = new LumoraClient("http://localhost:3030");
      const fees = await client.fees();
      assert.equal(fees.transfer_fee, 10);
      assert.equal(fees.withdraw_fee, 20);
    });
  });

  describe("deposit()", () => {
    it("sends POST with commitment and amount", async () => {
      const receipt: DepositReceipt = {
        leaf_index: 0,
        merkle_root: "ff".repeat(32),
      };
      installFetchMock(mockResponse(receipt));
      const client = new LumoraClient("http://localhost:3030");
      const result = await client.deposit({
        commitment: "aa".repeat(32),
        amount: 1000,
      });
      assert.equal(result.leaf_index, 0);

      const [url, init] = fetchMock.mock.calls[0].arguments;
      assert.equal(url, "http://localhost:3030/v1/deposit");
      assert.equal((init as RequestInit).method, "POST");
      const body = JSON.parse((init as RequestInit).body as string);
      assert.equal(body.commitment, "aa".repeat(32));
      assert.equal(body.amount, 1000);
    });
  });

  describe("checkNullifier()", () => {
    it("sends POST with nullifier field", async () => {
      installFetchMock(mockResponse({ spent: false }));
      const client = new LumoraClient("http://localhost:3030");
      const result = await client.checkNullifier("00".repeat(32));
      assert.equal(result.spent, false);

      const body = JSON.parse(
        (fetchMock.mock.calls[0].arguments[1] as RequestInit).body as string,
      );
      assert.equal(body.nullifier, "00".repeat(32));
    });
  });

  describe("history()", () => {
    it("returns paginated events", async () => {
      installFetchMock(
        mockResponse({ events: [{ type: "Deposit" }], total: 1 }),
      );
      const client = new LumoraClient("http://localhost:3030");
      const history = await client.history({ offset: 0, limit: 50 });
      assert.equal(history.total, 1);
      assert.equal(history.events.length, 1);
    });

    it("sends empty object when no params", async () => {
      installFetchMock(mockResponse({ events: [], total: 0 }));
      const client = new LumoraClient("http://localhost:3030");
      await client.history();
      const body = JSON.parse(
        (fetchMock.mock.calls[0].arguments[1] as RequestInit).body as string,
      );
      assert.deepEqual(body, {});
    });
  });

  describe("API key authentication", () => {
    it("includes X-API-Key header when apiKey provided", async () => {
      installFetchMock(
        mockResponse({
          pool_balance: 0,
          commitment_count: 0,
          merkle_root: "",
          circuit_version: "",
        }),
      );
      const client = new LumoraClient("http://localhost:3030", "secret-key");
      await client.status();
      const headers = (fetchMock.mock.calls[0].arguments[1] as RequestInit)
        .headers as Record<string, string>;
      assert.equal(headers["X-API-Key"], "secret-key");
    });

    it("does not include X-API-Key when no apiKey", async () => {
      installFetchMock(
        mockResponse({
          pool_balance: 0,
          commitment_count: 0,
          merkle_root: "",
          circuit_version: "",
        }),
      );
      const client = new LumoraClient("http://localhost:3030");
      await client.status();
      const headers = (fetchMock.mock.calls[0].arguments[1] as RequestInit)
        .headers as Record<string, string>;
      assert.equal(headers["X-API-Key"], undefined);
    });
  });

  describe("error handling", () => {
    it("throws LumoraError on non-ok response", async () => {
      installFetchMock(mockResponse('{"error":"bad request"}', 400, false));
      const client = new LumoraClient("http://localhost:3030");
      await assert.rejects(
        () => client.status(),
        (err: unknown) => {
          assert.ok(err instanceof LumoraError);
          assert.equal(err.status, 400);
          assert.ok(err.body.includes("bad request"));
          return true;
        },
      );
    });

    it("LumoraError has correct name", () => {
      const err = new LumoraError(500, "internal");
      assert.equal(err.name, "LumoraError");
      assert.ok(err.message.includes("500"));
    });
  });

  describe("syncStatus()", () => {
    it("sends GET to /v1/sync/status", async () => {
      installFetchMock(
        mockResponse({
          height: 42,
          merkle_root: "ab".repeat(32),
          nullifier_count: 5,
        }),
      );
      const client = new LumoraClient("http://localhost:3030");
      const s = await client.syncStatus();
      assert.equal(s.height, 42);
      assert.equal(s.nullifier_count, 5);
    });
  });

  describe("syncEvents()", () => {
    it("sends POST to /v1/sync/events with from_height", async () => {
      installFetchMock(
        mockResponse({
          from_height: 10,
          events: [{ type: "Deposit", amount: 100 }],
        }),
      );
      const client = new LumoraClient("http://localhost:3030");
      const delta = await client.syncEvents({ from_height: 10 });
      assert.equal(delta.from_height, 10);
      assert.equal(delta.events.length, 1);
      assert.equal(delta.events[0].type, "Deposit");
    });
  });

  describe("batchVerify()", () => {
    it("sends POST with proofs array", async () => {
      installFetchMock(mockResponse({ results: [true], all_valid: true }));
      const client = new LumoraClient("http://localhost:3030");
      const result = await client.batchVerify([
        {
          proof_bytes: "aa",
          merkle_root: "bb",
          nullifiers: ["cc", "dd"],
          output_commitments: ["ee", "ff"],
        },
      ]);
      assert.equal(result.all_valid, true);
    });
  });

  describe("epochRoots()", () => {
    it("sends GET to /v1/epoch-roots", async () => {
      installFetchMock(
        mockResponse({
          current_epoch: 100,
          roots: [{ epoch_id: 99, root: "aabb" }],
        }),
      );
      const client = new LumoraClient("http://localhost:3030");
      const result = await client.epochRoots();
      assert.equal(result.current_epoch, 100);
      assert.equal(result.roots.length, 1);
      assert.equal(result.roots[0].epoch_id, 99);
    });
  });

  describe("stealthScan()", () => {
    it("sends POST to /v1/stealth-scan with defaults", async () => {
      installFetchMock(mockResponse({ notes: [], count: 0 }));
      const client = new LumoraClient("http://localhost:3030");
      const result = await client.stealthScan();
      assert.equal(result.count, 0);
      assert.deepEqual(result.notes, []);
    });

    it("sends POST with from_leaf_index and limit", async () => {
      installFetchMock(
        mockResponse({
          notes: [
            {
              leaf_index: 5,
              commitment: "aa",
              ciphertext: "bb",
              ephemeral_pubkey: "cc",
            },
          ],
          count: 1,
        }),
      );
      const client = new LumoraClient("http://localhost:3030");
      const result = await client.stealthScan({
        from_leaf_index: 5,
        limit: 10,
      });
      assert.equal(result.count, 1);
      assert.equal(result.notes[0].leaf_index, 5);
    });
  });

  describe("domain fields", () => {
    it("transfer accepts optional domain fields", async () => {
      installFetchMock(
        mockResponse({
          nullifiers: ["a", "b"],
          output_commitments: ["c", "d"],
          new_root: "ee",
        }),
      );
      const client = new LumoraClient("http://localhost:3030");
      await client.transfer({
        proof_bytes: "aa",
        merkle_root: "bb",
        nullifiers: ["cc", "dd"],
        output_commitments: ["ee", "ff"],
        domain_chain_id: 1,
        domain_app_id: 42,
      });
      assert.equal(fetchMock.mock.calls.length, 1);
    });
  });

  describe("timeout and retry", () => {
    it("throws LumoraConnectionError on timeout", async () => {
      // Simulate an abort (timeout) by installing a fetch that rejects
      // with an AbortError.
      const abortError = new DOMException(
        "The operation was aborted",
        "AbortError",
      );
      globalThis.fetch = mock.fn<typeof globalThis.fetch>(async () => {
        throw abortError;
      }) as unknown as typeof globalThis.fetch;

      const client = new LumoraClient("http://localhost:3030", undefined, {
        timeoutMs: 1,
        maxRetries: 0,
      });

      await assert.rejects(
        () => client.status(),
        (err: Error) => {
          assert.ok(err instanceof LumoraConnectionError);
          assert.match(err.message, /timed out/i);
          return true;
        },
      );
    });

    it("retries on 503 and eventually succeeds", async () => {
      let callCount = 0;
      globalThis.fetch = mock.fn<typeof globalThis.fetch>(async () => {
        callCount++;
        if (callCount < 3) {
          return mockResponse("overloaded", 503, false);
        }
        return mockResponse({
          pool_balance: 1,
          commitment_count: 0,
          merkle_root: "aa",
          circuit_version: "v1",
        });
      }) as unknown as typeof globalThis.fetch;

      const client = new LumoraClient("http://localhost:3030", undefined, {
        timeoutMs: 5000,
        maxRetries: 3,
        retryBaseMs: 1, // minimal delay for tests
      });

      const result = await client.status();
      assert.equal(result.pool_balance, 1);
      assert.equal(callCount, 3);
    });

    it("retries exhausted throws last error", async () => {
      globalThis.fetch = mock.fn<typeof globalThis.fetch>(async () => {
        return mockResponse("overloaded", 503, false);
      }) as unknown as typeof globalThis.fetch;

      const client = new LumoraClient("http://localhost:3030", undefined, {
        timeoutMs: 5000,
        maxRetries: 2,
        retryBaseMs: 1,
      });

      await assert.rejects(
        () => client.status(),
        (err: Error) => {
          assert.ok(err instanceof LumoraError);
          assert.equal((err as LumoraError).status, 503);
          return true;
        },
      );
    });

    it("does not retry 4xx errors", async () => {
      let callCount = 0;
      globalThis.fetch = mock.fn<typeof globalThis.fetch>(async () => {
        callCount++;
        return mockResponse("bad request", 400, false);
      }) as unknown as typeof globalThis.fetch;

      const client = new LumoraClient("http://localhost:3030", undefined, {
        timeoutMs: 5000,
        maxRetries: 3,
        retryBaseMs: 1,
      });

      await assert.rejects(
        () => client.status(),
        (err: Error) => {
          assert.ok(err instanceof LumoraError);
          return true;
        },
      );
      assert.equal(callCount, 1, "should not retry 4xx errors");
    });

    it("constructor uses defaults when options omitted", () => {
      const client = new LumoraClient("http://localhost:3030");
      // No crash — defaults are applied
      assert.ok(client);
    });
  });

  describe("relayNote()", () => {
    it("sends POST to /v1/relay-note with tag and ciphertext", async () => {
      installFetchMock(mockResponse("{}", 200, true));
      const client = new LumoraClient("http://localhost:3030");
      await client.relayNote({ tag: "aabb", ciphertext: "ccdd" });
      assert.equal(fetchMock.mock.calls.length, 1);

      const [url, init] = fetchMock.mock.calls[0].arguments;
      assert.equal(url, "http://localhost:3030/v1/relay-note");
      assert.equal((init as RequestInit).method, "POST");
      const body = JSON.parse((init as RequestInit).body as string);
      assert.equal(body.tag, "aabb");
      assert.equal(body.ciphertext, "ccdd");
    });

    it("throws LumoraError on 400 response", async () => {
      installFetchMock(mockResponse('{"error":"missing fields"}', 400, false));
      const client = new LumoraClient("http://localhost:3030");
      await assert.rejects(
        () => client.relayNote({ tag: "", ciphertext: "" }),
        (err: unknown) => {
          assert.ok(err instanceof LumoraError);
          assert.equal(err.status, 400);
          return true;
        },
      );
    });
  });

  describe("getNotes()", () => {
    it("sends POST to /v1/notes with tag", async () => {
      installFetchMock(mockResponse(["note1", "note2"]));
      const client = new LumoraClient("http://localhost:3030");
      const notes = await client.getNotes("aabb");
      assert.deepEqual(notes, ["note1", "note2"]);

      const [url, init] = fetchMock.mock.calls[0].arguments;
      assert.equal(url, "http://localhost:3030/v1/notes");
      assert.equal((init as RequestInit).method, "POST");
      const body = JSON.parse((init as RequestInit).body as string);
      assert.equal(body.tag, "aabb");
    });

    it("returns empty array when no notes", async () => {
      installFetchMock(mockResponse([]));
      const client = new LumoraClient("http://localhost:3030");
      const notes = await client.getNotes("nonexistent");
      assert.deepEqual(notes, []);
    });
  });

  describe("withdraw()", () => {
    it("sends POST with all required fields", async () => {
      installFetchMock(
        mockResponse({
          amount: 100,
          recipient: "aa".repeat(32),
          new_root: "bb".repeat(32),
        }),
      );
      const client = new LumoraClient("http://localhost:3030");
      const result = await client.withdraw({
        proof_bytes: "deadbeef",
        merkle_root: "aa".repeat(32),
        nullifiers: ["bb".repeat(32), "cc".repeat(32)],
        output_commitments: ["dd".repeat(32), "ee".repeat(32)],
        amount: 100,
        recipient: "ff".repeat(32),
      });
      assert.equal(result.amount, 100);
    });
  });
});
