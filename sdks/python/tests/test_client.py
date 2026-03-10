"""Unit tests for Lumora Python SDK (offline & with mock server)."""

import json
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Any
from lumora import LumoraClient, LumoraError, LumoraConnectionError


# ── Mock Server ─────────────────────────────────────────────────────

class _MockHandler(BaseHTTPRequestHandler):
    """Minimal handler that returns canned responses so we can verify
    the SDK constructs correct requests."""

    def _send_json(self, code: int, body: Any) -> None:
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return json.loads(self.rfile.read(length))
        return {}

    # ── Routes ──────────────────────────────────────────────────────

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_json(200, {
                "status": "ok",
                "version": "0.1.0",
                "uptime_secs": 42,
                "pool_balance": 0,
                "commitment_count": 0,
                "current_epoch": 0,
                "merkle_root": "00" * 32,
            })
        elif self.path == "/v1/status":
            self._send_json(200, {
                "pool_balance": 42,
                "commitment_count": 10,
                "merkle_root": "0x1234",
                "circuit_version": "v1",
            })
        elif self.path == "/v1/fees":
            self._send_json(200, {
                "transfer_fee": 1,
                "withdraw_fee": 2,
                "min_deposit": 100,
                "min_withdraw": 100,
            })
        elif self.path == "/v1/epoch-roots":
            self._send_json(200, {
                "current_epoch": 3,
                "roots": [{"epoch_id": 1, "root": "0xabc"}],
            })
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        body = self._read_body()

        if self.path == "/v1/deposit":
            self._send_json(200, {"leaf_index": 0, "new_root": "0xdead"})
        elif self.path == "/v1/transfer":
            resp: dict[str, Any] = {
                "leaf_indices": [1, 2],
                "new_root": "0xbeef",
            }
            if "domain_chain_id" in body:
                resp["_domain_chain_id"] = body["domain_chain_id"]
            if "domain_app_id" in body:
                resp["_domain_app_id"] = body["domain_app_id"]
            self._send_json(200, resp)
        elif self.path == "/v1/withdraw":
            resp = {
                "change_leaf_indices": [3, 4],
                "new_root": "0xcafe",
                "amount": body.get("amount", 0),
            }
            if "domain_chain_id" in body:
                resp["_domain_chain_id"] = body["domain_chain_id"]
            self._send_json(200, resp)
        elif self.path == "/v1/nullifier":
            self._send_json(200, {"spent": False})
        elif self.path == "/v1/relay-note":
            self._send_json(201, None)
        elif self.path == "/v1/notes":
            self._send_json(200, [
                {"leaf_index": 0, "commitment": "aa", "ciphertext": "bb", "ephemeral_pubkey": "cc"},
            ])
        elif self.path == "/v1/history":
            self._send_json(200, {"total": 5, "events": []})
        elif self.path == "/v1/batch-verify":
            self._send_json(200, {"all_valid": True, "count": len(body.get("proofs", []))})
        elif self.path == "/v1/stealth-scan":
            self._send_json(200, {"notes": [], "count": 0})
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # silence server logs during tests


def _start_mock_server() -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), _MockHandler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


# ── Unit Tests (no server) ──────────────────────────────────────────

class TestClientConstruction(unittest.TestCase):
    def test_create_client(self) -> None:
        client = LumoraClient("http://127.0.0.1:3030", api_key="test-key")
        self.assertEqual(client.base_url, "http://127.0.0.1:3030")
        self.assertEqual(client.api_key, "test-key")

    def test_strip_trailing_slash(self) -> None:
        client = LumoraClient("http://localhost:3030/")
        self.assertEqual(client.base_url, "http://localhost:3030")

    def test_no_api_key(self) -> None:
        client = LumoraClient("http://localhost:3030")
        self.assertIsNone(client.api_key)


class TestLumoraError(unittest.TestCase):
    def test_error_message(self) -> None:
        err = LumoraError(401, "unauthorized")
        self.assertEqual(err.status, 401)
        self.assertEqual(err.body, "unauthorized")
        self.assertIn("401", str(err))


# ── Integration Tests (with mock server) ────────────────────────────

class TestClientWithMockServer(unittest.TestCase):
    server: HTTPServer
    url: str
    client: LumoraClient

    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.url = _start_mock_server()
        cls.client = LumoraClient(cls.url, api_key="test")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    # ── Health / status ─────────────────────────────────────────────

    def test_health(self) -> None:
        resp = self.client.health()
        self.assertEqual(resp["status"], "ok")
        self.assertIn("version", resp)
        self.assertIn("uptime_secs", resp)

    def test_status(self) -> None:
        resp = self.client.status()
        self.assertEqual(resp["pool_balance"], 42)
        self.assertIn("merkle_root", resp)

    def test_fees(self) -> None:
        resp = self.client.fees()
        self.assertIn("transfer_fee", resp)
        self.assertIn("min_deposit", resp)

    # ── Deposit ─────────────────────────────────────────────────────

    def test_deposit(self) -> None:
        resp = self.client.deposit("0xabc", 100)
        self.assertIn("leaf_index", resp)
        self.assertIn("new_root", resp)

    # ── Transfer ────────────────────────────────────────────────────

    def test_transfer(self) -> None:
        resp = self.client.transfer(
            proof="0xproof",
            merkle_root="0xroot",
            nullifiers=("0xnf0", "0xnf1"),
            output_commitments=("0xcm0", "0xcm1"),
        )
        self.assertIn("leaf_indices", resp)

    def test_transfer_with_domain(self) -> None:
        resp = self.client.transfer(
            proof="0xproof",
            merkle_root="0xroot",
            nullifiers=("0xnf0", "0xnf1"),
            output_commitments=("0xcm0", "0xcm1"),
            domain_chain_id=1,
            domain_app_id=42,
        )
        self.assertEqual(resp["_domain_chain_id"], 1)
        self.assertEqual(resp["_domain_app_id"], 42)

    # ── Withdraw ────────────────────────────────────────────────────

    def test_withdraw(self) -> None:
        resp = self.client.withdraw(
            proof="0xproof",
            merkle_root="0xroot",
            nullifiers=("0xnf0", "0xnf1"),
            output_commitments=("0xcm0", "0xcm1"),
            amount=500,
            recipient="0xrecipient",
        )
        self.assertEqual(resp["amount"], 500)
        self.assertIn("change_leaf_indices", resp)

    def test_withdraw_with_domain(self) -> None:
        resp = self.client.withdraw(
            proof="0xproof",
            merkle_root="0xroot",
            nullifiers=("0xnf0", "0xnf1"),
            output_commitments=("0xcm0", "0xcm1"),
            amount=100,
            recipient="0xrecipient",
            domain_chain_id=7,
        )
        self.assertEqual(resp["_domain_chain_id"], 7)

    # ── Nullifier ───────────────────────────────────────────────────

    def test_check_nullifier(self) -> None:
        resp = self.client.check_nullifier("0xnf")
        self.assertFalse(resp["spent"])

    # ── Notes ───────────────────────────────────────────────────────

    def test_relay_note(self) -> None:
        self.client.relay_note(
            recipient_tag="aa" * 32,
            leaf_index=0,
            commitment="bb" * 32,
            ciphertext="cc" * 64,
            ephemeral_pubkey="dd" * 32,
        )

    def test_get_notes(self) -> None:
        resp = self.client.get_notes("aa" * 32)
        self.assertIsInstance(resp, list)
        self.assertEqual(len(resp), 1)
        self.assertIn("commitment", resp[0])

    # ── History ─────────────────────────────────────────────────────

    def test_history(self) -> None:
        resp = self.client.history(offset=0, limit=10)
        self.assertEqual(resp["total"], 5)

    # ── Batch verify ────────────────────────────────────────────────

    def test_batch_verify(self) -> None:
        resp = self.client.batch_verify([{"proof": "0x"}])
        self.assertTrue(resp["all_valid"])
        self.assertEqual(resp["count"], 1)

    # ── Epoch roots ─────────────────────────────────────────────────

    def test_epoch_roots(self) -> None:
        resp = self.client.epoch_roots()
        self.assertEqual(resp["current_epoch"], 3)
        self.assertEqual(len(resp["roots"]), 1)

    # ── Stealth scan ────────────────────────────────────────────────

    def test_stealth_scan(self) -> None:
        resp = self.client.stealth_scan(from_leaf_index=0, limit=500)
        self.assertEqual(resp["count"], 0)
        self.assertIsInstance(resp["notes"], list)

    # ── Error handling ──────────────────────────────────────────────

    def test_404_raises_lumora_error(self) -> None:
        client = LumoraClient(self.url)
        with self.assertRaises(LumoraError) as ctx:
            client._request("GET", "/nonexistent")
        self.assertEqual(ctx.exception.status, 404)


# ── Timeout & Retry tests ──────────────────────────────────────────

class _SlowHandler(BaseHTTPRequestHandler):
    """Handler that sleeps longer than the client timeout."""

    def do_GET(self) -> None:  # noqa: N802
        import time
        time.sleep(5)
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: object) -> None:
        pass


class _RetryHandler(BaseHTTPRequestHandler):
    """Returns 503 for first N requests, then 200."""

    call_count = 0

    def do_GET(self) -> None:  # noqa: N802
        _RetryHandler.call_count += 1
        if _RetryHandler.call_count < 3:
            payload = b'"overloaded"'
            self.send_response(503)
        else:
            payload = json.dumps({
                "pool_balance": 1,
                "commitment_count": 0,
                "merkle_root": "aa",
                "circuit_version": "v1",
            }).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: object) -> None:
        pass


class TestTimeoutAndRetry(unittest.TestCase):
    """Tests for SDK timeout and retry behaviour."""

    def test_timeout_raises_connection_error(self) -> None:
        server = HTTPServer(("127.0.0.1", 0), _SlowHandler)
        port = server.server_address[1]
        t = Thread(target=server.handle_request, daemon=True)
        t.start()
        client = LumoraClient(f"http://127.0.0.1:{port}", timeout=0.5)
        with self.assertRaises(LumoraConnectionError):
            client._request("GET", "/slow")
        server.server_close()

    def test_retry_on_503_succeeds(self) -> None:
        _RetryHandler.call_count = 0
        server = HTTPServer(("127.0.0.1", 0), _RetryHandler)
        port = server.server_address[1]
        t = Thread(target=lambda: [server.handle_request() for _ in range(3)], daemon=True)
        t.start()
        client = LumoraClient(
            f"http://127.0.0.1:{port}",
            timeout=5.0,
            max_retries=3,
            retry_base=0.01,
        )
        resp = client.status()
        self.assertEqual(resp["pool_balance"], 1)
        self.assertEqual(_RetryHandler.call_count, 3)
        server.server_close()

    def test_no_retry_on_400(self) -> None:
        call_count = 0

        class _BadReqHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                nonlocal call_count
                call_count += 1
                payload = b'"bad request"'
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args: object) -> None:
                pass

        server = HTTPServer(("127.0.0.1", 0), _BadReqHandler)
        port = server.server_address[1]
        t = Thread(target=server.handle_request, daemon=True)
        t.start()
        client = LumoraClient(
            f"http://127.0.0.1:{port}",
            timeout=5.0,
            max_retries=3,
            retry_base=0.01,
        )
        with self.assertRaises(LumoraError):
            client.status()
        self.assertEqual(call_count, 1, "should not retry 400 errors")
        server.server_close()

    def test_constructor_defaults(self) -> None:
        client = LumoraClient("http://localhost:3030")
        self.assertIsNotNone(client)


if __name__ == "__main__":
    unittest.main()
