"""
Lumora Python SDK — HTTP client for the Lumora RPC API.

Usage::

    from lumora import LumoraClient

    client = LumoraClient("http://127.0.0.1:3030", api_key="my-api-key")
    status = client.status()
    print(f"Pool balance: {status['pool_balance']}")

    # With timeout and retries:
    client = LumoraClient(
        "http://127.0.0.1:3030",
        timeout=10.0,     # seconds
        max_retries=3,
        retry_base=0.5,   # seconds (exponential backoff)
    )
"""

from __future__ import annotations

import json
import random
import time
from typing import Any, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class LumoraError(Exception):
    """Error returned by the Lumora API."""

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"Lumora API error ({status}): {body}")


class LumoraConnectionError(Exception):
    """Network or connection error (timeout, DNS failure, etc.)."""

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        self.cause = cause
        super().__init__(message)


_RETRYABLE_STATUS = frozenset({429, 502, 503, 504})

# Maximum response body size to prevent memory exhaustion (10 MB).
MAX_RESPONSE_BYTES = 10 * 1024 * 1024


class LumoraClient:
    """Synchronous HTTP client for the Lumora RPC API.

    Uses only the standard library (``urllib``) — no external dependencies.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        *,
        timeout: float = 30.0,
        max_retries: int = 0,
        retry_base: float = 0.5,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Invalid URL scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed."
            )
        if api_key and parsed.scheme != "https":
            import warnings
            warnings.warn(
                "API key is being sent over plain HTTP. "
                "Use HTTPS in production to protect credentials in transit.",
                stacklevel=2,
            )
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_base = retry_base

    # ---- Internal ----------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
    ) -> Any:
        url = f"{self.base_url}/v1{path}"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        data: Optional[bytes] = None
        if body is not None:
            data = json.dumps(body).encode()

        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                jitter = 0.5 + random.random()  # noqa: S311
                delay = self.retry_base * (2 ** (attempt - 1)) * jitter
                time.sleep(delay)

            req = Request(url, data=data, headers=headers, method=method)
            try:
                with urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                    body = resp.read(MAX_RESPONSE_BYTES + 1)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise LumoraError(0, f"response exceeded {MAX_RESPONSE_BYTES} bytes")
                    return json.loads(body)
            except HTTPError as exc:
                if exc.code in _RETRYABLE_STATUS and attempt < self.max_retries:
                    last_error = LumoraError(exc.code, exc.read().decode())
                    continue
                raise LumoraError(exc.code, exc.read().decode()) from exc
            except URLError as exc:
                last_error = LumoraConnectionError(
                    f"Connection error: {exc.reason}", exc,
                )
                if attempt >= self.max_retries:
                    raise last_error from exc
            except TimeoutError as exc:
                last_error = LumoraConnectionError(
                    f"Request timed out after {self.timeout}s: {method} {path}",
                    exc,
                )
                if attempt >= self.max_retries:
                    raise last_error from exc

        raise last_error or LumoraConnectionError("request failed")

    # ---- Public API --------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Check server health (unauthenticated). Returns structured JSON."""
        req = Request(f"{self.base_url}/health")
        with urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            return json.loads(resp.read(MAX_RESPONSE_BYTES))

    def status(self) -> dict[str, Any]:
        """Get pool status."""
        return self._request("GET", "/status")

    def fees(self) -> dict[str, Any]:
        """Get fee estimates."""
        return self._request("GET", "/fees")

    def deposit(self, commitment: str, amount: int) -> dict[str, Any]:
        """Deposit a commitment into the pool."""
        return self._request("POST", "/deposit", {
            "commitment": commitment,
            "amount": amount,
        })

    def transfer(
        self,
        proof: str,
        merkle_root: str,
        nullifiers: tuple[str, str],
        output_commitments: tuple[str, str],
        *,
        domain_chain_id: Optional[int] = None,
        domain_app_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """Submit a private transfer proof."""
        body: dict[str, Any] = {
            "proof": proof,
            "merkle_root": merkle_root,
            "nullifiers": list(nullifiers),
            "output_commitments": list(output_commitments),
        }
        if domain_chain_id is not None:
            body["domain_chain_id"] = domain_chain_id
        if domain_app_id is not None:
            body["domain_app_id"] = domain_app_id
        return self._request("POST", "/transfer", body)

    def withdraw(
        self,
        proof: str,
        merkle_root: str,
        nullifiers: tuple[str, str],
        output_commitments: tuple[str, str],
        amount: int,
        recipient: str,
        *,
        domain_chain_id: Optional[int] = None,
        domain_app_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """Submit a withdrawal proof."""
        body: dict[str, Any] = {
            "proof": proof,
            "merkle_root": merkle_root,
            "nullifiers": list(nullifiers),
            "output_commitments": list(output_commitments),
            "amount": amount,
            "recipient": recipient,
        }
        if domain_chain_id is not None:
            body["domain_chain_id"] = domain_chain_id
        if domain_app_id is not None:
            body["domain_app_id"] = domain_app_id
        return self._request("POST", "/withdraw", body)

    def check_nullifier(self, nullifier: str) -> dict[str, Any]:
        """Check if a nullifier has been spent."""
        return self._request("POST", "/nullifier", {"nullifier": nullifier})

    def relay_note(
        self,
        recipient_tag: str,
        leaf_index: int,
        commitment: str,
        ciphertext: str,
        ephemeral_pubkey: str,
    ) -> None:
        """Store an encrypted note for a recipient."""
        self._request("POST", "/relay-note", {
            "recipient_tag": recipient_tag,
            "leaf_index": leaf_index,
            "commitment": commitment,
            "ciphertext": ciphertext,
            "ephemeral_pubkey": ephemeral_pubkey,
        })

    def get_notes(self, recipient_tag: str) -> list[dict[str, Any]]:
        """Fetch encrypted notes by recipient tag."""
        return self._request("POST", "/notes", {"recipient_tag": recipient_tag})

    def history(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Query paginated event history."""
        return self._request("POST", "/history", {
            "offset": offset,
            "limit": limit,
        })

    def sync_status(self) -> dict[str, Any]:
        """Get node sync status."""
        return self._request("GET", "/sync/status")

    def batch_verify(
        self,
        proofs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Batch verify transfer proofs."""
        return self._request("POST", "/batch-verify", {"proofs": proofs})

    def epoch_roots(self) -> dict[str, Any]:
        """Get all finalized nullifier-epoch Merkle roots."""
        return self._request("GET", "/epoch-roots")

    def stealth_scan(
        self,
        from_leaf_index: int = 0,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """Fetch encrypted notes for client-side stealth address scanning."""
        return self._request("POST", "/stealth-scan", {
            "from_leaf_index": from_leaf_index,
            "limit": limit,
        })

    # ── BitVM Bridge ────────────────────────────────────────────────

    def bitvm_status(self) -> dict[str, Any]:
        """Check BitVM bridge status."""
        return self._request("GET", "/bitvm/status")

    def bitvm_poll_deposits(self) -> dict[str, Any]:
        """Poll the host chain for new deposits via the BitVM bridge."""
        return self._request("POST", "/bitvm/poll")

    def bitvm_commit_root(self) -> dict[str, Any]:
        """Commit the current Merkle root to the host chain."""
        return self._request("POST", "/bitvm/commit-root")
