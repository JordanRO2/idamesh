"""A thin JSON-RPC-over-HTTP client to a single worker endpoint (idapro-free).

The supervisor forwards each routed ``tools/call`` to the owning worker's
streamable-HTTP ``/mcp`` endpoint and relays the reply. A worker is a full MCP
server, so before any tool call the client must complete the MCP lifecycle with it
(``initialize`` → ``notifications/initialized``); the client does this lazily,
once per endpoint, caching the assigned ``Mcp-Session-Id``. Only the standard
library (``http.client``) is used, so this runs in the router process.

Robustness. Three failure modes are handled here so a single flaky
moment does not surface as a hard routing error:

* **Stale MCP session.** A cached ``Mcp-Session-Id`` can outlive the worker it was
  minted for (the worker restarted on the same port, or the session was torn
  down). The worker then rejects the id — either at the transport (HTTP ``404``
  ``unknown session``) or, when it does not require a session header, at the MCP
  layer (its engine's ``INVALID_PARAMS`` "Session not initialized" error). Either
  way :meth:`forward` forgets the dead id, re-handshakes once, and replays the
  frame a single time.
* **Spawn/bind race.** A ``ConnectionRefusedError`` means the TCP connect was
  refused, so the worker received nothing — safe to retry. :meth:`_post` retries
  exactly this, with a short backoff. Any other socket error is ambiguous (the
  worker may already have acted on a possibly non-idempotent tool call) and is
  never retried.
* **Deadlines.** Each HTTP round-trip is bounded by ``call_timeout`` (the socket
  timeout), so a wedged worker cannot block a routing thread indefinitely.

Connection reuse is intentionally *not* attempted: the worker's HTTP server closes
the connection after every response (HTTP/1.0), so a fresh connection per call is
the correct, race-free choice.
"""

from __future__ import annotations

import http.client
import json
import threading
import time
from typing import Any, Dict, Mapping, Optional, Tuple

#: MCP revision the supervisor negotiates with its workers.
DEFAULT_WORKER_PROTOCOL_VERSION = "2025-06-18"
#: Loopback Origin the worker's DNS-rebind guard accepts.
_ORIGIN = "http://localhost"
_ENDPOINT = "/mcp"

#: JSON-RPC "invalid params" code. Restated here as a numeric protocol fact rather
#: than imported: this module lives in ``infrastructure`` and may not depend on the
#: ``interface`` layer where ``ErrorCode.INVALID_PARAMS`` is named (it equals the
#: sibling ``infrastructure.rpc.router.RpcErrorCode.BAD_PARAMS``).
_JSONRPC_INVALID_PARAMS = -32602

#: Case-insensitive substrings that mark a *stale MCP session* in a worker's
#: rejection. Our worker's engine emits "Session not initialized …" (when it does
#: not require a session header) and its transport emits "unknown session" (when it
#: does). Matching these lets a stale cached id be recovered transparently while
#: leaving a genuine bad-argument ``INVALID_PARAMS`` (whose message never mentions
#: initialization) to propagate untouched.
_STALE_SESSION_MARKERS = ("not initialized", "unknown session")

#: How many times a refused TCP connect is retried before giving up.
_DEFAULT_CONNECT_RETRIES = 3
#: Base back-off (seconds) between connect retries; grows linearly with attempts.
_DEFAULT_RETRY_BACKOFF = 0.05


class WorkerClientError(RuntimeError):
    """A forward to a worker failed at the transport/handshake level."""


class WorkerUnavailableError(WorkerClientError):
    """The worker endpoint could not be reached (connection refused, retries spent)."""


class _StaleSession(Exception):
    """Internal signal: the worker rejected our cached ``Mcp-Session-Id`` at the
    transport (HTTP ``404``). Caught by :meth:`WorkerClient.forward` to re-handshake."""


class WorkerClient:
    """Forwards JSON-RPC frames to worker HTTP endpoints, one MCP session each."""

    def __init__(
        self,
        *,
        connect_timeout: float = 5.0,
        call_timeout: float = 120.0,
        protocol_version: str = DEFAULT_WORKER_PROTOCOL_VERSION,
        max_connect_retries: int = _DEFAULT_CONNECT_RETRIES,
        retry_backoff: float = _DEFAULT_RETRY_BACKOFF,
    ) -> None:
        # ``connect_timeout`` is reserved: ``http.client`` collapses connect and
        # read into one socket timeout, so ``call_timeout`` bounds the whole
        # round-trip. Kept in the signature as a frozen contract.
        self._connect_timeout = connect_timeout
        self._call_timeout = call_timeout
        self._protocol_version = protocol_version
        self._max_connect_retries = max(0, int(max_connect_retries))
        self._retry_backoff = max(0.0, float(retry_backoff))
        #: (host, port) -> the worker-assigned Mcp-Session-Id once initialized.
        self._sessions: Dict[Tuple[str, int], str] = {}
        self._lock = threading.Lock()

    def forward(
        self,
        *,
        host: str,
        port: int,
        frame: Mapping[str, Any],
        token: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Forward one JSON-RPC ``frame`` to the worker and return its parsed
        response (``None`` for a notification/response-only frame).

        Ensures the worker's MCP session is initialized first. If the worker
        rejects the cached session id as stale, the id is forgotten, the lifecycle
        is re-established once, and the frame is replayed a single time. Raises
        :class:`WorkerClientError` on a transport failure.
        """
        last_response: Optional[Dict[str, Any]] = None
        for attempt in range(2):
            with self._lock:
                was_cached = (host, port) in self._sessions
            session_id = self._ensure_session(host, port, token)
            try:
                response, _assigned = self._http_call(
                    host, port, frame, token, session_id
                )
            except _StaleSession:
                # Rejected at the transport (HTTP 404 unknown session).
                self.invalidate(host, port)
                if attempt == 0 and was_cached:
                    continue  # re-handshake with a fresh id and replay once
                raise WorkerClientError(
                    f"worker {host}:{port} rejected MCP session id {session_id!r}"
                )
            if response is not None and self._is_stale_session_response(response):
                # Rejected at the MCP layer (engine's not-initialized gate).
                self.invalidate(host, port)
                last_response = response
                if attempt == 0 and was_cached:
                    continue
            return response
        return last_response  # pragma: no cover - loop always returns/raises first

    def ping(self, *, host: str, port: int, token: Optional[str] = None) -> bool:
        """A real ``ping`` round-trip; ``True`` iff the worker answers a result."""
        try:
            session_id = self._ensure_session(host, port, token)
            response, _ = self._http_call(
                host,
                port,
                {"jsonrpc": "2.0", "id": "ping", "method": "ping"},
                token,
                session_id,
            )
        except (WorkerClientError, _StaleSession, OSError):
            return False
        return isinstance(response, dict) and "result" in response

    def invalidate(self, host: str, port: int) -> None:
        """Forget a cached MCP session (e.g. after the worker was reaped)."""
        with self._lock:
            self._sessions.pop((host, port), None)

    # -- internals -----------------------------------------------------------

    def _ensure_session(self, host: str, port: int, token: Optional[str]) -> str:
        """Complete the MCP lifecycle with the worker once; cache its session id.

        A cached id is returned as-is; :meth:`forward` is responsible for detecting
        a stale one, :meth:`invalidate`-ing it, and calling back in to force a fresh
        handshake.
        """
        key = (host, port)
        with self._lock:
            cached = self._sessions.get(key)
        if cached is not None:
            return cached

        init_frame = {
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {
                "protocolVersion": self._protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "idamesh-supervisor", "version": "0.0.1"},
            },
        }
        response, assigned = self._http_call(host, port, init_frame, token, None)
        if assigned is None:
            raise WorkerClientError(
                f"worker {host}:{port} did not assign an Mcp-Session-Id at initialize"
            )
        if not isinstance(response, dict) or "result" not in response:
            raise WorkerClientError(
                f"worker {host}:{port} rejected initialize: {response!r}"
            )
        self._http_call(
            host,
            port,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            token,
            assigned,
        )
        with self._lock:
            self._sessions[key] = assigned
        return assigned

    def _http_call(
        self,
        host: str,
        port: int,
        frame: Mapping[str, Any],
        token: Optional[str],
        session_id: Optional[str],
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """POST one frame to the worker; return ``(parsed_response, assigned_sid)``.

        ``parsed_response`` is ``None`` for a ``202`` (notification ack). Raises
        :class:`_StaleSession` when a session-bearing call is rejected with HTTP
        ``404`` (stale id), and :class:`WorkerClientError` on any other
        connection/HTTP-status/decoding failure.
        """
        body = json.dumps(frame, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Origin": _ORIGIN,
            "MCP-Protocol-Version": self._protocol_version,
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        if token:
            headers["Authorization"] = f"Bearer {token}"

        status, data, assigned = self._post(host, port, body, headers)

        if status == 202 or not data:
            return None, assigned
        if status == 404 and session_id is not None and self._body_marks_stale(data):
            raise _StaleSession()
        if status != 200:
            raise WorkerClientError(
                f"worker {host}:{port} returned HTTP {status}: {data[:256]!r}"
            )
        try:
            parsed = json.loads(data)
        except (ValueError, TypeError) as exc:
            raise WorkerClientError(
                f"worker {host}:{port} returned non-JSON body: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise WorkerClientError(
                f"worker {host}:{port} returned a non-object response: {parsed!r}"
            )
        return parsed, assigned

    def _post(
        self,
        host: str,
        port: int,
        body: bytes,
        headers: Mapping[str, str],
    ) -> Tuple[int, bytes, Optional[str]]:
        """POST ``body`` to ``/mcp`` and return ``(status, data, assigned_sid)``.

        Retries a refused TCP connect (the worker is briefly unreachable during a
        spawn/bind race — nothing was transmitted, so a replay is safe). Any other
        socket error propagates immediately as a possibly-mid-flight failure.
        """
        last_exc: Optional[BaseException] = None
        for attempt in range(self._max_connect_retries + 1):
            conn = http.client.HTTPConnection(host, port, timeout=self._call_timeout)
            try:
                conn.request("POST", _ENDPOINT, body, dict(headers))
                resp = conn.getresponse()
                assigned = resp.getheader("Mcp-Session-Id")
                data = resp.read()
                return resp.status, data, assigned
            except ConnectionRefusedError as exc:
                last_exc = exc
                if attempt < self._max_connect_retries:
                    if self._retry_backoff:
                        time.sleep(self._retry_backoff * (attempt + 1))
                    continue
                raise WorkerUnavailableError(
                    f"worker {host}:{port} refused connection after "
                    f"{attempt + 1} attempt(s): {exc}"
                ) from exc
            except OSError as exc:
                raise WorkerClientError(
                    f"forward to {host}:{port} failed: {exc}"
                ) from exc
            finally:
                conn.close()
        # Unreachable: the loop returns, retries, or raises on the final attempt.
        raise WorkerUnavailableError(  # pragma: no cover
            f"worker {host}:{port} unreachable: {last_exc}"
        )

    @staticmethod
    def _is_stale_session_response(response: Any) -> bool:
        """Whether a parsed JSON-RPC ``response`` is the worker rejecting a stale
        session at the MCP layer (an ``INVALID_PARAMS`` not-initialized error)."""
        if not isinstance(response, dict):
            return False
        error = response.get("error")
        if not isinstance(error, dict) or error.get("code") != _JSONRPC_INVALID_PARAMS:
            return False
        message = str(error.get("message", "")).lower()
        return any(marker in message for marker in _STALE_SESSION_MARKERS)

    @staticmethod
    def _body_marks_stale(data: bytes) -> bool:
        """Whether a 404 body names a stale/unknown session (vs. a wrong path)."""
        try:
            text = data.decode("utf-8", "replace").lower()
        except Exception:  # noqa: BLE001 — defensive; treat as not-stale
            return False
        return any(marker in text for marker in _STALE_SESSION_MARKERS)
