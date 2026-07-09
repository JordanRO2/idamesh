"""Shared fixtures for the transport/RPC unit tests.

The transports are exercised against an **in-process fake dispatcher** (never the
real MCP engine), so these tests cover only the byte-moving and framing concerns
the transport layer owns.
"""

from __future__ import annotations

import http.client
import json
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from idamesh.infrastructure.transport.http import HttpTransport


class FakeDispatcher:
    """A minimal :class:`Dispatcher` stand-in.

    It returns a canned JSON-RPC *result* for any id-bearing request and ``None``
    (the "no body" signal) for a notification, mirroring the real ``Router``'s
    return contract without any MCP semantics. Every call is recorded so tests
    can assert what the transport forwarded.
    """

    def __init__(self, *, result: Optional[Dict[str, Any]] = None) -> None:
        self.result: Dict[str, Any] = result if result is not None else {"ok": True}
        self.calls: List[SimpleNamespace] = []

    def dispatch(
        self,
        raw: Any,
        *,
        session_id: Optional[str] = None,
        protocol_version: Optional[str] = None,
        features: frozenset = frozenset(),
        deadline: Optional[float] = None,
    ) -> Optional[bytes]:
        self.calls.append(
            SimpleNamespace(
                raw=raw,
                session_id=session_id,
                protocol_version=protocol_version,
                features=features,
                deadline=deadline,
            )
        )
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError):
            obj = None
        if isinstance(obj, dict) and "id" not in obj:
            return None  # notification -> no response body
        rid = obj.get("id") if isinstance(obj, dict) else None
        return json.dumps(
            {"jsonrpc": "2.0", "id": rid, "result": self.result}
        ).encode("utf-8")


@pytest.fixture
def fake_dispatcher() -> FakeDispatcher:
    return FakeDispatcher()


@pytest.fixture
def http_server():
    """Factory that starts an ephemeral-port :class:`HttpTransport` and reaps it."""
    started: List[HttpTransport] = []

    def _start(dispatcher: Any, **kwargs: Any) -> HttpTransport:
        transport = HttpTransport(dispatcher, port=0, **kwargs)
        transport.serve(block=False)
        started.append(transport)
        return transport

    yield _start

    for transport in started:
        transport.stop()


def http_request(
    port: int,
    method: str,
    *,
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    path: str = "/mcp",
):
    """Issue one HTTP request to the loopback server; return (status, headers, body)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        payload = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, payload
    finally:
        conn.close()
