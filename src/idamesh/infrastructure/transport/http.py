"""Streamable-HTTP transport (single ``/mcp`` endpoint).

Implements the MCP Streamable HTTP transport: ``POST`` carries one request or
notification (JSON reply for requests, ``202 Accepted`` for notifications/
responses); ``GET`` returns ``405`` (no server-initiated SSE in v1); ``DELETE``
tears down a session. Enforces the DNS-rebinding controls the spec mandates —
mandatory ``Origin`` validation and loopback binding — plus an optional bearer
token, the ``MCP-Session-Id`` lifecycle, and the ``MCP-Protocol-Version`` header.
"""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Optional,
    Set,
    Union,
)
from urllib.parse import parse_qs, urlsplit

from idamesh.infrastructure.transport.base import Dispatcher, Transport

#: Loopback-only default bind, per the spec's DNS-rebinding guidance.
DEFAULT_HOST: str = "127.0.0.1"
DEFAULT_PORT: int = 13337
#: 10 MiB request-body ceiling.
DEFAULT_MAX_BODY_BYTES: int = 10 * 1024 * 1024
#: Assumed protocol version when the client sends no ``MCP-Protocol-Version``
#: header and it is otherwise unknowable (Streamable-HTTP spec §5.5).
DEFAULT_PROTOCOL_VERSION: str = "2025-03-26"

#: Origin allow-list: a predicate, an explicit list, or ``"*"``.
OriginPolicy = Union[Callable[[str], bool], Iterable[str], str]

#: The single MCP endpoint path.
_ENDPOINT = "/mcp"
#: Hosts treated as loopback by the default Origin policy.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
#: Highest number of consecutive ports to probe when the requested one is busy.
_PORT_SCAN_SPAN = 64


def _json_body(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def _peek_method(body: bytes) -> Optional[str]:
    """Best-effort read of a single frame's ``method`` for session lifecycle.

    The transport never interprets MCP semantics beyond this: it only needs to
    know whether a POST is an ``initialize`` (to mint a session).
    """
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        return None
    if isinstance(obj, dict):
        method = obj.get("method")
        return method if isinstance(method, str) else None
    return None


class _McpHTTPServer(ThreadingHTTPServer):
    """A threading HTTP server carrying a back-reference to its transport."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, transport: "HttpTransport") -> None:
        self.transport = transport
        super().__init__(address, handler)


class _McpRequestHandler(BaseHTTPRequestHandler):
    """Maps the MCP Streamable-HTTP verbs onto the injected dispatcher."""

    # Close the connection after each response: simplest robust framing.
    protocol_version = "HTTP/1.0"

    # -- verb handlers -----------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler contract
        transport = self.server.transport  # type: ignore[attr-defined]
        parsed = urlsplit(self.path)
        if parsed.path != _ENDPOINT:
            return self._send(404, _json_body({"error": "not found"}))
        if not self._guard(transport):
            return None

        length = self._content_length()
        if length > transport._max_body_bytes:
            return self._send(413, _json_body({"error": "payload too large"}))
        body = self.rfile.read(length) if length > 0 else b""
        if len(body) > transport._max_body_bytes:
            return self._send(413, _json_body({"error": "payload too large"}))

        method = _peek_method(body)
        session_id = self.headers.get("Mcp-Session-Id")
        assigned: Optional[str] = None
        if method == "initialize":
            assigned = transport._new_session()
            session_id = assigned
        elif transport._require_session:
            if not session_id:
                return self._send(400, _json_body({"error": "missing session id"}))
            if not transport._known_session(session_id):
                return self._send(404, _json_body({"error": "unknown session"}))

        # Protocol-version header (Streamable-HTTP spec §5.5): a present-but-
        # unsupported value is a 400; an absent one falls back to the assumed
        # default so a header-less client (curl, our own SDK) still works.
        raw_version = self.headers.get("MCP-Protocol-Version")
        if raw_version is None:
            protocol_version: Optional[str] = transport._default_protocol_version
        elif transport._is_supported_version(raw_version):
            protocol_version = raw_version
        else:
            return self._send(
                400,
                _json_body(
                    {
                        "error": "unsupported protocol version",
                        "supported": transport._supported_versions_list(),
                        "requested": raw_version,
                    }
                ),
            )

        features = frozenset(
            item
            for value in parse_qs(parsed.query).get("features", [])
            for item in value.split(",")
            if item
        )

        reply = transport._dispatcher.dispatch(
            body,
            session_id=session_id,
            protocol_version=protocol_version,
            features=features,
        )

        extra: Dict[str, str] = {}
        if assigned is not None:
            extra["Mcp-Session-Id"] = assigned
        if reply is None:
            # Purely notification(s)/response(s): acknowledge with no body.
            return self._send(202, b"", extra_headers=extra)
        return self._send(200, reply, extra_headers=extra)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path != _ENDPOINT:
            return self._send(404, _json_body({"error": "not found"}))
        # No server-initiated SSE stream in v1.
        return self._send(
            405,
            _json_body({"error": "method not allowed"}),
            extra_headers={"Allow": "POST, DELETE, OPTIONS"},
        )

    def do_DELETE(self) -> None:  # noqa: N802
        transport = self.server.transport  # type: ignore[attr-defined]
        parsed = urlsplit(self.path)
        if parsed.path != _ENDPOINT:
            return self._send(404, _json_body({"error": "not found"}))
        if not self._guard(transport):
            return None
        session_id = self.headers.get("Mcp-Session-Id")
        if session_id and transport._known_session(session_id):
            transport._drop_session(session_id)
            return self._send(200, b"")
        return self._send(404, _json_body({"error": "unknown session"}))

    def do_OPTIONS(self) -> None:  # noqa: N802
        transport = self.server.transport  # type: ignore[attr-defined]
        origin = self.headers.get("Origin")
        headers = {"Allow": "POST, GET, DELETE, OPTIONS"}
        if origin is not None and transport._origin_allowed(origin):
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Methods"] = "POST, GET, DELETE, OPTIONS"
            headers["Access-Control-Allow-Headers"] = (
                "Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version"
            )
        return self._send(204, b"", extra_headers=headers)

    # -- helpers -----------------------------------------------------------

    def _guard(self, transport: "HttpTransport") -> bool:
        """Enforce Origin validation and optional bearer auth; reply on failure."""
        origin = self.headers.get("Origin")
        if origin is not None and not transport._origin_allowed(origin):
            self._send(403, _json_body({"error": "origin not allowed"}))
            return False
        if transport._bearer_token is not None:
            expected = f"Bearer {transport._bearer_token}"
            if self.headers.get("Authorization", "") != expected:
                self._send(401, _json_body({"error": "unauthorized"}))
                return False
        return True

    def _content_length(self) -> int:
        try:
            return max(0, int(self.headers.get("Content-Length", 0)))
        except (TypeError, ValueError):
            return 0

    def _send(
        self,
        status: int,
        body: bytes = b"",
        *,
        content_type: str = "application/json",
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.send_response(status)
        if body:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *_args: Any) -> None:  # noqa: D401 — silence stderr noise
        """Suppress the default per-request stderr logging."""
        return None


class HttpTransport(Transport):
    """A threaded streamable-HTTP server bound to loopback by default."""

    def __init__(
        self,
        dispatcher: Dispatcher,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        bearer_token: Optional[str] = None,
        allowed_origins: Optional[OriginPolicy] = None,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        require_session: bool = False,
        supported_protocol_versions: Optional[Iterable[str]] = None,
        default_protocol_version: str = DEFAULT_PROTOCOL_VERSION,
    ) -> None:
        super().__init__(dispatcher)
        self._host = host
        self._port = port
        self._bearer_token = bearer_token
        self._allowed_origins = allowed_origins
        self._max_body_bytes = max_body_bytes
        self._require_session = require_session
        # The composition root passes the engine's SUPPORTED_PROTOCOL_VERSIONS
        # here (as plain strings, so no interface->infrastructure import). When
        # ``None`` the header is accepted unvalidated (only the absent->default
        # fallback applies), preserving the pre-validation behavior.
        self._supported_versions: Optional[Set[str]] = (
            set(supported_protocol_versions)
            if supported_protocol_versions is not None
            else None
        )
        self._default_protocol_version = default_protocol_version
        self._httpd: Optional[_McpHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._sessions: Set[str] = set()
        self._sessions_lock = threading.Lock()

    def _is_supported_version(self, version: str) -> bool:
        """Whether ``version`` is negotiable (always true when unconfigured)."""
        if self._supported_versions is None:
            return True
        return version in self._supported_versions

    def _supported_versions_list(self) -> list:
        """Sorted supported versions for a 400 error body (``[]`` if unconfigured)."""
        if self._supported_versions is None:
            return []
        return sorted(self._supported_versions)

    def serve(self, *, block: bool = True) -> None:
        """Bind and serve (scanning upward from ``port`` for a free port)."""
        if self._httpd is None:
            self._httpd = self._bind()
        if block:
            self._httpd.serve_forever()
        else:
            self._thread = threading.Thread(
                target=self._httpd.serve_forever, daemon=True
            )
            self._thread.start()

    def stop(self) -> None:
        """Shut down the HTTP server and release the socket."""
        httpd, self._httpd = self._httpd, None
        thread, self._thread = self._thread, None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if thread is not None:
            thread.join(timeout=5)

    @property
    def bound_port(self) -> int:
        """The port actually bound (may differ from the requested ``port``)."""
        if self._httpd is None:
            raise RuntimeError("server is not bound; call serve() first")
        return self._httpd.server_address[1]

    # -- session lifecycle -------------------------------------------------

    def _new_session(self) -> str:
        # Cryptographically secure, visible-ASCII per the Streamable-HTTP spec.
        session_id = secrets.token_hex(16)
        with self._sessions_lock:
            self._sessions.add(session_id)
        return session_id

    def _known_session(self, session_id: str) -> bool:
        with self._sessions_lock:
            return session_id in self._sessions

    def _drop_session(self, session_id: str) -> None:
        with self._sessions_lock:
            self._sessions.discard(session_id)

    # -- policy ------------------------------------------------------------

    def _origin_allowed(self, origin: str) -> bool:
        policy = self._allowed_origins
        if policy is None:
            return _is_loopback_origin(origin)
        if policy == "*":
            return True
        if callable(policy):
            return bool(policy(origin))
        return origin in set(policy)

    # -- internals ---------------------------------------------------------

    def _bind(self) -> _McpHTTPServer:
        if self._port == 0:
            return _McpHTTPServer((self._host, 0), _McpRequestHandler, self)
        last_error: Optional[OSError] = None
        for candidate in range(self._port, self._port + _PORT_SCAN_SPAN):
            try:
                return _McpHTTPServer(
                    (self._host, candidate), _McpRequestHandler, self
                )
            except OSError as exc:
                last_error = exc
        raise last_error if last_error is not None else OSError("no free port")


def _is_loopback_origin(origin: str) -> bool:
    try:
        host = urlsplit(origin).hostname
    except ValueError:
        return False
    return host in _LOOPBACK_HOSTS
