"""Unit tests for the supervisor router and its worker HTTP client (idapro-free).

The supervisor is exercised against a *fake* worker pool and a *fake* worker HTTP
endpoint: ``http.client.HTTPConnection`` is monkeypatched with a stand-in bound to
an in-memory :class:`FakeWorkerHub`, so the router's *real* :class:`SupervisorRouter`
and the *real* :class:`WorkerClient` (handshake, session caching, stale-session
recovery, connect-retry) are driven end to end without spawning any process or
loading idalib.

Locked in here:

* ``initialize`` / ``ping`` / ``notifications/initialized`` answered locally;
* ``tools/list`` = the management tools **plus** every worker tool with an optional
  ``database`` routing key injected (management-named worker tools filtered,
  feature-gated tools hidden unless requested);
* management ``tools/call`` (``idb_open`` / ``idb_list`` / ``idb_merge``) handled
  locally against the pool;
* a worker ``tools/call`` forwarded to the owning session with ``database`` stripped
  from the arguments, sole-session default, and the missing/ambiguous/unknown
  session errors;
* the worker client's session reuse, stale-session re-handshake (both the MCP-layer
  not-initialized error and the transport 404), bearer passthrough, and
  connection-refused retry.
"""

from __future__ import annotations

import http.client
import itertools
import json
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest

from idamesh.infrastructure.rpc.worker_client import (
    WorkerClient,
    WorkerClientError,
    WorkerUnavailableError,
)
from idamesh.interface.mcp.engine import (
    SUPPORTED_PROTOCOL_VERSIONS,
    ErrorCode,
    McpError,
    ServerInfo,
)
from idamesh.interface.mcp.registry import Registry
from idamesh.interface.router.management import DATABASE_ARG, MANAGEMENT_TOOL_NAMES
from idamesh.interface.router.supervisor import SupervisorRouter

# --------------------------------------------------------------------------- #
# Fakes: worker sessions + pool (satisfy the SessionView / WorkerPoolPort ports)
# --------------------------------------------------------------------------- #


class FakeSession:
    """A routing record satisfying ``SessionView``."""

    def __init__(
        self,
        session_id: str,
        host: str,
        port: int,
        *,
        input_path: str = "/bin/target",
        token: Optional[str] = None,
    ) -> None:
        self.session_id = session_id
        self.host = host
        self.port = port
        self.token = token
        self.input_path = input_path
        self.private_copy_path = f"/scratch/{session_id}/target"
        self.touched = 0

    def touch(self) -> None:
        self.touched += 1

    def to_info(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "input_path": self.input_path,
            "filename": self.input_path.rsplit("/", 1)[-1],
            "private_copy_path": self.private_copy_path,
            "backend": "worker",
            "host": self.host,
            "port": self.port,
            "created_at": "2026-01-01T00:00:00+00:00",
            "last_accessed": "2026-01-01T00:00:00+00:00",
        }


class FakeWorkerPool:
    """A ``WorkerPoolPort`` stand-in with an in-memory, insertion-ordered map."""

    def __init__(self) -> None:
        self._sessions: Dict[str, FakeSession] = {}
        self.open_calls: List[Tuple[str, Optional[str]]] = []
        self.open_error: Optional[Exception] = None
        self._seq = itertools.count(1)
        self._port_seq = itertools.count(45001)

    def add(self, session: FakeSession) -> FakeSession:
        self._sessions[session.session_id] = session
        return session

    # -- WorkerPoolPort ---------------------------------------------------- #

    def open_session(
        self, input_path: str, *, preferred_session_id: Optional[str] = None
    ) -> FakeSession:
        self.open_calls.append((input_path, preferred_session_id))
        if self.open_error is not None:
            raise self.open_error
        if preferred_session_id and preferred_session_id in self._sessions:
            return self._sessions[preferred_session_id]
        session_id = f"sess-{next(self._seq)}"
        session = FakeSession(
            session_id, "127.0.0.1", next(self._port_seq), input_path=input_path
        )
        self._sessions[session_id] = session
        return session

    def list_sessions(self) -> List[FakeSession]:
        return list(self._sessions.values())

    def get(self, session_id: str) -> Optional[FakeSession]:
        return self._sessions.get(session_id)

    def close_session(self, session_id: str) -> bool:
        return self._sessions.pop(session_id, None) is not None

    def reap(self) -> List[str]:
        return []


# --------------------------------------------------------------------------- #
# Fakes: worker HTTP endpoint hub (monkeypatched over http.client.HTTPConnection)
# --------------------------------------------------------------------------- #


def _encode(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class _FakeResponse:
    def __init__(self, status: int, data: bytes, headers: Dict[str, str]) -> None:
        self.status = status
        self._data = data
        self._headers = headers

    def getheader(self, name: str, default: Any = None) -> Any:
        for key, value in self._headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def read(self) -> bytes:
        return self._data


class FakeEndpoint:
    """One fake worker's ``/mcp`` endpoint: MCP lifecycle + a canned tool result."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        expected_token: Optional[str] = None,
        require_session: bool = False,
        tool_result: Optional[Dict[str, Any]] = None,
        tool_error: Optional[Dict[str, Any]] = None,
        refuse_count: int = 0,
    ) -> None:
        self.host = host
        self.port = port
        self.expected_token = expected_token
        self.require_session = require_session
        self.tool_result = (
            tool_result if tool_result is not None else {"served_by": port}
        )
        self.tool_error = tool_error
        self.refuse_count = refuse_count
        self.known_sessions: set[str] = set()
        self._sid_seq = itertools.count(1)
        self.init_count = 0
        self.tool_calls: List[Dict[str, Any]] = []
        self.requests: List[Dict[str, Any]] = []

    def maybe_refuse(self) -> None:
        if self.refuse_count > 0:
            self.refuse_count -= 1
            raise ConnectionRefusedError(f"{self.host}:{self.port} refusing connect")

    def dispatch(
        self, path: str, body: bytes, headers: Dict[str, str]
    ) -> Tuple[int, bytes, Dict[str, str]]:
        if path != "/mcp":
            return 404, _encode({"error": "not found"}), {}
        if self.expected_token is not None:
            if headers.get("Authorization") != f"Bearer {self.expected_token}":
                return 401, _encode({"error": "unauthorized"}), {}
        frame = json.loads(body.decode("utf-8"))
        method = frame.get("method")
        rid = frame.get("id")
        session_id = headers.get("Mcp-Session-Id")
        self.requests.append({"method": method, "session_id": session_id})

        if method == "initialize":
            self.init_count += 1
            sid = f"mcp-{self.port}-{next(self._sid_seq)}"
            self.known_sessions.add(sid)
            result = {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "idamesh-worker", "version": "0.0.1"},
            }
            return (
                200,
                _encode({"jsonrpc": "2.0", "id": rid, "result": result}),
                {"Mcp-Session-Id": sid},
            )
        if method == "notifications/initialized":
            return 202, b"", {}
        if method == "ping":
            return 200, _encode({"jsonrpc": "2.0", "id": rid, "result": {}}), {}

        # Any operational method (tools/call, ...): enforce the session gate.
        if self.require_session and not session_id:
            return 400, _encode({"error": "missing session id"}), {}
        if session_id not in self.known_sessions:
            if self.require_session:
                return 404, _encode({"error": "unknown session"}), {}
            err = {
                "jsonrpc": "2.0",
                "id": rid,
                "error": {
                    "code": ErrorCode.INVALID_PARAMS,
                    "message": "Session not initialized: complete 'initialize' first",
                },
            }
            return 200, _encode(err), {}

        self.tool_calls.append(
            {"session_id": session_id, "frame": frame, "headers": dict(headers)}
        )
        if self.tool_error is not None:
            return (
                200,
                _encode({"jsonrpc": "2.0", "id": rid, "error": self.tool_error}),
                {},
            )
        return (
            200,
            _encode({"jsonrpc": "2.0", "id": rid, "result": self.tool_result}),
            {},
        )


class FakeWorkerHub:
    """Registry of fake endpoints + the ``HTTPConnection`` factory bound to them."""

    def __init__(self) -> None:
        self.endpoints: Dict[Tuple[str, int], FakeEndpoint] = {}

    def register(self, host: str, port: int, **kwargs: Any) -> FakeEndpoint:
        endpoint = FakeEndpoint(host, port, **kwargs)
        self.endpoints[(host, port)] = endpoint
        return endpoint

    def connection_factory(self):
        hub = self

        class _FakeHTTPConnection:
            def __init__(self, host: str, port: int, timeout: Any = None) -> None:
                self._host = host
                self._port = port
                self._pending: Optional[Tuple[str, bytes, Dict[str, str]]] = None

            def request(
                self,
                method: str,
                path: str,
                body: Any = None,
                headers: Optional[Dict[str, str]] = None,
            ) -> None:
                endpoint = hub.endpoints.get((self._host, self._port))
                if endpoint is None:
                    raise ConnectionRefusedError(f"no endpoint at {self._host}:{self._port}")
                endpoint.maybe_refuse()
                raw = body if isinstance(body, (bytes, bytearray)) else _encode(body)
                self._pending = (path, bytes(raw), dict(headers or {}))

            def getresponse(self) -> _FakeResponse:
                endpoint = hub.endpoints[(self._host, self._port)]
                assert self._pending is not None
                path, body, headers = self._pending
                status, data, resp_headers = endpoint.dispatch(path, body, headers)
                return _FakeResponse(status, data, resp_headers)

            def close(self) -> None:
                self._pending = None

        return _FakeHTTPConnection


# --------------------------------------------------------------------------- #
# A real, idapro-free worker registry with a handful of dummy tools
# --------------------------------------------------------------------------- #


def build_worker_registry() -> Registry:
    reg = Registry()

    @reg.tool
    def decompile(address: str) -> dict:
        """Decompile the function at an address."""
        return {}

    @reg.tool
    def list_funcs(offset: int = 0, count: int = 100) -> dict:
        """Page through functions."""
        return {}

    # A worker tool whose name collides with a management tool must be dropped
    # from the merged catalog (the supervisor answers idb_list itself).
    @reg.tool(name="idb_list")
    def worker_idb_list() -> dict:
        """Should never reach the merged tools/list."""
        return {}

    # Feature-gated: hidden unless the request advertises the feature.
    @reg.tool
    @reg.feature("experimental")
    def risky() -> dict:
        """A feature-gated worker tool."""
        return {}

    return reg


# --------------------------------------------------------------------------- #
# Fixtures + helpers
# --------------------------------------------------------------------------- #


@pytest.fixture
def pool() -> FakeWorkerPool:
    return FakeWorkerPool()


@pytest.fixture
def worker_registry() -> Registry:
    return build_worker_registry()


@pytest.fixture
def hub(monkeypatch) -> FakeWorkerHub:
    hub = FakeWorkerHub()
    monkeypatch.setattr(http.client, "HTTPConnection", hub.connection_factory())
    return hub


@pytest.fixture
def client() -> WorkerClient:
    # No back-off so the connect-retry tests do not actually sleep.
    return WorkerClient(retry_backoff=0.0)


@pytest.fixture
def router(pool, client, worker_registry) -> SupervisorRouter:
    return SupervisorRouter(
        pool=pool,
        client=client,
        worker_registry=worker_registry,
        server_info=ServerInfo(name="idamesh", version="9.9.9"),
    )


def _ready_ctx(
    router: SupervisorRouter, *, session_id: str = "http-1", features=frozenset()
) -> SimpleNamespace:
    """Drive the local lifecycle so operational methods pass the init gate."""
    ctx = SimpleNamespace(session_id=session_id, features=features)
    router.initialize({"protocolVersion": "2025-06-18"}, ctx)
    router.initialized(None, ctx)
    return ctx


def _call(router: SupervisorRouter, ctx, name: str, **arguments) -> dict:
    return router.tools_call({"name": name, "arguments": arguments}, ctx)


def _tools_by_name(result: dict) -> Dict[str, dict]:
    return {tool["name"]: tool for tool in result["tools"]}


# --------------------------------------------------------------------------- #
# initialize / ping / lifecycle gate (local)
# --------------------------------------------------------------------------- #


def test_initialize_keeps_supported_version_and_advertises_capabilities(router):
    ctx = SimpleNamespace(session_id="http-1", features=frozenset())
    result = router.initialize({"protocolVersion": "2025-06-18"}, ctx)
    assert result["protocolVersion"] == "2025-06-18"
    assert result["capabilities"]["tools"] == {"listChanged": False}
    assert "resources" in result["capabilities"]
    assert result["serverInfo"] == {"name": "idamesh", "version": "9.9.9"}


def test_initialize_falls_back_to_newest_for_unknown_version(router):
    ctx = SimpleNamespace(session_id="http-1", features=frozenset())
    result = router.initialize({"protocolVersion": "1999-01-01"}, ctx)
    assert result["protocolVersion"] == SUPPORTED_PROTOCOL_VERSIONS[0]


def test_ping_is_answered_locally(router):
    ctx = SimpleNamespace(session_id="http-1", features=frozenset())
    assert router.ping({}, ctx) == {}


def test_operational_methods_require_initialization(router):
    ctx = SimpleNamespace(session_id="never-initialized", features=frozenset())
    with pytest.raises(McpError) as excinfo:
        router.tools_list({}, ctx)
    assert excinfo.value.code == ErrorCode.INVALID_PARAMS


# --------------------------------------------------------------------------- #
# tools/list — merge + database injection
# --------------------------------------------------------------------------- #


def test_tools_list_merges_management_and_worker_tools(router):
    ctx = _ready_ctx(router)
    tools = _tools_by_name(router.tools_list({}, ctx))

    # Every management tool is present.
    assert MANAGEMENT_TOOL_NAMES <= set(tools)
    # Worker tools are present too...
    assert "decompile" in tools and "list_funcs" in tools
    # ...but a worker tool colliding with a management name is filtered out, so
    # the sole idb_list is the management one (object shape, no database key).
    assert DATABASE_ARG not in tools["idb_list"]["inputSchema"].get("properties", {})
    # A feature-gated tool stays hidden without the feature.
    assert "risky" not in tools


def test_tools_list_has_no_duplicate_names(router):
    ctx = _ready_ctx(router)
    names = [tool["name"] for tool in router.tools_list({}, ctx)["tools"]]
    assert len(names) == len(set(names))


def test_tools_list_injects_optional_database_into_worker_tools(router):
    ctx = _ready_ctx(router)
    tools = _tools_by_name(router.tools_list({}, ctx))

    decompile_schema = tools["decompile"]["inputSchema"]
    props = decompile_schema["properties"]
    assert props[DATABASE_ARG]["type"] == "string"
    # database is optional: the pre-existing required param survives, database is
    # not added to required.
    assert decompile_schema.get("required") == ["address"]
    assert DATABASE_ARG not in decompile_schema.get("required", [])

    # A worker tool with only-defaulted params gains database but requires nothing.
    list_funcs_schema = tools["list_funcs"]["inputSchema"]
    assert DATABASE_ARG in list_funcs_schema["properties"]
    assert DATABASE_ARG not in list_funcs_schema.get("required", [])


def test_management_tools_do_not_get_database_injected(router):
    ctx = _ready_ctx(router)
    tools = _tools_by_name(router.tools_list({}, ctx))
    for name in MANAGEMENT_TOOL_NAMES:
        props = tools[name]["inputSchema"].get("properties", {})
        assert DATABASE_ARG not in props


def test_tools_list_reveals_feature_gated_tool_when_requested(router):
    ctx = _ready_ctx(router, features=frozenset({"experimental"}))
    tools = _tools_by_name(router.tools_list({}, ctx))
    assert "risky" in tools
    assert DATABASE_ARG in tools["risky"]["inputSchema"]["properties"]


# --------------------------------------------------------------------------- #
# management tools/call — handled locally against the pool
# --------------------------------------------------------------------------- #


def test_idb_open_mints_fresh_session_locally(router, pool):
    ctx = _ready_ctx(router)
    result = _call(router, ctx, "idb_open", input_path="/bin/target")

    assert result["isError"] is False
    payload = result["structuredContent"]
    assert payload["input_path"] == "/bin/target"
    assert payload["shared"] is False
    assert payload["backend"] == "worker"
    # Routed to the pool with no preferred id (fresh private copy = N-copies).
    assert pool.open_calls == [("/bin/target", None)]


def test_idb_open_marks_shared_when_preferred_session_reused(router, pool):
    existing = pool.add(FakeSession("sess-keep", "127.0.0.1", 45000))
    ctx = _ready_ctx(router)
    result = _call(
        router, ctx, "idb_open", input_path="/bin/target",
        preferred_session_id="sess-keep",
    )
    payload = result["structuredContent"]
    assert payload["session_id"] == existing.session_id
    assert payload["shared"] is True


def test_idb_open_requires_input_path(router):
    ctx = _ready_ctx(router)
    result = _call(router, ctx, "idb_open")
    assert result["isError"] is True
    assert "input_path" in result["content"][0]["text"]


def test_idb_open_pool_failure_is_tool_error_not_protocol_error(router, pool):
    pool.open_error = RuntimeError("concurrency cap reached")
    ctx = _ready_ctx(router)
    result = _call(router, ctx, "idb_open", input_path="/bin/target")
    assert result["isError"] is True
    assert "concurrency cap reached" in result["content"][0]["text"]


def test_idb_list_enumerates_sessions_locally(router, pool):
    pool.add(FakeSession("sess-a", "127.0.0.1", 45001))
    pool.add(FakeSession("sess-b", "127.0.0.1", 45002))
    ctx = _ready_ctx(router)
    result = _call(router, ctx, "idb_list")

    payload = result["structuredContent"]
    assert payload["count"] == 2
    assert [s["session_id"] for s in payload["sessions"]] == ["sess-a", "sess-b"]


def test_idb_merge_with_no_sessions_is_a_structured_error(router):
    # idb_merge is now wired to the merge orchestrator; with no open copies of the
    # named binary it refuses with a structured error (isError + a report body).
    ctx = _ready_ctx(router)
    result = _call(router, ctx, "idb_merge", path="/bin/target", into="sess-x")
    assert result["isError"] is True
    assert "session" in result["content"][0]["text"].lower()


def test_idb_close_releases_session_locally(router, pool):
    pool.add(FakeSession("sess-a", "127.0.0.1", 45001))
    pool.add(FakeSession("sess-b", "127.0.0.1", 45002))
    ctx = _ready_ctx(router)

    result = _call(router, ctx, "idb_close", session_id="sess-a")

    assert result["isError"] is False
    payload = result["structuredContent"]
    assert payload == {"session_id": "sess-a", "closed": True}
    # Only the addressed session was dropped from the pool.
    assert {s.session_id for s in pool.list_sessions()} == {"sess-b"}


def test_idb_close_unknown_session_reports_not_closed(router, pool):
    ctx = _ready_ctx(router)
    result = _call(router, ctx, "idb_close", session_id="ghost")
    assert result["isError"] is False
    assert result["structuredContent"] == {"session_id": "ghost", "closed": False}


def test_idb_close_requires_session_id(router):
    ctx = _ready_ctx(router)
    result = _call(router, ctx, "idb_close")
    assert result["isError"] is True
    assert "session_id" in result["content"][0]["text"]


def test_idb_close_is_advertised_in_tools_list(router):
    ctx = _ready_ctx(router)
    tools = _tools_by_name(router.tools_list({}, ctx))
    assert "idb_close" in tools
    schema = tools["idb_close"]["inputSchema"]
    assert schema["required"] == ["session_id"]
    # A management tool never gains the injected database routing key.
    assert DATABASE_ARG not in schema.get("properties", {})
    # It is a mutating tool, not read-only.
    assert tools["idb_close"]["annotations"]["readOnlyHint"] is False


# --------------------------------------------------------------------------- #
# worker tools/call — forwarded to the owning session
# --------------------------------------------------------------------------- #


def test_worker_call_forwarded_to_named_session_with_database_stripped(
    router, pool, hub
):
    pool.add(FakeSession("sess-a", "127.0.0.1", 45001))
    pool.add(FakeSession("sess-b", "127.0.0.1", 45002))
    endpoint_a = hub.register("127.0.0.1", 45001)
    endpoint_b = hub.register("127.0.0.1", 45002)
    ctx = _ready_ctx(router)

    result = _call(
        router, ctx, "decompile", address="0x401000", database="sess-b"
    )

    # Relayed the worker's own result verbatim (not a management envelope).
    assert result == {"served_by": 45002}
    # Only the addressed session saw the call...
    assert endpoint_a.tool_calls == []
    assert len(endpoint_b.tool_calls) == 1
    recorded = endpoint_b.tool_calls[0]["frame"]
    assert recorded["method"] == "tools/call"
    assert recorded["params"]["name"] == "decompile"
    # ...and the routing key was stripped before forwarding.
    assert recorded["params"]["arguments"] == {"address": "0x401000"}


def test_worker_call_touches_the_routed_session(router, pool, hub):
    session = pool.add(FakeSession("sess-a", "127.0.0.1", 45001))
    hub.register("127.0.0.1", 45001)
    ctx = _ready_ctx(router)
    _call(router, ctx, "decompile", address="0x401000", database="sess-a")
    assert session.touched >= 1


def test_sole_session_is_the_default_when_database_omitted(router, pool, hub):
    pool.add(FakeSession("sess-only", "127.0.0.1", 45001))
    endpoint = hub.register("127.0.0.1", 45001)
    ctx = _ready_ctx(router)

    result = _call(router, ctx, "decompile", address="0x401000")

    assert result == {"served_by": 45001}
    assert len(endpoint.tool_calls) == 1
    assert endpoint.tool_calls[0]["frame"]["params"]["arguments"] == {
        "address": "0x401000"
    }


def test_no_open_session_is_a_clear_error(router, pool):
    ctx = _ready_ctx(router)
    with pytest.raises(McpError) as excinfo:
        _call(router, ctx, "decompile", address="0x401000")
    assert excinfo.value.code == ErrorCode.INVALID_PARAMS
    assert "no database is open" in excinfo.value.message


def test_ambiguous_session_requires_explicit_database(router, pool):
    pool.add(FakeSession("sess-a", "127.0.0.1", 45001))
    pool.add(FakeSession("sess-b", "127.0.0.1", 45002))
    ctx = _ready_ctx(router)
    with pytest.raises(McpError) as excinfo:
        _call(router, ctx, "decompile", address="0x401000")
    assert excinfo.value.code == ErrorCode.INVALID_PARAMS
    assert "multiple databases" in excinfo.value.message


def test_unknown_database_is_rejected(router, pool):
    pool.add(FakeSession("sess-a", "127.0.0.1", 45001))
    ctx = _ready_ctx(router)
    with pytest.raises(McpError) as excinfo:
        _call(router, ctx, "decompile", address="0x401000", database="ghost")
    assert excinfo.value.code == ErrorCode.INVALID_PARAMS
    assert "ghost" in excinfo.value.message


def test_non_string_database_is_a_protocol_error(router, pool):
    pool.add(FakeSession("sess-a", "127.0.0.1", 45001))
    ctx = _ready_ctx(router)
    with pytest.raises(McpError) as excinfo:
        router.tools_call(
            {"name": "decompile", "arguments": {"address": "0x1", "database": 123}},
            ctx,
        )
    assert excinfo.value.code == ErrorCode.INVALID_PARAMS


def test_worker_error_response_is_surfaced_as_protocol_error(router, pool, hub):
    pool.add(FakeSession("sess-a", "127.0.0.1", 45001))
    hub.register(
        "127.0.0.1", 45001, tool_error={"code": -32000, "message": "boom"}
    )
    ctx = _ready_ctx(router)
    with pytest.raises(McpError) as excinfo:
        _call(router, ctx, "decompile", address="0x401000", database="sess-a")
    assert excinfo.value.code == -32000
    assert excinfo.value.message == "boom"


def test_bearer_token_is_forwarded_to_the_worker(router, pool, hub):
    pool.add(
        FakeSession("sess-a", "127.0.0.1", 45001, token="s3cr3t")
    )
    endpoint = hub.register("127.0.0.1", 45001, expected_token="s3cr3t")
    ctx = _ready_ctx(router)

    result = _call(router, ctx, "decompile", address="0x401000", database="sess-a")

    assert result == {"served_by": 45001}
    assert endpoint.tool_calls[0]["headers"]["Authorization"] == "Bearer s3cr3t"


def test_missing_bearer_token_forward_fails_as_internal_error(router, pool, hub):
    # Session carries no token but the worker requires one -> handshake 401.
    pool.add(FakeSession("sess-a", "127.0.0.1", 45001))
    hub.register("127.0.0.1", 45001, expected_token="s3cr3t")
    ctx = _ready_ctx(router)
    with pytest.raises(McpError) as excinfo:
        _call(router, ctx, "decompile", address="0x401000", database="sess-a")
    assert excinfo.value.code == ErrorCode.INTERNAL


# --------------------------------------------------------------------------- #
# resources — not routable without a session
# --------------------------------------------------------------------------- #


def test_resources_list_is_empty_locally(router):
    ctx = _ready_ctx(router)
    assert router.resources_list({}, ctx) == {"resources": []}
    assert router.resources_templates_list({}, ctx) == {"resourceTemplates": []}


def test_resource_read_is_not_routable(router):
    ctx = _ready_ctx(router)
    with pytest.raises(McpError) as excinfo:
        router.resources_read({"uri": "ida://metadata"}, ctx)
    assert excinfo.value.code == ErrorCode.INVALID_PARAMS


# --------------------------------------------------------------------------- #
# WorkerClient hardening — session reuse, stale recovery, connect retry
# --------------------------------------------------------------------------- #


def _forward_frame(name: str = "decompile") -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": {}},
    }


def test_client_handshakes_once_then_reuses_session(client, hub):
    endpoint = hub.register("127.0.0.1", 45001)
    for _ in range(3):
        response = client.forward(host="127.0.0.1", port=45001, frame=_forward_frame())
        assert response["result"] == {"served_by": 45001}
    assert endpoint.init_count == 1
    assert len(endpoint.tool_calls) == 3


def test_client_rehandshakes_on_stale_mcp_session(client, hub):
    endpoint = hub.register("127.0.0.1", 45001)
    first = client.forward(host="127.0.0.1", port=45001, frame=_forward_frame())
    assert first["result"] == {"served_by": 45001}
    assert endpoint.init_count == 1

    # The worker forgets every session (as if it restarted on the same port).
    endpoint.known_sessions.clear()

    second = client.forward(host="127.0.0.1", port=45001, frame=_forward_frame())
    # Recovered: re-handshaked exactly once and replayed the frame successfully.
    assert second["result"] == {"served_by": 45001}
    assert endpoint.init_count == 2


def test_client_rehandshakes_on_transport_404(client, hub):
    endpoint = hub.register("127.0.0.1", 45001, require_session=True)
    first = client.forward(host="127.0.0.1", port=45001, frame=_forward_frame())
    assert first["result"] == {"served_by": 45001}
    assert endpoint.init_count == 1

    endpoint.known_sessions.clear()  # now a stale id yields HTTP 404
    second = client.forward(host="127.0.0.1", port=45001, frame=_forward_frame())
    assert second["result"] == {"served_by": 45001}
    assert endpoint.init_count == 2


def test_client_does_not_rehandshake_on_ordinary_invalid_params(client, hub):
    # A genuine bad-argument error shares the INVALID_PARAMS code but is not a
    # stale-session marker; it must be relayed, not retried.
    endpoint = hub.register(
        "127.0.0.1",
        45001,
        tool_error={
            "code": ErrorCode.INVALID_PARAMS,
            "message": "invalid argument 'address'",
        },
    )
    client.forward(host="127.0.0.1", port=45001, frame=_forward_frame())
    response = client.forward(host="127.0.0.1", port=45001, frame=_forward_frame())
    assert response["error"]["message"] == "invalid argument 'address'"
    assert endpoint.init_count == 1  # never re-handshaked


def test_client_retries_a_refused_connection(client, hub):
    endpoint = hub.register("127.0.0.1", 45001, refuse_count=2)
    response = client.forward(host="127.0.0.1", port=45001, frame=_forward_frame())
    assert response["result"] == {"served_by": 45001}
    assert endpoint.refuse_count == 0  # both refusals consumed by retries


def test_client_gives_up_after_exhausting_connect_retries(hub):
    client = WorkerClient(retry_backoff=0.0, max_connect_retries=2)
    hub.register("127.0.0.1", 45001, refuse_count=99)
    with pytest.raises(WorkerUnavailableError):
        client.forward(host="127.0.0.1", port=45001, frame=_forward_frame())


def test_client_ping_round_trips(client, hub):
    hub.register("127.0.0.1", 45001)
    assert client.ping(host="127.0.0.1", port=45001) is True


def test_client_ping_false_when_unreachable(hub):
    client = WorkerClient(retry_backoff=0.0, max_connect_retries=0)
    # No endpoint registered at this port -> connection refused.
    assert client.ping(host="127.0.0.1", port=45099) is False


def test_hard_http_error_from_handshake_raises_worker_client_error(client, hub):
    hub.register("127.0.0.1", 45001, expected_token="need-token")
    with pytest.raises(WorkerClientError):
        # No token supplied -> the initialize POST gets a 401.
        client.forward(host="127.0.0.1", port=45001, frame=_forward_frame())
