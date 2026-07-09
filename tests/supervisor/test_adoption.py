"""The supervisor adopting a discovered GUI instance (idapro-free).

Drives the *real* :class:`SupervisorRouter` wired with a fake worker pool, a fake
worker client, and a *real* ``GuiDiscoveryReader`` over a temp registry that holds a
single ``backend="gui"`` record. Locks in that an adopted GUI is surfaced by
``idb_list`` alongside owned workers, is routable by its session id (with its bearer
token forwarded), participates in the sole-session default, and — with no discovery
wired — the supervisor behaves exactly as before.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from idamesh.infrastructure.discovery import (
    BACKEND_GUI,
    DiscoveryEntry,
    DiscoveryRegistry,
    GuiDiscoveryReader,
)
from idamesh.interface.mcp.engine import ServerInfo
from idamesh.interface.mcp.registry import Registry
from idamesh.interface.router.supervisor import SupervisorRouter
from tests.supervisor.test_router import (  # reuse the router test's fakes
    FakeSession,
    FakeWorkerPool,
    _ready_ctx,
    build_worker_registry,
)


class RecordingClient:
    """A ``WorkerClientPort`` stand-in that records forwards and returns a canned result."""

    def __init__(self) -> None:
        self.forwards: List[Dict[str, Any]] = []

    def forward(self, *, host, port, frame, token=None):
        self.forwards.append(
            {"host": host, "port": port, "frame": frame, "token": token}
        )
        rid = frame.get("id")
        return {"jsonrpc": "2.0", "id": rid, "result": {"served_by": port}}

    def ping(self, *, host, port, token=None):
        return True


@pytest.fixture
def registry(tmp_path) -> DiscoveryRegistry:
    return DiscoveryRegistry(tmp_path / "instances", alive_check=lambda pid: True)


def _write_gui(registry: DiscoveryRegistry, session_id="gui-target-abc", *, port=13337):
    registry.write(
        DiscoveryEntry(
            session_id=session_id,
            backend=BACKEND_GUI,
            host="127.0.0.1",
            port=port,
            token="gui-token",
            pid=1234,
            binary="target.exe",
            idb_path="C:/bins/target.exe",
        )
    )


def _router(pool, client, discovery=None) -> SupervisorRouter:
    return SupervisorRouter(
        pool=pool,
        client=client,
        worker_registry=build_worker_registry(),
        server_info=ServerInfo(name="idamesh", version="9.9.9"),
        discovery=discovery,
    )


def test_idb_list_surfaces_adopted_gui(registry):
    _write_gui(registry)
    pool = FakeWorkerPool()
    router = _router(pool, RecordingClient(), GuiDiscoveryReader(registry))
    ctx = _ready_ctx(router)

    result = router.tools_call({"name": "idb_list", "arguments": {}}, ctx)
    payload = result["structuredContent"]

    assert payload["count"] == 1
    session = payload["sessions"][0]
    assert session["session_id"] == "gui-target-abc"
    assert session["backend"] == "gui"
    assert session["host"] == "127.0.0.1"
    assert session["port"] == 13337


def test_idb_list_merges_owned_and_adopted(registry):
    _write_gui(registry, "gui-x", port=20000)
    pool = FakeWorkerPool()
    pool.add(FakeSession("sess-worker", "127.0.0.1", 45001))
    router = _router(pool, RecordingClient(), GuiDiscoveryReader(registry))
    ctx = _ready_ctx(router)

    payload = router.tools_call({"name": "idb_list", "arguments": {}}, ctx)[
        "structuredContent"
    ]
    ids = {s["session_id"] for s in payload["sessions"]}
    assert ids == {"sess-worker", "gui-x"}
    assert payload["count"] == 2


def test_call_routed_to_adopted_gui_forwards_token(registry):
    _write_gui(registry, "gui-target-abc", port=13337)
    pool = FakeWorkerPool()
    client = RecordingClient()
    router = _router(pool, client, GuiDiscoveryReader(registry))
    ctx = _ready_ctx(router)

    result = router.tools_call(
        {
            "name": "decompile",
            "arguments": {"address": "0x401000", "database": "gui-target-abc"},
        },
        ctx,
    )

    # Relayed the GUI worker's result and forwarded to the discovered endpoint.
    assert result == {"served_by": 13337}
    assert len(client.forwards) == 1
    fwd = client.forwards[0]
    assert (fwd["host"], fwd["port"], fwd["token"]) == ("127.0.0.1", 13337, "gui-token")
    # The routing key was stripped before forwarding.
    assert fwd["frame"]["params"]["arguments"] == {"address": "0x401000"}


def test_sole_adopted_gui_is_the_default_when_database_omitted(registry):
    _write_gui(registry, "gui-only", port=13337)
    pool = FakeWorkerPool()  # no owned workers
    client = RecordingClient()
    router = _router(pool, client, GuiDiscoveryReader(registry))
    ctx = _ready_ctx(router)

    result = router.tools_call(
        {"name": "decompile", "arguments": {"address": "0x401000"}}, ctx
    )
    assert result == {"served_by": 13337}
    assert client.forwards[0]["port"] == 13337


def test_ambiguous_when_worker_and_gui_both_present(registry):
    _write_gui(registry, "gui-x", port=13337)
    pool = FakeWorkerPool()
    pool.add(FakeSession("sess-worker", "127.0.0.1", 45001))
    router = _router(pool, RecordingClient(), GuiDiscoveryReader(registry))
    ctx = _ready_ctx(router)

    from idamesh.interface.mcp.engine import ErrorCode, McpError

    with pytest.raises(McpError) as excinfo:
        router.tools_call({"name": "decompile", "arguments": {"address": "0x1"}}, ctx)
    assert excinfo.value.code == ErrorCode.INVALID_PARAMS
    assert "multiple databases" in excinfo.value.message


def test_no_discovery_wired_behaves_as_before(registry):
    # A registry with a live GUI exists, but the router was built with discovery=None:
    # the GUI must be invisible (backwards-compatible default).
    _write_gui(registry, "gui-x")
    pool = FakeWorkerPool()
    router = _router(pool, RecordingClient(), discovery=None)
    ctx = _ready_ctx(router)

    payload = router.tools_call({"name": "idb_list", "arguments": {}}, ctx)[
        "structuredContent"
    ]
    assert payload["count"] == 0


def test_unknown_session_still_errors_with_discovery(registry):
    _write_gui(registry, "gui-x")
    pool = FakeWorkerPool()
    router = _router(pool, RecordingClient(), GuiDiscoveryReader(registry))
    ctx = _ready_ctx(router)

    from idamesh.interface.mcp.engine import ErrorCode, McpError

    with pytest.raises(McpError) as excinfo:
        router.tools_call(
            {"name": "decompile", "arguments": {"address": "0x1", "database": "ghost"}},
            ctx,
        )
    assert excinfo.value.code == ErrorCode.INVALID_PARAMS
    assert "ghost" in excinfo.value.message
