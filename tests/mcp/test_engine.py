"""Unit tests driving the MCP engine with fake in-memory tools (no IDA)."""

from __future__ import annotations

import base64
import json
from typing import Annotated

import pytest

from idamesh.application.policies.limits import Limits
from idamesh.interface.mcp.engine import (
    SUPPORTED_PROTOCOL_VERSIONS,
    ErrorCode,
    McpEngine,
    McpError,
    ServerInfo,
    ToolError,
)
from idamesh.interface.mcp.overflow import OVERFLOW_URI_PREFIX
from idamesh.interface.mcp.registry import Registry
from idamesh.interface.mcp.specs import RequestView
from tests.mcp.support import FakeCancel, FakeCtx


def mark_ready(engine, ctx=None):
    """Drive the lifecycle handshake so the (default test) session is past the
    init gate; returns the engine for chaining."""
    engine.initialized(None, ctx if ctx is not None else FakeCtx())
    return engine


def build_engine(*, initialized: bool = True, **kwargs):
    reg = Registry()

    @reg.tool
    def echo(text: Annotated[str, "text to echo back"]) -> dict:
        """Echo the given text back to the caller."""
        return {"echo": text}

    @reg.tool
    def add(a: int, b: int = 0) -> int:
        """Add two integers."""
        return a + b

    @reg.tool
    def boom() -> dict:
        """Always raises a tool-execution error."""
        raise ToolError("kaboom")

    @reg.tool
    @reg.feature("debug")
    def secret() -> dict:
        """Hidden behind the optional 'debug' feature group."""
        return {"secret": True}

    engine = McpEngine(
        reg,
        server_info=ServerInfo(name="idamesh", version="9.9.9"),
        **kwargs,
    )
    if initialized:
        # Happy-path tests operate a session that has completed the MCP
        # lifecycle handshake for the default FakeCtx session.
        engine.initialize({"protocolVersion": "2025-11-25"}, FakeCtx())
        mark_ready(engine)
    return engine, reg


# -- lifecycle --------------------------------------------------------------- #


def test_initialize_keeps_supported_client_version():
    engine, _ = build_engine()
    res = engine.initialize(
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "c", "version": "1"},
        },
        FakeCtx(),
    )
    assert res["protocolVersion"] == "2025-06-18"
    assert res["serverInfo"] == {"name": "idamesh", "version": "9.9.9"}
    assert res["capabilities"]["tools"] == {"listChanged": False}
    assert "resources" in res["capabilities"]


def test_initialize_negotiates_down_to_newest_for_unknown_version():
    engine, _ = build_engine()
    res = engine.initialize({"protocolVersion": "1999-01-01"}, FakeCtx())
    assert res["protocolVersion"] == SUPPORTED_PROTOCOL_VERSIONS[0]


def test_ping_and_initialized():
    engine, _ = build_engine()
    assert engine.ping(None, FakeCtx()) == {}
    assert engine.initialized(None, FakeCtx()) is None


def test_pre_init_requests_are_rejected_but_ping_and_initialize_are_allowed():
    engine, _ = build_engine(initialized=False)
    methods = engine.methods()
    ctx = FakeCtx(session_id="unready")

    # ping and initialize are always allowed, even before the handshake.
    assert methods["ping"](None, ctx) == {}
    init = methods["initialize"]({"protocolVersion": "2025-11-25"}, ctx)
    assert init["protocolVersion"] == "2025-11-25"

    # Operational methods are rejected until notifications/initialized arrives.
    for method, params in (
        ("tools/call", {"name": "echo", "arguments": {"text": "hi"}}),
        ("tools/list", {}),
        ("resources/list", None),
        ("resources/read", {"uri": "ida://metadata"}),
    ):
        with pytest.raises(McpError) as exc:
            methods[method](params, ctx)
        assert exc.value.code == ErrorCode.INVALID_PARAMS

    # After the initialized notification the same session is open for business.
    methods["notifications/initialized"](None, ctx)
    env = methods["tools/call"]({"name": "echo", "arguments": {"text": "hi"}}, ctx)
    assert env["isError"] is False
    assert env["structuredContent"] == {"echo": "hi"}


def test_lifecycle_gate_is_per_session():
    engine, _ = build_engine(initialized=False)
    ready = FakeCtx(session_id="s-ready")
    other = FakeCtx(session_id="s-other")
    engine.initialized(None, ready)

    # The initialized session passes; a different, un-initialized one does not.
    assert engine.tools_list({}, ready)["tools"]
    with pytest.raises(McpError):
        engine.tools_list({}, other)


# -- tools/list -------------------------------------------------------------- #


def test_tools_list_shape_and_feature_hiding():
    engine, _ = build_engine()
    res = engine.tools_list({}, FakeCtx())
    names = [t["name"] for t in res["tools"]]
    assert names == ["add", "boom", "echo"]  # sorted; 'secret' hidden
    assert "nextCursor" not in res

    echo = next(t for t in res["tools"] if t["name"] == "echo")
    assert echo["description"] == "Echo the given text back to the caller."
    assert echo["inputSchema"]["type"] == "object"
    assert echo["inputSchema"]["properties"]["text"]["type"] == "string"
    assert echo["inputSchema"]["required"] == ["text"]
    assert echo["outputSchema"]["type"] == "object"
    assert echo["annotations"]["readOnlyHint"] is True


def test_tools_list_reveals_feature_when_enabled():
    engine, _ = build_engine()
    res = engine.tools_list({}, FakeCtx(features={"debug"}))
    assert "secret" in [t["name"] for t in res["tools"]]


def test_tools_list_cursor_offsets_the_page():
    engine, _ = build_engine()
    cursor = base64.urlsafe_b64encode(json.dumps({"o": 2}).encode()).decode()
    res = engine.tools_list({"cursor": cursor}, FakeCtx())
    assert [t["name"] for t in res["tools"]] == ["echo"]


def test_tools_list_invalid_cursor_is_protocol_error():
    engine, _ = build_engine()
    with pytest.raises(McpError) as exc:
        engine.tools_list({"cursor": "not-a-valid-cursor"}, FakeCtx())
    assert exc.value.code == ErrorCode.INVALID_PARAMS


# -- tools/call -------------------------------------------------------------- #


def test_tools_call_happy_path():
    engine, _ = build_engine()
    env = engine.tools_call({"name": "echo", "arguments": {"text": "hi"}}, FakeCtx())
    assert env["isError"] is False
    assert env["structuredContent"] == {"echo": "hi"}
    assert env["content"][0]["type"] == "text"
    assert json.loads(env["content"][0]["text"]) == {"echo": "hi"}


def test_tools_call_scalar_return_is_wrapped_under_result():
    engine, _ = build_engine()
    env = engine.tools_call({"name": "add", "arguments": {"a": 2, "b": 3}}, FakeCtx())
    assert env["structuredContent"] == {"result": 5}
    assert env["isError"] is False


def test_tools_call_applies_declared_default():
    engine, _ = build_engine()
    env = engine.tools_call({"name": "add", "arguments": {"a": 7}}, FakeCtx())
    assert env["structuredContent"] == {"result": 7}


def test_tools_call_toolerror_becomes_iserror_result():
    engine, _ = build_engine()
    env = engine.tools_call({"name": "boom"}, FakeCtx())
    assert env["isError"] is True
    assert "kaboom" in env["content"][0]["text"]
    assert "structuredContent" not in env


def test_tools_call_unknown_tool_is_protocol_error():
    engine, _ = build_engine()
    with pytest.raises(McpError) as exc:
        engine.tools_call({"name": "nope"}, FakeCtx())
    assert exc.value.code == ErrorCode.INVALID_PARAMS
    assert "Unknown tool" in exc.value.message


def test_tools_call_bad_argument_type_is_protocol_error():
    engine, _ = build_engine()
    with pytest.raises(McpError) as exc:
        engine.tools_call({"name": "echo", "arguments": {"text": 123}}, FakeCtx())
    assert exc.value.code == ErrorCode.INVALID_PARAMS
    assert exc.value.data == {"param": "text"}


def test_tools_call_missing_required_argument_is_protocol_error():
    engine, _ = build_engine()
    with pytest.raises(McpError) as exc:
        engine.tools_call({"name": "echo", "arguments": {}}, FakeCtx())
    assert exc.value.code == ErrorCode.INVALID_PARAMS


def test_tools_call_unknown_argument_is_protocol_error():
    engine, _ = build_engine()
    with pytest.raises(McpError) as exc:
        engine.tools_call({"name": "echo", "arguments": {"text": "x", "z": 1}}, FakeCtx())
    assert exc.value.code == ErrorCode.INVALID_PARAMS


def test_gated_tool_call_returns_iserror_result():
    engine, _ = build_engine()
    env = engine.tools_call({"name": "secret"}, FakeCtx())  # 'debug' not enabled
    assert env["isError"] is True
    assert "not enabled" in env["content"][0]["text"]


def test_tools_call_cooperative_cancellation_yields_iserror():
    reg = Registry()
    cancel = FakeCancel()

    def slow() -> dict:
        """Cooperatively polls the request's cancellation token."""
        cancel.check()
        return {"done": True}

    reg.tool(slow)
    engine = mark_ready(McpEngine(reg))
    ctx = FakeCtx(cancel=cancel)
    cancel.cancel()  # trip it (as a notifications/cancelled would)

    env = engine.tools_call({"name": "slow"}, ctx)
    assert env["isError"] is True
    assert "cancel" in env["content"][0]["text"].lower()


# -- annotations / hints ----------------------------------------------------- #


def test_destructive_annotation_surfaced_in_tools_list():
    reg = Registry()

    @reg.tool
    @reg.destructive
    def wipe() -> dict:
        """Destroys something."""
        return {"ok": True}

    engine = mark_ready(McpEngine(reg))
    tool = engine.tools_list({}, FakeCtx())["tools"][0]
    assert tool["annotations"]["readOnlyHint"] is False
    assert tool["annotations"]["destructiveHint"] is True


# -- output guard / overflow ------------------------------------------------- #


def test_output_guard_spills_oversized_result_to_a_resource():
    reg = Registry()

    @reg.tool
    def big() -> dict:
        """Returns an oversized payload."""
        return {"blob": "x" * 400}

    engine = mark_ready(McpEngine(reg, limits=Limits(output_budget_chars=50)))
    env = engine.tools_call({"name": "big"}, FakeCtx())
    assert env["isError"] is False
    meta = env["_meta"]["com.idamesh/overflow"]
    assert meta["truncated"] is True
    ref = meta["ref"]
    assert ref.startswith(OVERFLOW_URI_PREFIX)

    read = engine.resources_read({"uri": ref}, FakeCtx())
    contents = read["contents"][0]
    assert contents["uri"] == ref
    assert json.loads(contents["text"]) == {"blob": "x" * 400}


def test_resources_read_overflow_miss_is_resource_not_found():
    engine, _ = build_engine()
    with pytest.raises(McpError) as exc:
        engine.resources_read({"uri": OVERFLOW_URI_PREFIX + "0" * 64}, FakeCtx())
    assert exc.value.code == ErrorCode.RESOURCE_NOT_FOUND


# -- resources --------------------------------------------------------------- #


def test_literal_resource_list_and_read():
    reg = Registry()

    @reg.resource("ida://metadata")
    def metadata() -> dict:
        """Static database metadata."""
        return {"ok": True}

    engine = mark_ready(McpEngine(reg))
    listing = engine.resources_list(None, FakeCtx())
    assert listing["resources"][0]["uri"] == "ida://metadata"
    read = engine.resources_read({"uri": "ida://metadata"}, FakeCtx())
    assert json.loads(read["contents"][0]["text"]) == {"ok": True}


def test_templated_resource_binds_path_param():
    reg = Registry()

    @reg.resource("ida://function/{address}")
    def function_at(address: str) -> dict:
        """A function resource keyed by address."""
        return {"address": address}

    engine = mark_ready(McpEngine(reg))
    templates = engine.resources_templates_list(None, FakeCtx())
    assert templates["resourceTemplates"][0]["uriTemplate"] == "ida://function/{address}"
    read = engine.resources_read({"uri": "ida://function/0x401000"}, FakeCtx())
    assert json.loads(read["contents"][0]["text"]) == {"address": "0x401000"}


def test_resources_read_unknown_uri_is_resource_not_found():
    engine, _ = build_engine()
    with pytest.raises(McpError) as exc:
        engine.resources_read({"uri": "ida://nope"}, FakeCtx())
    assert exc.value.code == ErrorCode.RESOURCE_NOT_FOUND


# -- wiring seam ------------------------------------------------------------- #


def test_methods_map_exposes_the_mcp_method_set():
    engine, _ = build_engine()
    assert set(engine.methods()) == {
        "initialize",
        "notifications/initialized",
        "ping",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/templates/list",
        "resources/read",
    }


def test_map_exception_covers_protocol_and_tool_errors():
    engine, _ = build_engine()
    assert engine.map_exception(McpError(ErrorCode.INVALID_PARAMS, "x", "d")) == (
        ErrorCode.INVALID_PARAMS,
        "x",
        "d",
    )
    assert engine.map_exception(ToolError("t")) == (ErrorCode.TOOL, "t", None)
    assert engine.map_exception(ValueError("y")) is None


def test_fake_ctx_structurally_satisfies_request_view():
    assert isinstance(FakeCtx(), RequestView)
