"""Unit tests for the JSON-RPC 2.0 :class:`Router`."""

from __future__ import annotations

import json

import pytest

from idamesh.infrastructure.rpc.context import (
    CancellationRegistry,
    Cancelled,
    CancellationToken,
)
from idamesh.infrastructure.rpc.router import (
    Router,
    RpcError,
    RpcErrorCode,
    RpcRequest,
    RpcResponse,
)


def _decode(reply):
    assert reply is not None
    return json.loads(reply.decode("utf-8"))


def make_router(**kwargs) -> Router:
    router = Router(**kwargs)
    router.register("ping", lambda params, ctx: {})
    router.register("echo", lambda params, ctx: {"echo": params})
    router.register("note", lambda params, ctx: None, notification=True)

    def boom(params, ctx):
        raise RuntimeError("kaboom")

    def bad_params(params, ctx):
        raise RpcError(RpcErrorCode.BAD_PARAMS, "nope", {"param": "x"})

    router.register("boom", boom)
    router.register("bad_params", bad_params)
    return router


def frame(method, *, id=None, params=None, notification=False):
    obj = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        obj["params"] = params
    if not notification:
        obj["id"] = id
    return json.dumps(obj).encode("utf-8")


# -- happy path -----------------------------------------------------------


def test_ping_returns_empty_result():
    out = _decode(make_router().dispatch(frame("ping", id=1)))
    assert out == {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_echo_forwards_params():
    out = _decode(make_router().dispatch(frame("echo", id="abc", params={"a": 1})))
    assert out == {"jsonrpc": "2.0", "id": "abc", "result": {"echo": {"a": 1}}}


def test_string_and_null_ids_echo_exactly():
    router = make_router()
    assert _decode(router.dispatch(frame("ping", id="s")))["id"] == "s"
    # A call carrying an explicit null id is answered (distinct from a notification).
    assert _decode(router.dispatch(frame("ping", id=None)))["id"] is None


# -- notifications --------------------------------------------------------


def test_notification_yields_no_response():
    assert make_router().dispatch(frame("ping", notification=True)) is None


def test_notification_only_handler_never_responds_even_with_id():
    # 'note' is registered notification=True: no response even when given an id.
    assert make_router().dispatch(frame("note", id=7)) is None


def test_unknown_notification_is_silently_ignored():
    assert make_router().dispatch(frame("does_not_exist", notification=True)) is None


# -- error model ----------------------------------------------------------


def test_unknown_method_is_method_not_found():
    out = _decode(make_router().dispatch(frame("nope", id=1)))
    assert out["error"]["code"] == RpcErrorCode.METHOD_MISSING
    assert "error" in out and "result" not in out


def test_parse_error_on_bad_json():
    out = _decode(make_router().dispatch(b"{ not valid json"))
    assert out["error"]["code"] == RpcErrorCode.PARSE
    assert out["id"] is None


def test_invalid_request_missing_jsonrpc():
    out = _decode(make_router().dispatch(json.dumps({"method": "ping", "id": 1}).encode()))
    assert out["error"]["code"] == RpcErrorCode.INVALID_REQUEST


def test_invalid_request_non_string_method():
    out = _decode(make_router().dispatch(json.dumps({"jsonrpc": "2.0", "method": 5, "id": 1}).encode()))
    assert out["error"]["code"] == RpcErrorCode.INVALID_REQUEST


def test_fractional_id_is_rejected():
    out = _decode(make_router().dispatch(b'{"jsonrpc":"2.0","method":"ping","id":1.5}'))
    assert out["error"]["code"] == RpcErrorCode.INVALID_REQUEST


def test_boolean_id_is_rejected():
    out = _decode(make_router().dispatch(json.dumps({"jsonrpc": "2.0", "method": "ping", "id": True}).encode()))
    assert out["error"]["code"] == RpcErrorCode.INVALID_REQUEST


def test_rpc_error_from_handler_is_propagated():
    out = _decode(make_router().dispatch(frame("bad_params", id=3)))
    assert out["error"]["code"] == RpcErrorCode.BAD_PARAMS
    assert out["error"]["data"] == {"param": "x"}


def test_unhandled_exception_maps_to_internal_with_traceback():
    out = _decode(make_router().dispatch(frame("boom", id=9)))
    assert out["error"]["code"] == RpcErrorCode.INTERNAL
    assert "traceback" in out["error"]["data"]


def test_redacted_mode_hides_internal_details():
    out = _decode(make_router(redact_internal_errors=True).dispatch(frame("boom", id=9)))
    assert out["error"]["code"] == RpcErrorCode.INTERNAL
    assert out["error"]["message"] == "internal error"
    assert "data" not in out["error"]


def test_injected_exception_mapper_wins():
    def mapper(exc):
        if isinstance(exc, RuntimeError):
            return (-32050, "mapped runtime failure", {"kind": "runtime"})
        return None

    router = make_router()
    router.map_exception = mapper
    out = _decode(router.dispatch(frame("boom", id=1)))
    assert out["error"]["code"] == -32050
    assert out["error"]["message"] == "mapped runtime failure"


# -- batches --------------------------------------------------------------


def test_batch_drops_notifications_and_returns_calls():
    router = make_router()
    batch = [
        {"jsonrpc": "2.0", "method": "ping", "id": 1},
        {"jsonrpc": "2.0", "method": "ping"},  # notification -> dropped
        {"jsonrpc": "2.0", "method": "echo", "id": 2, "params": {"k": "v"}},
    ]
    out = _decode(router.dispatch(json.dumps(batch).encode()))
    assert isinstance(out, list)
    ids = sorted(item["id"] for item in out)
    assert ids == [1, 2]


def test_all_notification_batch_yields_no_response():
    router = make_router()
    batch = [
        {"jsonrpc": "2.0", "method": "ping"},
        {"jsonrpc": "2.0", "method": "note", "id": 4},  # notification handler
    ]
    assert router.dispatch(json.dumps(batch).encode()) is None


def test_empty_batch_is_invalid_request():
    out = _decode(make_router().dispatch(b"[]"))
    assert out["error"]["code"] == RpcErrorCode.INVALID_REQUEST


# -- cancellation ---------------------------------------------------------


def test_cancellation_registry_open_trip_close():
    registry = CancellationRegistry()
    token = registry.open(1)
    assert token.cancelled is False
    assert registry.trip(1) is True
    assert token.cancelled is True
    registry.close(1)
    assert registry.trip(1) is False  # no live token after close


def test_cancelled_token_check_raises():
    token = CancellationToken()
    token.check()  # no-op when not cancelled
    token.cancel()
    with pytest.raises(Cancelled):
        token.check()


def test_cancelled_notification_trips_registered_token():
    registry = CancellationRegistry()
    router = Router(registry=registry)
    token = registry.open(42)
    reply = router.dispatch(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 42},
            }
        ).encode()
    )
    assert reply is None  # a notification: no response
    assert token.cancelled is True


def test_initialize_is_never_registered_for_cancellation():
    # The MCP spec forbids cancelling ``initialize``; the router must not open a
    # cancellation token for it, so an in-flight ``initialize`` has no live token.
    registry = CancellationRegistry()
    router = Router(registry=registry)
    seen = {}

    def handler(params, ctx):
        # A registered call has a live token that trip() can find by its id.
        seen["tripped"] = registry.trip(ctx.request_id)
        return {"ok": True}

    router.register("initialize", handler)
    router.register("other", handler)

    router.dispatch(frame("initialize", id=1))
    assert seen["tripped"] is False  # no token registered for initialize

    router.dispatch(frame("other", id=2))
    assert seen["tripped"] is True  # a normal id-bearing call is registered


def test_cancelled_handler_during_dispatch_maps_to_cancelled_code():
    router = Router()

    def cancels(params, ctx):
        ctx.cancel.cancel()
        ctx.cancel.check()  # raises Cancelled

    router.register("cancels", cancels)
    out = _decode(router.dispatch(frame("cancels", id=5)))
    assert out["error"]["code"] == RpcErrorCode.CANCELLED


# -- value objects --------------------------------------------------------


def test_rpc_request_from_wire_distinguishes_notification():
    call = RpcRequest.from_wire({"jsonrpc": "2.0", "method": "m", "id": 1})
    assert call.has_id is True and call.id == 1
    notif = RpcRequest.from_wire({"jsonrpc": "2.0", "method": "m"})
    assert notif.has_id is False


def test_rpc_response_to_wire_is_mutually_exclusive():
    ok = RpcResponse(1, result={"x": 1}).to_wire()
    assert ok == {"jsonrpc": "2.0", "id": 1, "result": {"x": 1}}
    err = RpcResponse(1, error={"code": -1, "message": "e"}).to_wire()
    assert "result" not in err and err["error"]["code"] == -1
