"""Unit tests for the streamable-HTTP transport (fake dispatcher)."""

from __future__ import annotations

import json

from tests.transport.conftest import http_request

REQUEST = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
NOTIFICATION = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
INITIALIZE = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode()


def _post(port, body, **headers):
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers)
    return http_request(port, "POST", body=body, headers=hdrs)


# -- core POST semantics --------------------------------------------------


def test_post_request_returns_json(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher).bound_port
    status, headers, body = _post(port, REQUEST)
    assert status == 200
    assert headers["content-type"] == "application/json"
    payload = json.loads(body)
    assert payload["id"] == 1
    assert payload["result"] == {"ok": True}


def test_post_notification_returns_202_no_body(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher).bound_port
    status, _headers, body = _post(port, NOTIFICATION)
    assert status == 202
    assert body == b""


def test_get_returns_405(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher).bound_port
    status, headers, _body = http_request(port, "GET")
    assert status == 405
    assert "POST" in headers.get("allow", "")


def test_unknown_path_returns_404(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher).bound_port
    status, _headers, _body = http_request(port, "POST", body=REQUEST, path="/nope")
    assert status == 404


# -- Origin validation (DNS-rebinding MUST) -------------------------------


def test_bad_origin_returns_403(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher).bound_port
    status, _headers, _body = _post(port, REQUEST, Origin="http://evil.example.com")
    assert status == 403
    assert not fake_dispatcher.calls  # never reached the dispatcher


def test_loopback_origin_is_allowed(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher).bound_port
    status, _headers, _body = _post(port, REQUEST, Origin="http://localhost:5173")
    assert status == 200


def test_absent_origin_is_allowed(fake_dispatcher, http_server):
    # Non-browser clients (curl, our own SDK) send no Origin; that must pass.
    port = http_server(fake_dispatcher).bound_port
    status, _headers, _body = _post(port, REQUEST)
    assert status == 200


def test_explicit_origin_allow_list(fake_dispatcher, http_server):
    port = http_server(
        fake_dispatcher, allowed_origins=["https://trusted.example"]
    ).bound_port
    ok, _h, _b = _post(port, REQUEST, Origin="https://trusted.example")
    bad, _h2, _b2 = _post(port, REQUEST, Origin="https://other.example")
    assert ok == 200 and bad == 403


# -- sessions -------------------------------------------------------------


def test_session_assigned_on_initialize_and_required_after(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher, require_session=True).bound_port

    status, headers, _body = _post(port, INITIALIZE)
    assert status == 200
    session_id = headers.get("mcp-session-id")
    assert session_id  # a session was minted

    # A non-initialize request without the session id is rejected.
    missing, _h, _b = _post(port, REQUEST)
    assert missing == 400

    # An unknown session id is a 404 (client must re-initialize).
    unknown, _h2, _b2 = _post(port, REQUEST, **{"Mcp-Session-Id": "deadbeef"})
    assert unknown == 404

    # Echoing the assigned id succeeds.
    ok, _h3, _b3 = _post(port, REQUEST, **{"Mcp-Session-Id": session_id})
    assert ok == 200


def test_delete_terminates_session(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher, require_session=True).bound_port
    _s, headers, _b = _post(port, INITIALIZE)
    session_id = headers["mcp-session-id"]

    deleted, _h, _b2 = http_request(
        port, "DELETE", headers={"Mcp-Session-Id": session_id}
    )
    assert deleted == 200

    # After deletion the id is unknown -> 404.
    after, _h2, _b3 = _post(port, REQUEST, **{"Mcp-Session-Id": session_id})
    assert after == 404


def test_anonymous_sessions_allowed_by_default(fake_dispatcher, http_server):
    # require_session defaults to False: a plain request needs no session.
    port = http_server(fake_dispatcher).bound_port
    status, _headers, _body = _post(port, REQUEST)
    assert status == 200


# -- auth, size, headers --------------------------------------------------


def test_bearer_token_enforced(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher, bearer_token="s3cret").bound_port
    missing, _h, _b = _post(port, REQUEST)
    wrong, _h2, _b2 = _post(port, REQUEST, Authorization="Bearer nope")
    ok, _h3, _b3 = _post(port, REQUEST, Authorization="Bearer s3cret")
    assert missing == 401 and wrong == 401 and ok == 200


def test_oversized_body_returns_413(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher, max_body_bytes=64).bound_port
    big = b'{"jsonrpc":"2.0","id":1,"method":"x","params":"' + b"A" * 200 + b'"}'
    status, _headers, _body = _post(port, big)
    assert status == 413


def test_protocol_version_and_features_forwarded(fake_dispatcher, http_server):
    port = http_server(fake_dispatcher).bound_port
    status, _headers, _body = http_request(
        port,
        "POST",
        body=REQUEST,
        headers={
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-06-18",
        },
        path="/mcp?features=dbg,extra",
    )
    assert status == 200
    call = fake_dispatcher.calls[-1]
    assert call.protocol_version == "2025-06-18"
    assert call.features == frozenset({"dbg", "extra"})


# -- MCP-Protocol-Version handling (spec §5.5) ----------------------------

_SUPPORTED = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")


def test_supported_protocol_version_is_forwarded(fake_dispatcher, http_server):
    port = http_server(
        fake_dispatcher, supported_protocol_versions=_SUPPORTED
    ).bound_port
    status, _headers, _body = _post(port, REQUEST, **{"MCP-Protocol-Version": "2025-06-18"})
    assert status == 200
    assert fake_dispatcher.calls[-1].protocol_version == "2025-06-18"


def test_unsupported_protocol_version_returns_400(fake_dispatcher, http_server):
    port = http_server(
        fake_dispatcher, supported_protocol_versions=_SUPPORTED
    ).bound_port
    status, _headers, body = _post(port, REQUEST, **{"MCP-Protocol-Version": "1999-01-01"})
    assert status == 400
    assert not fake_dispatcher.calls  # rejected before reaching the dispatcher
    payload = json.loads(body)
    assert "1999-01-01" == payload.get("requested")


def test_absent_protocol_version_falls_back_to_default(fake_dispatcher, http_server):
    port = http_server(
        fake_dispatcher, supported_protocol_versions=_SUPPORTED
    ).bound_port
    status, _headers, _body = _post(port, REQUEST)
    assert status == 200
    assert fake_dispatcher.calls[-1].protocol_version == "2025-03-26"
