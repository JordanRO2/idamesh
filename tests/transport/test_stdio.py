"""Unit tests for :class:`StdioTransport` over in-memory byte pipes."""

from __future__ import annotations

import io
import json

from idamesh.infrastructure.rpc.router import Router
from idamesh.infrastructure.transport.stdio import StdioTransport


def _router() -> Router:
    router = Router()
    router.register("ping", lambda params, ctx: {"pong": True})
    router.register("echo", lambda params, ctx: {"echo": params})
    router.register("note", lambda params, ctx: None, notification=True)
    return router


def test_stdio_round_trip_writes_one_line_per_request():
    stdin = io.BytesIO(
        b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        b"\n"  # blank line is skipped
        b'{"jsonrpc":"2.0","method":"note"}\n'  # notification -> no output
        b'{"jsonrpc":"2.0","id":2,"method":"echo","params":{"a":1}}\n'
    )
    stdout = io.BytesIO()

    StdioTransport(_router(), stdin=stdin, stdout=stdout).serve(block=True)

    lines = [line for line in stdout.getvalue().split(b"\n") if line]
    assert len(lines) == 2  # ping + echo; note produced nothing
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert first == {"jsonrpc": "2.0", "id": 1, "result": {"pong": True}}
    assert second == {"jsonrpc": "2.0", "id": 2, "result": {"echo": {"a": 1}}}


def test_stdio_output_lines_are_newline_free():
    stdin = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"echo","params":{"s":"a\\nb"}}\n')
    stdout = io.BytesIO()

    StdioTransport(_router(), stdin=stdin, stdout=stdout).serve(block=True)

    raw = stdout.getvalue()
    # Exactly one terminating newline; the embedded string newline is JSON-escaped.
    assert raw.count(b"\n") == 1
    assert raw.endswith(b"\n")


def test_stdio_session_id_is_forwarded():
    seen = {}

    class Recorder:
        def dispatch(self, raw, *, session_id=None, **_):
            seen["session_id"] = session_id
            return None

    stdin = io.BytesIO(b'{"jsonrpc":"2.0","method":"note"}\n')
    StdioTransport(Recorder(), stdin=stdin, stdout=io.BytesIO(), session_id="s-1").serve(
        block=True
    )
    assert seen["session_id"] == "s-1"
