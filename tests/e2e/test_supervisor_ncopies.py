"""Live end-to-end proof of the supervisor's N-copies parallelism core.

This is the flagship test for the multi-process routing layer. It stands the real
supervisor up **in-process** — ``build_supervisor_container`` (the idapro-free
``WorkerPool`` + ``WorkerClient`` + ``SupervisorRouter``) served over the real
streamable-HTTP transport on an ephemeral loopback port — and drives it as an MCP
client over that socket, exactly as an external agent would. Nothing here imports
``idapro``; every database lives in a headless ``idalib`` worker the pool spawns as
its own windowless OS process.

What it proves (acceptance criteria for HTTP tool exposure, N-copies isolation,
and cleanup guarantees):

* ``tools/list`` over HTTP advertises the management tools ``idb_open`` /
  ``idb_list`` **and** the worker tools (``decompile``, ``list_funcs``, …) each
  carrying an added **optional** ``database`` routing key.
* ``idb_open(tiny.exe)`` twice yields two *different* session ids backed by two
  *distinct live worker processes* (two PIDs) over two *distinct private copies* —
  genuine N-copies parallelism on one binary, not a dedup.
* ``idb_list`` enumerates both sessions.
* A read tool routes to each copy independently: ``decompile(main, database=A)``
  and ``list_funcs(database=B)`` both succeed against their own worker.
* With two databases open, a routed call that **omits** ``database`` is rejected
  with a clear ``multiple databases`` error (the sole-session default only applies
  when exactly one is open — proven by routing to the last remaining session after
  one is closed).
* Each worker enforces its per-session bearer token: a **direct** tokenless call to
  a worker's ``/mcp`` is rejected with HTTP ``401`` while the same call with the
  minted token (and the supervisor's own routed forwards) succeeds.
* The ``idb_close`` management tool terminates a session's worker process, removes
  only that session's private scratch directory, and drops it from ``idb_list``;
  the user's original ``tiny.exe`` is never touched (same bytes, no sibling database
  file created next to it).

Skips cleanly when idalib is unavailable (``IDADIR`` unset / not importable) or the
fixture is missing, so CI without IDA stays green. Every spawned worker is created
without a console window (the pool sets ``CREATE_NO_WINDOW`` on Windows) and is
always reaped in teardown via ``pool.close_all()``.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pytest

from idamesh.bootstrap.supervisor_main import build_supervisor_container
from idamesh.infrastructure.process.scratch_copy import session_dir
from idamesh.infrastructure.transport.http import HttpTransport

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "tiny.exe"
_SRC = Path(__file__).resolve().parents[2] / "src"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_SPAWN_TIMEOUT = 180
_CALL_TIMEOUT = 120


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_SRC) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _idalib_available() -> bool:
    """True when a child process can import idalib with the current ``IDADIR``."""
    idadir = os.environ.get("IDADIR")
    if not idadir or not os.path.isdir(idadir):
        return False
    probe = (
        "import os\n"
        "d = os.environ.get('IDADIR')\n"
        "os.add_dll_directory(d)\n"
        "import idapro\n"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", probe],
            env=_child_env(),
            capture_output=True,
            timeout=_SPAWN_TIMEOUT,
            creationflags=_NO_WINDOW,
        )
    except Exception:
        return False
    return result.returncode == 0


pytestmark = pytest.mark.skipif(
    not _FIXTURE.exists() or not _idalib_available(),
    reason="idalib unavailable (set IDADIR to a valid IDA install) or fixture missing",
)


class _SupervisorClient:
    """A minimal MCP-over-HTTP client for the supervisor's front ``/mcp`` endpoint."""

    def __init__(self, url: str) -> None:
        self._url = url
        self._session: Optional[str] = None

    def _post(self, frame: dict) -> Optional[dict]:
        headers = {"Content-Type": "application/json", "Origin": "http://localhost"}
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        req = urllib.request.Request(
            self._url, data=json.dumps(frame).encode(), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=_CALL_TIMEOUT) as resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self._session = sid
            body = resp.read()
        return json.loads(body) if body else None

    def notify(self, method: str, params: Optional[dict] = None) -> None:
        frame: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            frame["params"] = params
        self._post(frame)

    def call(self, rid: int, method: str, params: Optional[dict] = None) -> dict:
        frame: Dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            frame["params"] = params
        result = self._post(frame)
        assert result is not None, f"expected a response body for {method!r}"
        return result

    def tool(self, rid: int, name: str, arguments: dict) -> dict:
        """Call ``tools/call`` and return the raw JSON-RPC response frame."""
        return self.call(rid, "tools/call", {"name": name, "arguments": arguments})


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _raw_worker_post(
    host: str, port: int, frame: dict, *, token: Optional[str] = None
) -> Tuple[int, bytes]:
    """POST a frame straight to a worker's ``/mcp`` (bypassing the supervisor).

    Returns ``(status, body)``. Used to prove a worker rejects an unauthenticated
    local caller with HTTP 401 while the supervisor's token-bearing forwards pass.
    """
    url = f"http://{host}:{port}/mcp"
    headers = {"Content-Type": "application/json", "Origin": "http://localhost"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        url, data=json.dumps(frame).encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=_CALL_TIMEOUT) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_supervisor_ncopies_live(tmp_path: Path, capsys, monkeypatch) -> None:
    # Isolate the filesystem discovery registry to this test. The supervisor is
    # built with adoption on (the default), whose GuiDiscoveryReader otherwise
    # reads the machine-global registry dir and would surface any live/leftover
    # GUI-plugin instance record, making idb_list non-hermetic. Pointing
    # IDA_MCP_USER_DIR at an empty tmp dir guarantees an empty registry, so
    # idb_list reflects exactly the workers this test spawns.
    monkeypatch.setenv("IDA_MCP_USER_DIR", str(tmp_path / "idausr"))

    # The "user's original" binary. We open it twice; each open must copy it into
    # a private scratch dir and open THAT, never this file.
    original = tmp_path / "tiny.exe"
    original.write_bytes(_FIXTURE.read_bytes())
    original_sha = _sha256(original)

    container = build_supervisor_container(max_workers=4, host="127.0.0.1")
    transport = HttpTransport(
        container.rpc_router,
        host="127.0.0.1",
        port=0,
        supported_protocol_versions=container.protocol_versions,
    )
    transport.serve(block=False)
    url = f"http://127.0.0.1:{transport.bound_port}/mcp"

    evidence: Dict[str, Any] = {}
    try:
        client = _SupervisorClient(url)

        # -- initialize + tools/list -------------------------------------- #
        init = client.call(1, "initialize", {"protocolVersion": "2025-06-18"})["result"]
        assert init["protocolVersion"] == "2025-06-18", init
        client.notify("notifications/initialized")

        tools = client.call(2, "tools/list")["result"]["tools"]
        by_name = {t["name"]: t for t in tools}
        # Management tools present.
        assert "idb_open" in by_name, sorted(by_name)
        assert "idb_list" in by_name, sorted(by_name)
        # Worker tools present, each with an added OPTIONAL database routing key.
        for worker_tool in ("decompile", "list_funcs"):
            assert worker_tool in by_name, sorted(by_name)
            schema = by_name[worker_tool]["inputSchema"]
            props = schema.get("properties", {})
            assert "database" in props, (worker_tool, schema)
            assert props["database"]["type"] == "string", (worker_tool, props)
            assert "database" not in schema.get("required", []), (worker_tool, schema)
        # Management tools do NOT gain a database key.
        assert "database" not in by_name["idb_open"]["inputSchema"].get("properties", {})

        # -- open the same binary twice -> two independent sessions ------- #
        open_a = client.tool(3, "idb_open", {"input_path": str(original)})["result"]
        assert open_a["isError"] is False, open_a
        info_a = open_a["structuredContent"]
        sid_a = info_a["session_id"]
        assert info_a["shared"] is False, info_a

        open_b = client.tool(4, "idb_open", {"input_path": str(original)})["result"]
        assert open_b["isError"] is False, open_b
        info_b = open_b["structuredContent"]
        sid_b = info_b["session_id"]
        assert info_b["shared"] is False, info_b

        # Distinct sessions, distinct private copies.
        assert sid_a != sid_b, (sid_a, sid_b)
        assert info_a["private_copy_path"] != info_b["private_copy_path"], (info_a, info_b)
        assert Path(info_a["private_copy_path"]).is_file(), info_a
        assert Path(info_b["private_copy_path"]).is_file(), info_b
        # Neither private copy is the user's original.
        assert Path(info_a["private_copy_path"]).resolve() != original.resolve()
        assert Path(info_b["private_copy_path"]).resolve() != original.resolve()

        # Two distinct LIVE worker processes (two PIDs), both running.
        sess_a = container.pool.get(sid_a)
        sess_b = container.pool.get(sid_b)
        assert sess_a is not None and sess_b is not None
        proc_a, proc_b = sess_a.process, sess_b.process
        assert proc_a is not None and proc_b is not None
        pid_a, pid_b = proc_a.pid, proc_b.pid
        assert pid_a != pid_b, (pid_a, pid_b)
        assert proc_a.poll() is None, "worker A must be alive"
        assert proc_b.poll() is None, "worker B must be alive"
        # Distinct endpoints (two servers on two ports).
        assert (sess_a.host, sess_a.port) != (sess_b.host, sess_b.port)

        # -- idb_list shows both ------------------------------------------ #
        listed = client.tool(5, "idb_list", {})["result"]["structuredContent"]
        assert listed["count"] == 2, listed
        listed_ids = {s["session_id"] for s in listed["sessions"]}
        assert listed_ids == {sid_a, sid_b}, (listed_ids, sid_a, sid_b)

        # -- route a read tool to EACH copy independently ----------------- #
        dec = client.tool(
            6, "decompile", {"address": "main", "database": sid_a}
        )["result"]
        assert dec["isError"] is False, dec
        pseudo = dec["structuredContent"]
        assert pseudo["name"] == "main", pseudo
        assert "main" in pseudo["pseudocode"] and "return" in pseudo["pseudocode"], pseudo

        lf = client.tool(
            7, "list_funcs", {"offset": 0, "count": 10, "database": sid_b}
        )["result"]
        assert lf["isError"] is False, lf
        page = lf["structuredContent"]
        assert page["total"] > 0 and len(page["items"]) > 0, page

        # -- database omitted with two sessions open -> a clear error ----- #
        ambiguous = client.tool(8, "decompile", {"address": "main"})
        assert "error" in ambiguous and "result" not in ambiguous, ambiguous
        assert ambiguous["error"]["code"] == -32602, ambiguous
        assert "multiple databases" in ambiguous["error"]["message"], ambiguous

        # -- per-worker bearer token: a direct tokenless call is rejected -- #
        # Each worker requires the random token the pool minted for it. A local
        # process hitting the worker's loopback /mcp WITHOUT that token gets 401,
        # even though the supervisor's own (token-bearing) forwards above worked.
        assert sess_a.token, "the pool must mint a per-worker token"
        init_frame = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        }
        status_noauth, _ = _raw_worker_post(sess_a.host, sess_a.port, init_frame)
        assert status_noauth == 401, f"tokenless worker call must be 401, got {status_noauth}"
        # The same direct call WITH the correct token is accepted (not 401).
        status_auth, _ = _raw_worker_post(
            sess_a.host, sess_a.port, init_frame, token=sess_a.token
        )
        assert status_auth == 200, f"token-bearing worker call must pass, got {status_auth}"

        # -- close session A via the idb_close management tool ------------- #
        # A client-reachable release path: idb_close terminates the worker and
        # removes only its private scratch dir, dropping it from idb_list.
        dir_a = session_dir(sid_a)
        dir_b = session_dir(sid_b)
        assert dir_a.is_dir() and dir_b.is_dir(), (dir_a, dir_b)

        closed = client.tool(10, "idb_close", {"session_id": sid_a})["result"]
        assert closed["isError"] is False, closed
        assert closed["structuredContent"] == {"session_id": sid_a, "closed": True}, closed

        proc_a.wait(timeout=30)
        assert proc_a.poll() is not None, "worker A must be terminated"
        assert not dir_a.exists(), f"session A scratch dir should be gone: {dir_a}"
        assert dir_b.exists(), "closing A must not touch B's scratch dir"
        # A dropped out of idb_list; only B remains.
        remaining = client.tool(11, "idb_list", {})["result"]["structuredContent"]
        assert {s["session_id"] for s in remaining["sessions"]} == {sid_b}, remaining

        # With exactly one session left, the sole-session default kicks in:
        # a routed call with database omitted now resolves to B.
        sole = client.tool(9, "list_funcs", {"offset": 0, "count": 5})["result"]
        assert sole["isError"] is False, sole
        assert sole["structuredContent"]["total"] > 0, sole

        # -- close session B: its worker + scratch gone too --------------- #
        assert container.pool.close_session(sid_b) is True
        proc_b.wait(timeout=30)
        assert proc_b.poll() is not None, "worker B must be terminated"
        assert not dir_b.exists(), f"session B scratch dir should be gone: {dir_b}"

        # -- the user's original file is untouched ------------------------ #
        assert original.is_file(), original
        assert _sha256(original) == original_sha, "original bytes must be unchanged"
        # No sibling database was created next to the user's original.
        assert not original.with_suffix(".i64").exists(), "no .i64 next to the original"
        assert not original.with_suffix(".idb").exists(), "no .idb next to the original"

        evidence = {
            "session_a": {
                "id": sid_a,
                "pid": pid_a,
                "endpoint": f"{sess_a.host}:{sess_a.port}",
                "private_copy": info_a["private_copy_path"],
                "scratch_removed": not dir_a.exists(),
            },
            "session_b": {
                "id": sid_b,
                "pid": pid_b,
                "endpoint": f"{sess_b.host}:{sess_b.port}",
                "private_copy": info_b["private_copy_path"],
                "scratch_removed": not dir_b.exists(),
            },
            "idb_list_count": listed["count"],
            "decompile_A_first_line": pseudo["lines"][0] if pseudo.get("lines") else "",
            "list_funcs_B_total": page["total"],
            "original_sha256_stable": _sha256(original) == original_sha,
        }
    finally:
        transport.stop()
        # Always reap every worker the pool spawned, even on assertion failure.
        container.pool.close_all()

    # Surface concrete live evidence (visible under ``pytest -s``).
    with capsys.disabled():
        print("\n=== N-COPIES LIVE EVIDENCE ===")
        print(json.dumps(evidence, indent=2))
