"""Live end-to-end proof of the merge-back — the flagship money-shot.

This is the capstone test for the whole N-copies supervisor: two agents each edit
their *own private copy* of one binary in parallel, then ``idb_merge`` consolidates
their divergent user annotations into **one** canonical database. It stands the real
supervisor up **in-process** (``build_supervisor_container`` — the idapro-free
``WorkerPool`` + ``WorkerClient`` + ``SupervisorRouter`` served over the real
streamable-HTTP transport on an ephemeral loopback port) and drives it as an MCP
client over that socket, exactly as an external agent would. Nothing here imports
``idapro``; every database lives in a headless ``idalib`` worker the pool spawns as
its own windowless OS process.

What it proves:

* Two private copies of ``tiny.exe`` (``idb_open`` twice) are edited **differently**
  through the routed mutation tools: copy A renames one function to ``agent_a_name``
  and sets a function comment on it; copy B renames a *different* function to
  ``agent_b_name`` and applies a prototype (``set_type``) to it. Before the merge,
  each new name exists in exactly one copy — genuine parallel divergence.
* ``idb_merge(sources=[A, B], into=A, policy="last", use_baseline=true)`` reconciles
  the two exports. Because the edits sit at different addresses, both survive with
  **zero conflicts**, and — critically — each copy's OWN pristine baseline (captured
  in-process at ``idb_open`` before any edit) is subtracted, so the copies' unchanged
  auto-analysis names never masquerade as edits and cross-copy analysis variance can
  never manufacture a false conflict (the determinism this design guarantees). The
  applied report shows both names/comment/type merged and a compressed ``.i64``
  snapshot written.
* **Consolidation is proven two ways**: reading session A back after the apply, and
  ``idb_open`` of the produced snapshot ``.i64`` as a fresh session — in *both*,
  ``lookup_funcs`` finds **both** ``agent_a_name`` **and** ``agent_b_name``. Two
  agents' parallel edits, now in one database.
* ``dry_run=true`` returns the same plan/counts but writes nothing (no ``ok`` /
  ``snapshot`` keys).
* Every spawned worker (A, B, the snapshot reopen) is reaped; each session's private
  scratch dir is removed; and the user's original ``tiny.exe`` is byte-for-byte
  unchanged with no bare ``.i64``/``.idb`` left beside it (only the intended
  ``.merged.i64`` canonical output). The merge spawns no baseline worker of its own —
  baselines are the per-session records captured at ``idb_open``.

Skips cleanly when idalib is unavailable (``IDADIR`` unset / not importable) or the
fixture is missing, so CI without IDA stays green. Every worker is created without a
console window (the pool sets ``CREATE_NO_WINDOW`` on Windows) and is always reaped
in teardown via ``pool.close_all()``.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from idamesh.bootstrap.supervisor_main import build_supervisor_container
from idamesh.infrastructure.process.scratch_copy import session_dir
from idamesh.infrastructure.transport.http import HttpTransport

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "tiny.exe"
_SRC = Path(__file__).resolve().parents[2] / "src"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_SPAWN_TIMEOUT = 180
# A single idb_merge call fans out several worker round-trips (export A, export B,
# apply + snapshot) with no baseline spawn of its own, so its one HTTP round-trip
# must tolerate that whole pipeline — hence the generous call timeout.
_CALL_TIMEOUT = 300


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

    def ok_tool(self, rid: int, name: str, arguments: dict) -> Dict[str, Any]:
        """Call a tool, assert a non-error result, and return its structuredContent."""
        frame = self.tool(rid, name, arguments)
        assert "result" in frame, (name, frame)
        result = frame["result"]
        assert result.get("isError") is False, (name, result)
        return result.get("structuredContent") or {}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _lookup_hits(client: _SupervisorClient, rid: int, query: str, sid: str) -> List[str]:
    """Names of functions whose name contains ``query`` in session ``sid``."""
    structured = client.ok_tool(rid, "lookup_funcs", {"query": query, "database": sid})
    return [m["name"] for m in structured.get("matches", [])]


def test_mergeback_live(tmp_path: Path, capsys, monkeypatch) -> None:
    # Isolate the filesystem discovery registry to this test (adoption defaults on;
    # its reader otherwise sees the machine-global registry). Keeps the supervisor's
    # session set to exactly the workers this test spawns.
    monkeypatch.setenv("IDA_MCP_USER_DIR", str(tmp_path / "idausr"))

    # The "user's original" binary. Every open copies it into a private scratch dir
    # and opens THAT; this file must never be modified.
    original = tmp_path / "tiny.exe"
    original.write_bytes(_FIXTURE.read_bytes())
    original_sha = _sha256(original)

    container = build_supervisor_container(max_workers=8, host="127.0.0.1")
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
        # The merge management tool + the three worker tools of the merge-back.
        assert "idb_merge" in by_name, sorted(by_name)
        for worker_tool in ("export_annotations", "apply_annotations", "idb_snapshot"):
            assert worker_tool in by_name, sorted(by_name)
            props = by_name[worker_tool]["inputSchema"].get("properties", {})
            assert "database" in props, (worker_tool, props)  # routing key injected
        # idb_merge is management: it does NOT gain a database routing key.
        assert "database" not in by_name["idb_merge"]["inputSchema"].get("properties", {})

        # -- open the same binary twice -> two private copies ------------- #
        info_a = client.ok_tool(3, "idb_open", {"input_path": str(original)})
        info_b = client.ok_tool(4, "idb_open", {"input_path": str(original)})
        sid_a, sid_b = info_a["session_id"], info_b["session_id"]
        assert sid_a != sid_b, (sid_a, sid_b)
        assert info_a["private_copy_path"] != info_b["private_copy_path"], (info_a, info_b)

        # -- pick two DIFFERENT functions to edit (same addrs in both copies) - #
        funcs = client.ok_tool(
            5, "export_funcs", {"offset": 0, "count": 200, "database": sid_a}
        )["items"]
        assert len(funcs) >= 2, funcs
        by_func_name = {f["name"]: f["address"] for f in funcs}
        addr_a = by_func_name.get("add_numbers")
        addr_b = by_func_name.get("main")
        if addr_a is None or addr_b is None or addr_a == addr_b:
            # Fallback: any two distinct real functions from the list.
            addr_a = funcs[0]["address"]
            addr_b = next(f["address"] for f in funcs if f["address"] != addr_a)
        assert addr_a != addr_b, (addr_a, addr_b)

        # -- agent A edits its OWN copy: rename + function comment --------- #
        ra = client.ok_tool(
            10, "rename", {"address": addr_a, "name": "agent_a_name", "database": sid_a}
        )
        assert ra["name"] == "agent_a_name" and ra["ok"] is True, ra
        client.ok_tool(
            11,
            "set_comment",
            {
                "address": addr_a,
                "comment": "reversed by agent A",
                "function": True,
                "database": sid_a,
            },
        )

        # -- agent B edits a DIFFERENT function on ITS copy: rename + type -- #
        rb = client.ok_tool(
            12, "rename", {"address": addr_b, "name": "agent_b_name", "database": sid_b}
        )
        assert rb["name"] == "agent_b_name" and rb["ok"] is True, rb
        client.ok_tool(
            13,
            "set_type",
            {"address": addr_b, "type": "int f(int a, int b)", "database": sid_b},
        )

        # -- divergence: each new name lives in exactly one copy pre-merge - #
        assert "agent_a_name" in _lookup_hits(client, 14, "agent_a_name", sid_a)
        assert _lookup_hits(client, 15, "agent_a_name", sid_b) == []
        assert "agent_b_name" in _lookup_hits(client, 16, "agent_b_name", sid_b)
        assert _lookup_hits(client, 17, "agent_b_name", sid_a) == []

        # -- dry-run merge: report the plan, write nothing ---------------- #
        dry = client.ok_tool(
            20,
            "idb_merge",
            {
                "sources": [sid_a, sid_b],
                "into": sid_a,
                "policy": "last",
                "use_baseline": True,
                "dry_run": True,
            },
        )
        assert dry["dry_run"] is True, dry
        assert "ok" not in dry and "snapshot" not in dry, dry
        assert set(dry["sessions"]) == {sid_a, sid_b}, dry
        assert dry["reachable"] == [sid_a, sid_b] or set(dry["reachable"]) == {sid_a, sid_b}
        assert dry["merged_counts"]["conflicts"] == 0, dry  # no false conflicts
        assert dry["merged_counts"]["names"] == 2, dry      # exactly the two edits
        assert dry["merged_counts"]["comments"] >= 1, dry
        assert dry["merged_counts"]["prototypes"] >= 1, dry
        # Each source's OWN pristine baseline (captured at idb_open) was subtracted.
        assert set(dry["baseline_sessions"]) == {sid_a, sid_b}, dry
        assert "baseline_missing" not in dry, dry

        # -- applied merge: consolidate into A + snapshot a canonical .i64 - #
        applied = client.ok_tool(
            21,
            "idb_merge",
            {
                "sources": [sid_a, sid_b],
                "into": sid_a,
                "policy": "last",
                "use_baseline": True,
            },
        )
        assert applied["ok"] is True and applied["dry_run"] is False, applied
        assert applied["into"] == sid_a, applied
        assert applied["merged_counts"]["conflicts"] == 0, applied
        assert applied["applied"]["names"] >= 2, applied
        assert applied["applied"]["comments"] >= 1, applied
        assert applied["applied"]["types"] >= 1, applied
        snap_path = Path(applied["snapshot"]["path"])
        assert snap_path.suffix == ".i64", applied
        assert applied["snapshot"]["size"] > 0, applied
        assert snap_path.is_file(), snap_path
        assert snap_path.stat().st_size == applied["snapshot"]["size"], applied

        # -- PROOF #1: read session A back — BOTH agents' edits are present  #
        a_after = client.ok_tool(
            30, "export_funcs", {"offset": 0, "count": 200, "database": sid_a}
        )["items"]
        a_names = {f["name"] for f in a_after}
        assert "agent_a_name" in a_names, sorted(a_names)
        assert "agent_b_name" in a_names, sorted(a_names)

        # -- PROOF #2: open the produced snapshot .i64 as a fresh session --- #
        info_s = client.ok_tool(31, "idb_open", {"input_path": str(snap_path)})
        sid_s = info_s["session_id"]
        assert sid_s not in (sid_a, sid_b), info_s
        assert "agent_a_name" in _lookup_hits(client, 32, "agent_a_name", sid_s)
        assert "agent_b_name" in _lookup_hits(client, 33, "agent_b_name", sid_s)

        # -- close every session; scratch dirs must be removed ------------- #
        dirs = {sid: session_dir(sid) for sid in (sid_a, sid_b, sid_s)}
        for d in dirs.values():
            assert d.is_dir(), d
        for rid, sid in enumerate((sid_a, sid_b, sid_s), start=40):
            closed = client.ok_tool(rid, "idb_close", {"session_id": sid})
            assert closed == {"session_id": sid, "closed": True}, closed
        # Give the pool a beat to reap, then confirm scratch is gone.
        for sid, d in dirs.items():
            assert not d.exists(), f"scratch dir for {sid} should be removed: {d}"

        # -- the user's original binary is untouched ---------------------- #
        assert original.is_file(), original
        assert _sha256(original) == original_sha, "original bytes must be unchanged"
        # No bare working database was left beside the user's original; only the
        # intended canonical .merged.i64 snapshot sits in the tmp directory.
        assert not original.with_suffix(".i64").exists(), "no bare .i64 next to original"
        assert not original.with_suffix(".idb").exists(), "no .idb next to original"

        evidence = {
            "session_a": sid_a,
            "session_b": sid_b,
            "func_a_addr": addr_a,
            "func_b_addr": addr_b,
            "dry_run_counts": dry["merged_counts"],
            "applied_counts": applied["applied"],
            "applied_merged_counts": applied["merged_counts"],
            "snapshot_path": str(snap_path),
            "snapshot_size": applied["snapshot"]["size"],
            "session_A_names_after_merge": sorted(
                n for n in a_names if n.startswith("agent_")
            ),
            "snapshot_session": sid_s,
            "both_names_in_snapshot": True,
            "original_sha256_stable": _sha256(original) == original_sha,
        }
    finally:
        transport.stop()
        # Always reap every worker the pool spawned, even on assertion failure.
        container.pool.close_all()

    # Surface concrete live evidence (visible under ``pytest -s``).
    with capsys.disabled():
        print("\n=== MERGE-BACK LIVE EVIDENCE ===")
        print(json.dumps(evidence, indent=2))
