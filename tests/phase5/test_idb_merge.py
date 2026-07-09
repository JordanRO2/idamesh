"""Unit tests for the supervisor-side ``idb_merge`` orchestration (idapro-free).

These drive the real
:class:`~idamesh.interface.router.merge.MergeOrchestrator` against a *fake* worker
pool and a *fake* worker client — no processes, no HTTP, no idalib. The fakes
satisfy the interface-local ports (:class:`WorkerPoolPort` / :class:`WorkerClientPort`
/ :class:`SessionView`) structurally and speak the frozen annotation wire shape, so
the whole merge-back pipeline runs end to end in-memory:

    resolve sources -> export(each) -> subtract each source's own pristine baseline
        -> reconcile(policy) -> dry_run report | apply(into) + snapshot -> applied

Locked in here:

* source resolution by ``path`` and by explicit ``sources`` ids;
* ``export_annotations`` fanned out to every source, wire records parsed;
* each source subtracted against ITS OWN pristine baseline (captured at idb_open
  and stored on the session) — the merge opens/reaps no worker of its own;
* two independently-analyzed copies that DISAGREE on an auto-analysis name still
  merge to exactly their disjoint edits with zero false conflicts (the regression);
* a source missing a baseline refuses the merge (``error`` + ``baseline_missing``)
  rather than merge its raw auto-analysis as edits;
* the pure :func:`reconcile` invoked with the exported records + per-source
  baselines + chosen policy;
* ``dry_run`` reports the plan/conflicts and writes nothing (no apply/snapshot);
* an applied merge writes into the right session (default first source / explicit
  ``into``) via ``apply_annotations`` + ``idb_snapshot`` at the canonical path;
* ``manual`` policy refuses a write while unresolved conflicts remain (structured
  error), and a provenance mismatch is refused;
* unreachable sources are reported and the merge proceeds on the rest;
* ``use_baseline=false`` disables baseline subtraction entirely;
* malformed arguments (bad policy, neither sources nor path) are rejected.
"""

from __future__ import annotations

import itertools
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import pytest

from idamesh.application.annotation_wire import annotation_record_from_wire
from idamesh.domain.services.reconciliation import ConflictPolicy
from idamesh.interface.router import merge as merge_module
from idamesh.interface.router.merge import MergeOrchestrator

SHA = "a" * 64
IMAGEBASE = 0x400000
INPUT_PATH = "/scratch/copy/target.exe"
CANONICAL_SNAPSHOT = "/scratch/copy/target.merged.i64"

# Tool names the orchestrator drives over the client (mirrors merge.py constants).
EXPORT = "export_annotations"
APPLY = "apply_annotations"
SNAPSHOT = "idb_snapshot"


# --------------------------------------------------------------------------- #
# Wire builders (the frozen AnnotationRecord JSON projection)
# --------------------------------------------------------------------------- #


def _provenance_wire(
    *, sha: Optional[str] = SHA, imagebase: Optional[int] = IMAGEBASE
) -> Dict[str, Any]:
    return {
        "input_path": INPUT_PATH,
        "input_sha256": sha,
        "imagebase": imagebase,
        "ida_version": "9.0",
    }


def _wire(
    *,
    names: Optional[Mapping[int, str]] = None,
    comments: Optional[Mapping[Tuple[int, str], Tuple[str, str]]] = None,
    prototypes: Optional[Mapping[int, str]] = None,
    sha: Optional[str] = SHA,
    imagebase: Optional[int] = IMAGEBASE,
) -> Dict[str, Any]:
    """Build one worker's ``export_annotations`` payload in the frozen wire shape."""
    return {
        "provenance": _provenance_wire(sha=sha, imagebase=imagebase),
        "names": [
            {"ea": ea, "name": name} for ea, name in (names or {}).items()
        ],
        "comments": [
            {"ea": ea, "scope": scope, "regular": regular, "repeatable": repeatable}
            for (ea, scope), (regular, repeatable) in (comments or {}).items()
        ],
        "prototypes": [
            {"ea": ea, "type": decl} for ea, decl in (prototypes or {}).items()
        ],
    }


def _names_of(record_wire: Mapping[str, Any]) -> Dict[int, str]:
    """Collapse a wire record's ``names`` list back into an ``{ea: name}`` map."""
    parsed = annotation_record_from_wire(record_wire)
    return dict(parsed.names)


def _ok_response(rid: Any, structured: Mapping[str, Any]) -> Dict[str, Any]:
    """A worker JSON-RPC success frame carrying ``structuredContent``."""
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "result": {
            "content": [{"type": "text", "text": "ok"}],
            "structuredContent": dict(structured),
            "isError": False,
        },
    }


def _error_response(rid: Any) -> Dict[str, Any]:
    """A worker tool-level failure frame (``isError``) — the export is unreachable."""
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "result": {
            "content": [{"type": "text", "text": "boom"}],
            "isError": True,
        },
    }


# --------------------------------------------------------------------------- #
# Fakes: one worker endpoint + a hub keyed by port
# --------------------------------------------------------------------------- #


class FakeEndpoint:
    """One fake worker: canned export/apply/snapshot results, recording every call."""

    def __init__(
        self,
        *,
        export: Optional[Mapping[str, Any]] = None,
        apply_result: Optional[Mapping[str, Any]] = None,
        snapshot_size: int = 4096,
        export_error: bool = False,
        apply_error: bool = False,
        snapshot_error: bool = False,
    ) -> None:
        self.export = dict(export) if export is not None else _wire()
        self.apply_result = (
            dict(apply_result)
            if apply_result is not None
            else {"applied": {"names": 0, "comments": 0, "types": 0},
                  "ok": True, "failures": []}
        )
        self.snapshot_size = snapshot_size
        self.export_error = export_error
        self.apply_error = apply_error
        self.snapshot_error = snapshot_error
        self.calls: List[Dict[str, Any]] = []

    def _record(self, frame: Mapping[str, Any]) -> Tuple[Any, str, Dict[str, Any]]:
        params = frame.get("params") or {}
        name = params.get("name")
        args = dict(params.get("arguments") or {})
        self.calls.append({"name": name, "arguments": args, "frame": dict(frame)})
        return frame.get("id"), name, args

    def calls_named(self, name: str) -> List[Dict[str, Any]]:
        return [c for c in self.calls if c["name"] == name]

    def handle(self, frame: Mapping[str, Any]) -> Dict[str, Any]:
        rid, name, args = self._record(frame)
        if name == EXPORT:
            if self.export_error:
                return _error_response(rid)
            return _ok_response(rid, self.export)
        if name == APPLY:
            if self.apply_error:
                return _error_response(rid)
            return _ok_response(rid, self.apply_result)
        if name == SNAPSHOT:
            if self.snapshot_error:
                return _error_response(rid)
            path = str(args.get("path", ""))
            return _ok_response(rid, {"path": path, "size": self.snapshot_size, "ok": True})
        raise AssertionError(f"unexpected worker tool {name!r}")


class FakeHub:
    """Port-addressed registry the fake pool populates and the fake client reads."""

    def __init__(self) -> None:
        self.by_port: Dict[int, FakeEndpoint] = {}

    def register(self, port: int, endpoint: FakeEndpoint) -> FakeEndpoint:
        self.by_port[port] = endpoint
        return endpoint


class FakeWorkerClient:
    """A ``WorkerClientPort`` stand-in dispatching frames to the hub by port."""

    def __init__(self, hub: FakeHub) -> None:
        self._hub = hub
        self.forwards: List[Dict[str, Any]] = []

    def forward(
        self,
        *,
        host: str,
        port: int,
        frame: Mapping[str, Any],
        token: Optional[str] = None,
    ) -> Optional[Mapping[str, Any]]:
        self.forwards.append({"host": host, "port": port, "frame": dict(frame), "token": token})
        endpoint = self._hub.by_port.get(port)
        if endpoint is None:
            raise ConnectionRefusedError(f"no endpoint at {host}:{port}")
        return endpoint.handle(frame)

    def ping(self, *, host: str, port: int, token: Optional[str] = None) -> bool:
        return port in self._hub.by_port


# --------------------------------------------------------------------------- #
# Fakes: session + worker pool
# --------------------------------------------------------------------------- #


class FakeSession:
    """A routing record satisfying ``SessionView``.

    Carries a ``baseline_record`` — the pristine annotation wire the supervisor
    captures in-process at ``idb_open`` — exactly as a real ``WorkerSession`` does,
    so the per-source baseline subtraction can be exercised without any process.
    """

    def __init__(
        self,
        session_id: str,
        host: str,
        port: int,
        *,
        input_path: str = INPUT_PATH,
        token: Optional[str] = None,
        baseline_record: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.session_id = session_id
        self.host = host
        self.port = port
        self.token = token
        self.input_path = input_path
        self.baseline_record = baseline_record
        self.touched = 0

    def touch(self) -> None:
        self.touched += 1

    def to_info(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "input_path": self.input_path,
            "filename": self.input_path.rsplit("/", 1)[-1],
        }


class FakeWorkerPool:
    """A ``WorkerPoolPort`` stand-in holding the parallel source sessions.

    The merge never opens or reaps a worker anymore (per-session baselines are
    captured at ``idb_open`` and stored on the session), so ``open_calls`` /
    ``close_calls`` staying empty is itself an assertion the tests make.
    """

    def __init__(self, hub: FakeHub) -> None:
        self._hub = hub
        self._sources: Dict[str, FakeSession] = {}
        self._port_seq = itertools.count(48001)
        self.open_calls: List[Tuple[str, Optional[str]]] = []
        self.close_calls: List[str] = []
        self.open_error: Optional[Exception] = None

    # -- test wiring ------------------------------------------------------- #

    def add_source(
        self,
        session_id: str,
        endpoint: FakeEndpoint,
        *,
        token: Optional[str] = None,
        baseline_record: Optional[Mapping[str, Any]] = None,
    ) -> FakeSession:
        port = next(self._port_seq)
        session = FakeSession(
            session_id, "127.0.0.1", port, token=token, baseline_record=baseline_record
        )
        self._sources[session_id] = session
        self._hub.register(port, endpoint)
        return session

    # -- WorkerPoolPort ---------------------------------------------------- #

    def open_session(
        self, input_path: str, *, preferred_session_id: Optional[str] = None
    ) -> FakeSession:
        # Recorded so tests can assert the merge NEVER spawns a baseline worker.
        self.open_calls.append((input_path, preferred_session_id))
        if self.open_error is not None:
            raise self.open_error
        raise AssertionError(
            "merge must not open any worker: baselines are per-session, captured "
            "at idb_open and stored on the session"
        )

    def list_sessions(self) -> List[FakeSession]:
        return list(self._sources.values())

    def get(self, session_id: str) -> Optional[FakeSession]:
        return self._sources.get(session_id)

    def close_session(self, session_id: str) -> bool:
        self.close_calls.append(session_id)
        return self._sources.pop(session_id, None) is not None

    def reap(self) -> List[str]:
        return []


# --------------------------------------------------------------------------- #
# Scenario builder
# --------------------------------------------------------------------------- #


class Env:
    def __init__(self) -> None:
        self.hub = FakeHub()
        self.pool = FakeWorkerPool(self.hub)
        self.client = FakeWorkerClient(self.hub)
        self.orch = MergeOrchestrator(pool=self.pool, client=self.client)
        self.endpoints: Dict[str, FakeEndpoint] = {}
        #: Per-session pristine baseline handed to sources added without an explicit
        #: one (mirrors the record captured in-process at idb_open before any edit).
        self._default_baseline: Optional[Mapping[str, Any]] = None

    def add_source(
        self,
        session_id: str,
        endpoint: FakeEndpoint,
        *,
        token: Optional[str] = None,
        baseline: Optional[Mapping[str, Any]] = None,
    ) -> FakeEndpoint:
        record = baseline if baseline is not None else self._default_baseline
        self.pool.add_source(
            session_id, endpoint, token=token, baseline_record=record
        )
        self.endpoints[session_id] = endpoint
        return endpoint

    def baseline(self, wire: Mapping[str, Any]) -> None:
        """Set the pristine baseline every subsequently-added source carries."""
        self._default_baseline = wire


def _conflicting_env(
    *,
    apply_result: Optional[Mapping[str, Any]] = None,
) -> Env:
    """Two copies that agree on one name + one comment but clash at 0x402000.

    Each copy carries its OWN pristine baseline holding the loader name at 0x400500
    that both copies still export, so it is subtracted per-source rather than merged
    as an edit.
    """
    env = Env()
    env.baseline(_wire(names={0x400500: "sub_400500"}))
    env.add_source(
        "sess-1",
        FakeEndpoint(
            export=_wire(
                names={0x400500: "sub_400500", 0x401000: "parse_hdr", 0x402000: "from_a"},
                comments={(0x401000, "func"): ("parses the header", "")},
            ),
            apply_result=apply_result,
        ),
    )
    env.add_source(
        "sess-2",
        FakeEndpoint(
            export=_wire(
                names={0x400500: "sub_400500", 0x402000: "from_b"},
                comments={(0x401000, "func"): ("parses the header", "")},
            ),
            apply_result=apply_result,
        ),
    )
    return env


# --------------------------------------------------------------------------- #
# dry-run: report the plan + conflicts, write nothing, reap the baseline
# --------------------------------------------------------------------------- #


def test_dry_run_reports_plan_and_conflicts_without_writing():
    env = _conflicting_env()

    result = env.orch.merge({"path": INPUT_PATH, "dry_run": True})

    assert result["dry_run"] is True
    # A dry-run never carries the applied-merge keys.
    assert "ok" not in result and "applied" not in result and "snapshot" not in result

    assert result["sessions"] == ["sess-1", "sess-2"]
    assert result["reachable"] == ["sess-1", "sess-2"]
    assert result["unreachable"] == []

    # 0x400500 (== baseline) subtracted; 0x401000 auto-resolves; 0x402000 conflicts.
    assert result["merged_counts"]["names"] == 1
    assert result["merged_counts"]["comments"] == 1
    assert result["merged_counts"]["conflicts"] == 1

    conflicts = result["conflicts"]
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict["field"] == "names"
    assert conflict["ea"] == 0x402000
    assert conflict["candidates"] == {"sess-1": "from_a", "sess-2": "from_b"}
    assert conflict["resolved"] is None  # manual leaves it for review

    # Nothing was applied or snapshotted on either source.
    for endpoint in env.endpoints.values():
        assert endpoint.calls_named(APPLY) == []
        assert endpoint.calls_named(SNAPSHOT) == []


def test_merge_uses_per_session_baselines_and_opens_no_worker():
    env = _conflicting_env()

    result = env.orch.merge({"path": INPUT_PATH, "dry_run": True, "use_baseline": True})

    # No throwaway baseline copy is ever opened or reaped: each source is subtracted
    # against its OWN pristine baseline captured at idb_open and stored on it.
    assert env.pool.open_calls == []
    assert env.pool.close_calls == []
    # Both sources contributed a per-session baseline; none were missing.
    assert result["baseline_sessions"] == ["sess-1", "sess-2"]
    assert "baseline_missing" not in result
    # The old single-baseline-session key is gone.
    assert "baseline_session" not in result


def test_source_without_a_captured_baseline_refuses_the_merge():
    # A source that never captured a baseline (e.g. capture export failed even after
    # retries) cannot have its real edits isolated. A use_baseline merge REFUSES
    # rather than merge that copy's raw auto-analysis as if it were edits — the exact
    # non-determinism the per-session-baseline design removes.
    env = Env()
    env.add_source(
        "sess-1",
        FakeEndpoint(export=_wire(names={0x400500: "sub_400500", 0x401000: "edit_a"})),
        baseline=_wire(names={0x400500: "sub_400500"}),
    )
    env.add_source(
        "sess-2",
        FakeEndpoint(export=_wire(names={0x400500: "sub_400500", 0x402000: "edit_b"})),
        baseline=None,  # no baseline captured
    )

    result = env.orch.merge({"path": INPUT_PATH, "dry_run": True, "policy": "manual"})

    assert "error" in result, result
    assert result.get("dry_run") is not True  # refused before the dry-run preview
    assert result["baseline_missing"] == ["sess-2"]
    assert result["baseline_sessions"] == ["sess-1"]


def test_baseline_subtraction_is_visible_in_the_merge():
    # Without subtraction the shared loader name at 0x400500 would agree and count
    # as a merged name; the baseline drops it, leaving only the genuine edit.
    env = _conflicting_env()
    result = env.orch.merge(
        {"path": INPUT_PATH, "dry_run": True, "policy": "last"}
    )
    assert result["merged_counts"]["names"] == 2  # parse_hdr + resolved 0x402000
    # 0x400500 never appears as a merged name because it equals the baseline.


# --------------------------------------------------------------------------- #
# reconcile is the domain engine the orchestrator drives
# --------------------------------------------------------------------------- #


def test_reconcile_is_invoked_with_exported_records_and_policy(monkeypatch):
    env = _conflicting_env()
    captured: Dict[str, Any] = {}
    real_reconcile = merge_module.reconcile

    def spy(records: Sequence[Any], **kwargs: Any):
        captured["records"] = list(records)
        captured["kwargs"] = dict(kwargs)
        return real_reconcile(records, **kwargs)

    monkeypatch.setattr(merge_module, "reconcile", spy)

    env.orch.merge({"path": INPUT_PATH, "dry_run": True, "policy": "last"})

    assert captured, "reconcile was never called"
    session_ids = [sid for sid, _record in captured["records"]]
    assert session_ids == ["sess-1", "sess-2"]
    assert captured["kwargs"]["policy"] is ConflictPolicy.LAST
    # Reconcile is driven with the per-source pristine baselines (keyed by session
    # id), not a single shared baseline.
    baselines = captured["kwargs"]["baselines"]
    assert baselines is not None
    assert set(baselines) == {"sess-1", "sess-2"}


# --------------------------------------------------------------------------- #
# applied merge: write into the target + snapshot the canonical .i64
# --------------------------------------------------------------------------- #


def test_apply_writes_into_first_source_and_snapshots_canonical_path():
    applied_counts = {"names": 2, "comments": 1, "types": 0}
    env = _conflicting_env(
        apply_result={"applied": applied_counts, "ok": True, "failures": []}
    )

    result = env.orch.merge({"path": INPUT_PATH, "policy": "last"})

    assert result["ok"] is True
    assert result["dry_run"] is False
    assert result["into"] == "sess-1"  # default target = first resolved source
    assert result["applied"] == applied_counts
    assert result["snapshot"] == {"path": CANONICAL_SNAPSHOT, "size": 4096}

    target = env.endpoints["sess-1"]
    other = env.endpoints["sess-2"]

    # The merged record was applied to sess-1 only.
    apply_calls = target.calls_named(APPLY)
    assert len(apply_calls) == 1
    assert other.calls_named(APPLY) == []

    # 'last' resolved 0x402000 to sess-2's value; parse_hdr survives; baseline gone.
    record_wire = apply_calls[0]["arguments"]["record"]
    assert _names_of(record_wire) == {0x401000: "parse_hdr", 0x402000: "from_b"}

    # And the canonical snapshot path was requested on the same session.
    snap_calls = target.calls_named(SNAPSHOT)
    assert len(snap_calls) == 1
    assert snap_calls[0]["arguments"]["path"] == CANONICAL_SNAPSHOT
    assert other.calls_named(SNAPSHOT) == []


def test_apply_targets_explicit_into_session():
    env = _conflicting_env()

    result = env.orch.merge(
        {"path": INPUT_PATH, "policy": "first", "into": "sess-2"}
    )

    assert result["into"] == "sess-2"
    assert env.endpoints["sess-2"].calls_named(APPLY)
    assert env.endpoints["sess-2"].calls_named(SNAPSHOT)
    assert env.endpoints["sess-1"].calls_named(APPLY) == []

    # 'first' resolved 0x402000 to sess-1's value.
    record_wire = env.endpoints["sess-2"].calls_named(APPLY)[0]["arguments"]["record"]
    assert _names_of(record_wire) == {0x401000: "parse_hdr", 0x402000: "from_a"}


def test_explicit_sources_resolve_and_apply_in_order():
    env = _conflicting_env()

    result = env.orch.merge({"sources": ["sess-2", "sess-1"], "policy": "first"})

    # sources order wins: sess-2 first => target sess-2, 'first' picks sess-2's value.
    assert result["sessions"] == ["sess-2", "sess-1"]
    assert result["into"] == "sess-2"
    record_wire = env.endpoints["sess-2"].calls_named(APPLY)[0]["arguments"]["record"]
    assert _names_of(record_wire)[0x402000] == "from_b"


# --------------------------------------------------------------------------- #
# refusals: manual-policy conflicts and provenance mismatch write nothing
# --------------------------------------------------------------------------- #


def test_manual_policy_refuses_write_while_conflicts_unresolved():
    env = _conflicting_env()

    result = env.orch.merge({"path": INPUT_PATH, "policy": "manual"})

    assert "error" in result
    assert "manual" in result["error"]
    # The unresolved conflict is surfaced in the refusal body...
    assert result["conflicts"][0]["ea"] == 0x402000
    assert result["sessions"] == ["sess-1", "sess-2"]
    # ...and absolutely nothing was written.
    for endpoint in env.endpoints.values():
        assert endpoint.calls_named(APPLY) == []
        assert endpoint.calls_named(SNAPSHOT) == []


def test_provenance_mismatch_is_refused_without_writing():
    env = Env()
    env.baseline(_wire(names={}))
    env.add_source("sess-1", FakeEndpoint(export=_wire(names={0x401000: "a"}, sha="a" * 64)))
    env.add_source("sess-2", FakeEndpoint(export=_wire(names={0x401000: "b"}, sha="b" * 64)))

    result = env.orch.merge({"path": INPUT_PATH, "policy": "last"})

    assert "error" in result
    assert result["sessions"] == ["sess-1", "sess-2"]
    assert result["reachable"] == ["sess-1", "sess-2"]
    for endpoint in env.endpoints.values():
        assert endpoint.calls_named(APPLY) == []
        assert endpoint.calls_named(SNAPSHOT) == []


# --------------------------------------------------------------------------- #
# write-target provenance gate (cross-binary corruption guard)
# --------------------------------------------------------------------------- #


def test_into_target_of_a_different_binary_is_refused_without_writing():
    # sess-1/sess-2 agree on sha "a"*64. 'into' names a SEPARATE open session that
    # is a copy of a DIFFERENT binary (sha "b"*64) and is NOT one of the sources.
    # Writing EA-keyed annotations into it would be silent corruption -> refuse.
    env = _conflicting_env()
    env.add_source(
        "sess-evil",
        FakeEndpoint(export=_wire(names={0x401000: "x"}, sha="b" * 64)),
    )

    result = env.orch.merge(
        {"sources": ["sess-1", "sess-2"], "policy": "last", "into": "sess-evil"}
    )

    assert "error" in result
    assert "sess-evil" in result["error"]
    assert result.get("ok") is None  # no applied-success payload
    # The bad target's provenance was consulted (export), but NOTHING was written
    # into any session — not even the mismatched target.
    assert env.endpoints["sess-evil"].calls_named(EXPORT)
    for endpoint in env.endpoints.values():
        assert endpoint.calls_named(APPLY) == []
        assert endpoint.calls_named(SNAPSHOT) == []


def test_into_target_matching_provenance_proceeds():
    # A separate open session for the SAME binary (sha matches the sources) is a
    # valid explicit target even though it never participated as a source.
    env = _conflicting_env()
    env.add_source(
        "sess-3",
        FakeEndpoint(
            export=_wire(names={0x401000: "parse_hdr"}, sha="a" * 64),
            apply_result={"applied": {"names": 2, "comments": 1, "types": 0},
                          "ok": True, "failures": []},
        ),
    )

    result = env.orch.merge(
        {"sources": ["sess-1", "sess-2"], "policy": "last", "into": "sess-3"}
    )

    assert result["ok"] is True
    assert result["into"] == "sess-3"
    assert env.endpoints["sess-3"].calls_named(APPLY)
    assert env.endpoints["sess-3"].calls_named(SNAPSHOT)
    # The sources were only exported, never written into.
    assert env.endpoints["sess-1"].calls_named(APPLY) == []
    assert env.endpoints["sess-2"].calls_named(APPLY) == []


# --------------------------------------------------------------------------- #
# apply outcome: worker failures + ok are surfaced (never silently "successful")
# --------------------------------------------------------------------------- #


def test_worker_apply_failures_are_surfaced_and_ok_reflects_them():
    failures = [{"ea": 0x402000, "field": "names", "error": "read-only segment"}]
    env = _conflicting_env(
        apply_result={"applied": {"names": 1, "comments": 1, "types": 0},
                      "ok": False, "failures": failures}
    )

    result = env.orch.merge({"path": INPUT_PATH, "policy": "last"})

    assert result["dry_run"] is False
    assert result["ok"] is False              # not silently successful
    assert result["failures"] == failures     # the worker's real failures surfaced
    assert result["applied"] == {"names": 1, "comments": 1, "types": 0}

    # Defensive: even an ok:true worker that still reports failures is not "ok".
    env2 = _conflicting_env(
        apply_result={"applied": {"names": 1, "comments": 0, "types": 0},
                      "ok": True, "failures": [{"ea": 0x402000, "error": "x"}]}
    )
    result2 = env2.orch.merge({"path": INPUT_PATH, "policy": "last"})
    assert result2["ok"] is False
    assert result2["failures"]


# --------------------------------------------------------------------------- #
# write-step failures become structured refusals, never unhandled exceptions
# --------------------------------------------------------------------------- #


def test_apply_transport_error_yields_structured_error_not_exception():
    env = _conflicting_env()
    env.endpoints["sess-1"].apply_error = True  # target = first source = sess-1

    result = env.orch.merge({"path": INPUT_PATH, "policy": "last"})

    assert "error" in result
    assert result.get("ok") is None
    assert result["sessions"] == ["sess-1", "sess-2"]
    # The apply raised; the snapshot never ran.
    assert env.endpoints["sess-1"].calls_named(SNAPSHOT) == []


def test_snapshot_transport_error_yields_structured_error_not_exception():
    env = _conflicting_env()
    env.endpoints["sess-1"].snapshot_error = True

    result = env.orch.merge({"path": INPUT_PATH, "policy": "last"})

    assert "error" in result
    assert result.get("ok") is None
    assert result["sessions"] == ["sess-1", "sess-2"]
    # The apply happened; the snapshot raised and was caught into a refusal.
    assert env.endpoints["sess-1"].calls_named(APPLY)


# --------------------------------------------------------------------------- #
# reachability + baseline toggles
# --------------------------------------------------------------------------- #


def test_unreachable_source_is_reported_and_merge_proceeds_on_the_rest():
    env = Env()
    env.baseline(_wire(names={}))
    env.add_source("sess-1", FakeEndpoint(export=_wire(names={0x401000: "kept"})))
    env.add_source("sess-2", FakeEndpoint(export_error=True))

    result = env.orch.merge({"path": INPUT_PATH, "dry_run": True})

    assert result["reachable"] == ["sess-1"]
    assert result["unreachable"] == ["sess-2"]
    # The reachable copy still contributes its edit.
    assert result["merged_counts"]["names"] == 1
    assert result["merged_counts"]["conflicts"] == 0


def test_use_baseline_false_skips_the_pristine_copy():
    env = _conflicting_env()

    result = env.orch.merge(
        {"path": INPUT_PATH, "dry_run": True, "use_baseline": False}
    )

    assert env.pool.open_calls == []  # no worker opened
    assert env.pool.close_calls == []
    assert "baseline_sessions" not in result  # subtraction disabled
    assert "baseline_missing" not in result
    # Without subtraction the loader name at 0x400500 now agrees and merges.
    assert result["merged_counts"]["names"] == 2  # 0x400500 + 0x401000


def test_diverging_autoanalysis_disjoint_edits_merge_without_false_conflicts():
    """The exact regression the per-session baseline fixes.

    Two independently-analyzed copies DISAGREE on an auto-analysis name at 0x400600
    (copy A calls it ``sub_400600_A``, copy B ``sub_400600_B`` — real idalib
    non-determinism across processes). Their genuine edits are disjoint (A edits
    0x401000, B edits 0x402000). Because each copy is subtracted against ITS OWN
    pristine baseline, the divergent auto-name is removed on both sides and never
    reaches reconcile — the merge is exactly the two edits, zero conflicts.
    """
    env = Env()
    env.add_source(
        "sess-1",
        FakeEndpoint(
            export=_wire(
                names={0x400500: "sub_400500", 0x400600: "sub_400600_A", 0x401000: "edit_a"}
            )
        ),
        baseline=_wire(names={0x400500: "sub_400500", 0x400600: "sub_400600_A"}),
    )
    env.add_source(
        "sess-2",
        FakeEndpoint(
            export=_wire(
                names={0x400500: "sub_400500", 0x400600: "sub_400600_B", 0x402000: "edit_b"}
            )
        ),
        baseline=_wire(names={0x400500: "sub_400500", 0x400600: "sub_400600_B"}),
    )

    result = env.orch.merge({"path": INPUT_PATH, "dry_run": True, "policy": "manual"})

    assert result["baseline_sessions"] == ["sess-1", "sess-2"]
    assert result["merged_counts"]["names"] == 2  # exactly edit_a + edit_b
    assert result["merged_counts"]["conflicts"] == 0  # the divergent auto-name is gone
    eas = {c["ea"] for c in result["conflicts"]}
    assert 0x400600 not in eas

    # Contrast: a SINGLE shared baseline (copy A's) leaves copy B's divergent
    # 0x400600 auto-name unsubtracted, so it leaks — proving why per-source matters.
    from idamesh.application.annotation_wire import annotation_record_from_wire
    from idamesh.domain.services.reconciliation import ConflictPolicy as _CP
    from idamesh.domain.services.reconciliation import reconcile as _reconcile

    rec_a = annotation_record_from_wire(
        _wire(names={0x400500: "sub_400500", 0x400600: "sub_400600_A", 0x401000: "edit_a"})
    )
    rec_b = annotation_record_from_wire(
        _wire(names={0x400500: "sub_400500", 0x400600: "sub_400600_B", 0x402000: "edit_b"})
    )
    shared = annotation_record_from_wire(
        _wire(names={0x400500: "sub_400500", 0x400600: "sub_400600_A"})
    )
    leaked = _reconcile(
        [("sess-1", rec_a), ("sess-2", rec_b)], baseline=shared, policy=_CP.MANUAL
    )
    # 0x400600 survives only on copy B (a false edit) — a name the fix eliminates.
    assert 0x400600 in leaked.names


# --------------------------------------------------------------------------- #
# no sessions + argument validation
# --------------------------------------------------------------------------- #


def test_no_live_sessions_is_a_structured_error():
    env = Env()
    result = env.orch.merge({"path": INPUT_PATH})
    assert "error" in result
    assert result["sessions"] == []
    assert result["reachable"] == [] and result["unreachable"] == []
    assert env.pool.open_calls == []  # never bothered opening a baseline


def test_unknown_policy_is_rejected():
    env = _conflicting_env()
    result = env.orch.merge({"path": INPUT_PATH, "policy": "bogus"})
    assert "error" in result
    assert "policy" in result["error"]


def test_missing_sources_and_path_is_rejected():
    env = _conflicting_env()
    result = env.orch.merge({})
    assert "error" in result
    for endpoint in env.endpoints.values():
        assert endpoint.calls == []
