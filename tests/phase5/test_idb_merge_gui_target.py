"""A live GUI instance must be able to RECEIVE a merge.

The point of the merge-back is to land a session's parallel work in the database
the operator is actually looking at. Before this, ``MergeOrchestrator`` was built
with the worker pool alone: an adopted (GUI) instance was structurally invisible,
so it could be neither source nor target — and passing its id was *silently
dropped* from the source set, producing a success report for a merge that had
excluded it.

The asymmetry that makes this safe:

* an adopted instance is a fine **target** — a target only receives annotations,
  so it needs no pristine baseline (there is no private copy to subtract);
* it stays a rejected **source** — with no private copy there is no baseline that
  could isolate its edits from auto-analysis, and the error now says so and
  points at ``into``.

Locked in here: adopted target resolution, no ``.merged.i64`` written beside a
database the supervisor does not own, the source rejection message, and the
provenance gate still refusing a cross-binary write into an adopted target.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from idamesh.interface.router.merge import MergeOrchestrator

from tests.phase5.test_idb_merge import (
    APPLY,
    SNAPSHOT,
    FakeEndpoint,
    FakeHub,
    FakeSession,
    FakeWorkerClient,
    FakeWorkerPool,
    _wire,
)

OTHER_SHA = "b" * 64


class FakeDiscovery:
    """A ``GuiDiscoveryPort`` stand-in holding adopted (GUI) instances."""

    def __init__(self, hub: FakeHub) -> None:
        self._hub = hub
        self._sessions: Dict[str, FakeSession] = {}
        self._port = 49001

    def add(self, session_id: str, endpoint: FakeEndpoint, **kw: Any) -> FakeSession:
        self._port += 1
        # An adopted instance owns its database: no private copy, and the
        # registry surfaces no input_path we could derive a snapshot path from.
        session = FakeSession(session_id, "127.0.0.1", self._port, input_path="", **kw)
        self._sessions[session_id] = session
        self._hub.register(self._port, endpoint)
        return session

    def list_sessions(self) -> Sequence[FakeSession]:
        return list(self._sessions.values())

    def get(self, session_id: str) -> Optional[FakeSession]:
        return self._sessions.get(session_id)


class GuiEnv:
    """A worker source plus an adopted GUI instance wired into one orchestrator."""

    def __init__(self, *, gui_export: Optional[Dict[str, Any]] = None) -> None:
        self.hub = FakeHub()
        self.pool = FakeWorkerPool(self.hub)
        self.discovery = FakeDiscovery(self.hub)
        self.client = FakeWorkerClient(self.hub)
        self.orch = MergeOrchestrator(
            pool=self.pool, client=self.client, discovery=self.discovery
        )
        baseline = _wire(names={0x400500: "sub_400500"})
        self.worker_endpoint = FakeEndpoint(
            export=_wire(names={0x400500: "sub_400500", 0x401000: "parse_hdr"}),
            apply_result={"applied": {"names": 1, "comments": 0, "types": 0},
                          "ok": True, "failures": []},
        )
        self.pool.add_source("sess-1", self.worker_endpoint, baseline_record=baseline)
        self.gui_endpoint = FakeEndpoint(
            export=gui_export if gui_export is not None else _wire(),
            apply_result={"applied": {"names": 1, "comments": 0, "types": 0},
                          "ok": True, "failures": []},
        )
        self.discovery.add("gui-idb-d80db6", self.gui_endpoint)


def test_adopted_gui_instance_can_receive_the_merge():
    env = GuiEnv()

    report = env.orch.merge(
        {"sources": ["sess-1"], "into": "gui-idb-d80db6", "policy": "last"}
    )

    assert "error" not in report, report
    assert report["into"] == "gui-idb-d80db6"
    assert report["applied"]["names"] == 1
    # The edit was written into the GUI, not into the worker copy.
    assert len(env.gui_endpoint.calls_named(APPLY)) == 1
    assert env.worker_endpoint.calls_named(APPLY) == []
    applied_record = env.gui_endpoint.calls_named(APPLY)[0]["arguments"]["record"]
    assert [n["name"] for n in applied_record["names"]] == ["parse_hdr"]


def test_no_snapshot_is_written_beside_a_database_we_do_not_own():
    env = GuiEnv()

    report = env.orch.merge(
        {"sources": ["sess-1"], "into": "gui-idb-d80db6", "policy": "last"}
    )

    assert env.gui_endpoint.calls_named(SNAPSHOT) == []
    assert "skipped" in report["snapshot"], report["snapshot"]
    assert "path" not in report["snapshot"]


def test_adopted_instance_is_still_rejected_as_a_source_and_points_at_into():
    env = GuiEnv()

    report = env.orch.merge(
        {"sources": ["sess-1", "gui-idb-d80db6"], "dry_run": True}
    )

    assert "error" in report, report
    assert "gui-idb-d80db6" in report["error"]
    assert "into" in report["error"]


def test_provenance_gate_still_refuses_a_cross_binary_write_into_the_gui():
    """The adopted target is not exempt from the safety that matters."""
    env = GuiEnv(gui_export=_wire(sha=OTHER_SHA))

    report = env.orch.merge(
        {"sources": ["sess-1"], "into": "gui-idb-d80db6", "policy": "last"}
    )

    assert "error" in report, report
    assert "refus" in report["error"].lower()
    assert env.gui_endpoint.calls_named(APPLY) == []


def test_worker_target_still_snapshots_as_before():
    """The adopted-target branch must not change behaviour for owned workers."""
    env = GuiEnv()

    report = env.orch.merge({"sources": ["sess-1"], "policy": "last"})

    assert "error" not in report, report
    assert report["into"] == "sess-1"
    assert len(env.worker_endpoint.calls_named(SNAPSHOT)) == 1
    assert report["snapshot"]["path"].endswith(".merged.i64")
