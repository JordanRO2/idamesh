"""Unit tests for the filesystem instance registry (idapro-free).

The whole registry is exercised against a temp directory with the liveness probe
faked, so no real process/port is needed. Locked in: an atomic round-trip, the
oldest-first ordering, self-healing (corrupt JSON, missing keys and a dead pid are pruned;
with a port_check an unreachable endpoint is only hidden, never unlinked), removal by port and by
session id, and the GUI-adoption reader's backend filtering + session lookup.
"""

from __future__ import annotations

import json

import pytest

from idamesh.infrastructure.discovery import (
    BACKEND_GUI,
    BACKEND_WORKER,
    DiscoveredSession,
    DiscoveryEntry,
    DiscoveryRegistry,
    GuiDiscoveryReader,
    ida_user_dir,
    registry_dir,
)


@pytest.fixture
def reg_dir(tmp_path):
    return tmp_path / "instances"


def _entry(session_id="gui-a", *, port=13337, backend=BACKEND_GUI, pid=4321, **kw):
    return DiscoveryEntry(
        session_id=session_id,
        backend=backend,
        host="127.0.0.1",
        port=port,
        token=kw.get("token", "tok-" + session_id),
        pid=pid,
        binary=kw.get("binary", "target.exe"),
        idb_path=kw.get("idb_path", "C:/bins/target.exe"),
        started_at=kw.get("started_at"),
    )


# --------------------------------------------------------------------------- #
# round-trip
# --------------------------------------------------------------------------- #


def test_write_then_read_round_trips(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    path = reg.write(_entry("gui-target-1"))

    assert path.name == "instance_13337.json"
    entries = reg.read_all()
    assert len(entries) == 1
    got = entries[0]
    assert got.session_id == "gui-target-1"
    assert got.backend == "gui"
    assert got.host == "127.0.0.1"
    assert got.port == 13337
    assert got.token == "tok-gui-target-1"
    assert got.pid == 4321
    assert got.binary == "target.exe"


def test_write_is_atomic_no_tmp_left(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    reg.write(_entry("gui-a"))
    leftover = list(reg_dir.glob("*.tmp"))
    assert leftover == []


def test_find_by_session(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    reg.write(_entry("gui-a", port=1000))
    reg.write(_entry("gui-b", port=1001))

    found = reg.find_by_session("gui-b")
    assert found is not None and found.port == 1001
    assert reg.find_by_session("nope") is None


def test_read_all_is_oldest_first(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    reg.write(_entry("gui-late", port=2, started_at="2026-02-01T00:00:00+00:00"))
    reg.write(_entry("gui-early", port=1, started_at="2026-01-01T00:00:00+00:00"))

    order = [e.session_id for e in reg.read_all()]
    assert order == ["gui-early", "gui-late"]


# --------------------------------------------------------------------------- #
# self-healing
# --------------------------------------------------------------------------- #


def test_corrupt_json_is_pruned(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    reg_dir.mkdir(parents=True, exist_ok=True)
    bad = reg_dir / "instance_9999.json"
    bad.write_text("{ not valid json ", encoding="utf-8")

    assert reg.read_all() == []
    assert not bad.exists()  # self-healed away


def test_missing_required_key_is_pruned(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    reg_dir.mkdir(parents=True, exist_ok=True)
    incomplete = reg_dir / "instance_8888.json"
    incomplete.write_text(json.dumps({"session_id": "x", "host": "127.0.0.1"}), encoding="utf-8")

    assert reg.read_all() == []
    assert not incomplete.exists()


def test_dead_pid_is_pruned(reg_dir):
    dead = {"pid": 4321}
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: pid not in dead.values())
    path = reg.write(_entry("gui-dead", pid=4321))
    assert path.exists()

    assert reg.read_all() == []
    assert not path.exists()


def test_entry_with_no_pid_is_kept(reg_dir):
    # A record carrying no pid is never pid-pruned (alive_check is not consulted).
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: False)
    reg.write(_entry("gui-nopid", pid=None))
    assert [e.session_id for e in reg.read_all()] == ["gui-nopid"]


def test_port_check_failure_omits_but_keeps_record(reg_dir):
    # A live pid with a failing probe (busy GUI) is hidden from this read only.
    reg = DiscoveryRegistry(
        reg_dir,
        alive_check=lambda pid: True,
        port_check=lambda host, port: False,  # nothing is reachable
    )
    path = reg.write(_entry("gui-busy"))
    assert reg.read_all() == []
    assert path.exists()


def test_port_check_recovers_after_transient_failure(reg_dir):
    ok = {"v": False}
    reg = DiscoveryRegistry(
        reg_dir, alive_check=lambda pid: True, port_check=lambda h, p: ok["v"]
    )
    reg.write(_entry("gui-flaky"))
    assert reg.read_all() == []
    ok["v"] = True
    assert [e.session_id for e in reg.read_all()] == ["gui-flaky"]


def test_dead_pid_is_unlinked_even_with_port_check(reg_dir):
    reg = DiscoveryRegistry(
        reg_dir, alive_check=lambda pid: False, port_check=lambda h, p: True
    )
    path = reg.write(_entry("gui-dead"))
    assert reg.read_all() == []
    assert not path.exists()


def test_bool_port_is_rejected(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    reg_dir.mkdir(parents=True, exist_ok=True)
    (reg_dir / "instance_1.json").write_text(
        json.dumps({"session_id": "x", "backend": "gui", "host": "h", "port": True}),
        encoding="utf-8",
    )
    assert reg.read_all() == []


# --------------------------------------------------------------------------- #
# removal
# --------------------------------------------------------------------------- #


def test_remove_port(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    reg.write(_entry("gui-a", port=1000))
    reg.write(_entry("gui-b", port=1001))

    assert reg.remove_port(1000) is True
    assert [e.session_id for e in reg.read_all()] == ["gui-b"]
    assert reg.remove_port(1000) is False  # already gone


def test_remove_session(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    reg.write(_entry("gui-a", port=1000))
    reg.write(_entry("gui-b", port=1001))

    assert reg.remove_session("gui-a") is True
    assert [e.session_id for e in reg.read_all()] == ["gui-b"]
    assert reg.remove_session("gui-a") is False


def test_read_all_missing_dir_is_empty(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    assert reg.read_all() == []  # directory never created


# --------------------------------------------------------------------------- #
# user-dir resolution
# --------------------------------------------------------------------------- #


def test_user_dir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("IDA_MCP_USER_DIR", str(tmp_path / "ida-user"))
    assert ida_user_dir() == tmp_path / "ida-user"
    assert registry_dir() == tmp_path / "ida-user" / "mcp" / "instances"


def test_user_dir_falls_back_to_idausr(monkeypatch, tmp_path):
    import os

    monkeypatch.delenv("IDA_MCP_USER_DIR", raising=False)
    first = tmp_path / "one"
    monkeypatch.setenv("IDAUSR", str(first) + os.pathsep + str(tmp_path / "two"))
    # First path-sep entry wins.
    resolved = ida_user_dir()
    assert resolved == first


# --------------------------------------------------------------------------- #
# GUI-adoption reader
# --------------------------------------------------------------------------- #


def test_reader_surfaces_only_gui_backend(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    reg.write(_entry("gui-a", port=1000, backend=BACKEND_GUI))
    reg.write(_entry("worker-x", port=1001, backend=BACKEND_WORKER))

    reader = GuiDiscoveryReader(reg)
    ids = [s.session_id for s in reader.list_sessions()]
    assert ids == ["gui-a"]  # worker records are not adopted by default
    assert reader.get("worker-x") is None
    assert reader.get("gui-a").session_id == "gui-a"


def test_discovered_session_to_info_shape(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    reg.write(_entry("gui-a", port=1000))
    reader = GuiDiscoveryReader(reg)

    session = reader.get("gui-a")
    assert isinstance(session, DiscoveredSession)
    info = session.to_info()
    assert info["session_id"] == "gui-a"
    assert info["backend"] == "gui"
    assert info["host"] == "127.0.0.1"
    assert info["port"] == 1000
    assert info["private_copy_path"] == ""  # a GUI owns its own database
    assert info["filename"] == "target.exe"
    # Routing surface required by the router's SessionView.
    assert session.host == "127.0.0.1" and session.port == 1000
    assert session.token == "tok-gui-a"
    assert session.baseline_record is None
    session.touch()  # no-op, must not raise


def test_transient_read_error_keeps_the_record(reg_dir, monkeypatch):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    path = reg.write(_entry("gui-live"))
    real_read_text = type(path).read_text

    def locked(self, *a, **kw):
        if self == path:
            raise PermissionError("sharing violation")
        return real_read_text(self, *a, **kw)

    monkeypatch.setattr(type(path), "read_text", locked)
    assert reg.read_all() == []
    assert path.exists()  # a locked file is not corrupt: do not delete it


# --------------------------------------------------------------------------- #
# input_path vs idb_path
# --------------------------------------------------------------------------- #


def test_input_path_round_trips_and_old_records_still_load(reg_dir):
    reg = DiscoveryRegistry(reg_dir, alive_check=lambda pid: True)
    entry = _entry("gui-new", port=1, idb_path="C:/bins/target.exe.i64")
    entry.input_path = "C:/bins/target.exe"
    reg.write(entry)
    assert reg.find_by_session("gui-new").input_path == "C:/bins/target.exe"

    old = _entry("gui-old", port=2).to_dict()
    del old["input_path"]  # record written by an older plugin
    (reg_dir / "instance_2.json").write_text(json.dumps(old))
    got = reg.find_by_session("gui-old")
    assert got.input_path is None
    assert DiscoveredSession(got).input_path == "C:/bins/target.exe"  # falls back to idb_path


def test_discovered_session_prefers_input_path_and_exposes_idb_path():
    entry = _entry("gui-x", idb_path="C:/bins/target.exe.i64")
    entry.input_path = "C:/bins/target.exe"
    info = DiscoveredSession(entry).to_info()
    assert info["input_path"] == "C:/bins/target.exe"
    assert info["idb_path"] == "C:/bins/target.exe.i64"
