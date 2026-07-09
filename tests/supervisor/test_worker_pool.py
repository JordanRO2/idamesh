"""Unit tests for the worker pool's spawn / copy / handshake seams (idapro-free).

The whole subprocess boundary is *faked*: ``subprocess.Popen`` is replaced with a
:class:`FakePopen` that emits the frozen readiness handshake on an in-memory
stdout and reports liveness via ``poll()``. No idalib is spawned, so these run on
any machine. Because only the process boundary is faked, the pool's *real*
``_spawn_worker`` / ``_await_handshake`` logic and the *real* private-copy
materialization in :mod:`idamesh.infrastructure.process.scratch_copy` are all
exercised end to end.

The invariants locked in here are the N-copies contract (two opens of one path =
two independent sessions/copies/processes), share-by-id, the concurrency cap, that
close removes the per-session scratch dir, and that reap drops dead sessions — plus
the spawn argv/flags, handshake parsing, and the failure/cleanup paths.
"""

from __future__ import annotations

import io
import itertools
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import List, Optional

import pytest

from idamesh.infrastructure.process import scratch_copy
from idamesh.infrastructure.process.worker_pool import (
    DEFAULT_HANDSHAKE_TIMEOUT,
    OPEN_TIMEOUT_ENV,
    ConcurrencyLimitError,
    SessionSpawnError,
    WorkerPool,
    _resolve_open_timeout,
)

# --------------------------------------------------------------------------- #
# Fake subprocess boundary
# --------------------------------------------------------------------------- #

_PORTS = itertools.count(15001)


class _BlockingStream:
    """A stdout stand-in whose ``readline`` blocks until explicitly released.

    Used to drive the handshake-timeout path: the pool's reader thread parks on
    ``readline`` while ``_await_handshake`` times out on its queue.
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def readline(self) -> bytes:
        self._event.wait()
        return b""

    def release(self) -> None:
        self._event.set()


class FakePopen:
    """A drop-in for ``subprocess.Popen`` that never launches anything.

    ``mode`` selects the child's behaviour:

    * ``"ok"``       — emit a valid ``{"ready": true, "port": N}`` line, stay alive.
    * ``"eof"``      — exit immediately with no handshake (nonzero code + stderr).
    * ``"bad_line"`` — emit a line that is not a valid handshake.
    * ``"hang"``     — never emit anything (blocks the reader).
    """

    def __init__(self, argv, *, mode: str = "ok", **kwargs) -> None:
        self.argv: List[str] = list(argv)
        self.kwargs = kwargs
        self.mode = mode
        self.creationflags = int(kwargs.get("creationflags", 0))
        self.start_new_session = bool(kwargs.get("start_new_session", False))
        self.port = next(_PORTS)
        self.terminate_calls = 0
        self.kill_calls = 0

        if mode == "ok":
            line = json.dumps(
                {"ready": True, "port": self.port, "transport": "http", "host": "127.0.0.1"}
            ).encode() + b"\n"
            self.stdout = io.BytesIO(line)
            self.stderr = io.BytesIO(b"")
            self._returncode: Optional[int] = None
        elif mode == "eof":
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"worker: failed to open database: boom\n")
            self._returncode = 3
        elif mode == "bad_line":
            self.stdout = io.BytesIO(b"this is not json\n")
            self.stderr = io.BytesIO(b"")
            self._returncode = None
        elif mode == "hang":
            self.stdout = _BlockingStream()
            self.stderr = io.BytesIO(b"")
            self._returncode = None
        else:  # pragma: no cover — guard against a typo'd mode
            raise ValueError(f"unknown FakePopen mode {mode!r}")

    # -- Popen surface the pool relies on ---------------------------------
    def poll(self) -> Optional[int]:
        return self._returncode

    def wait(self, timeout: Optional[float] = None) -> int:
        if self._returncode is None:
            self._returncode = 0
        return self._returncode

    def terminate(self) -> None:
        self.terminate_calls += 1
        if self._returncode is None:
            self._returncode = -15

    def kill(self) -> None:
        self.kill_calls += 1
        self._returncode = -9

    # -- test helper ------------------------------------------------------
    def die(self, code: int = 0) -> None:
        """Simulate the worker process exiting on its own."""
        self._returncode = code
        if isinstance(self.stdout, _BlockingStream):
            self.stdout.release()


class Spawner:
    """A ``Popen`` factory that records every spawned :class:`FakePopen`."""

    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.instances: List[FakePopen] = []

    def __call__(self, argv, **kwargs) -> FakePopen:
        proc = FakePopen(argv, mode=self.mode, **kwargs)
        self.instances.append(proc)
        return proc


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def scratch(tmp_path, monkeypatch) -> Path:
    """Point the scratch root at an isolated temp dir for the test."""
    root = tmp_path / "scratch"
    monkeypatch.setenv("IDA_MCP_WORKER_SCRATCH", str(root))
    return root


@pytest.fixture
def target(tmp_path) -> Path:
    """A tiny stand-in binary the pool will copy per session."""
    path = tmp_path / "target.bin"
    path.write_bytes(b"MZ\x00\x01fake-binary-payload\xde\xad\xbe\xef")
    return path


@pytest.fixture
def install_spawn(monkeypatch):
    """Install a :class:`Spawner` over ``subprocess.Popen`` and return it."""

    def _install(mode: str = "ok") -> Spawner:
        spawner = Spawner(mode)
        monkeypatch.setattr(subprocess, "Popen", spawner)
        return spawner

    return _install


@pytest.fixture
def make_pool():
    """Build pools and guarantee they are torn down after the test."""
    pools: List[WorkerPool] = []

    def _make(**kwargs) -> WorkerPool:
        pool = WorkerPool(**kwargs)
        pools.append(pool)
        return pool

    yield _make

    for pool in pools:
        pool.close_all()


# --------------------------------------------------------------------------- #
# N-copies: two opens of one path = two independent sessions
# --------------------------------------------------------------------------- #


def test_open_mints_fresh_session_with_private_copy(
    scratch, target, install_spawn, make_pool
):
    spawner = install_spawn("ok")
    pool = make_pool(max_workers=4)

    session = pool.open_session(str(target))

    assert len(spawner.instances) == 1
    fake = spawner.instances[0]
    # The bound port from the handshake landed on the session.
    assert session.port == fake.port
    assert session.host == "127.0.0.1"
    # A fresh per-worker bearer token is minted and stored on the session so the
    # router can forward it (the worker's endpoint requires it).
    assert isinstance(session.token, str) and session.token
    assert session.process is fake
    # The worker opened a private copy — never the user's original.
    copy = Path(session.private_copy_path)
    assert copy.is_file()
    assert copy != target
    assert copy.read_bytes() == target.read_bytes()
    # The copy lives under this session's own scratch dir.
    assert copy.parent.name == session.session_id
    assert copy.parent.parent == scratch.resolve() or copy.parent.parent == scratch


def test_repeated_open_of_same_path_yields_distinct_sessions(
    scratch, target, install_spawn, make_pool
):
    spawner = install_spawn("ok")
    pool = make_pool(max_workers=4)

    a = pool.open_session(str(target))
    b = pool.open_session(str(target))

    # Two processes, two ids, two ports, two private copies — genuine N-copies.
    assert len(spawner.instances) == 2
    assert a.session_id != b.session_id
    assert a.port != b.port
    assert a.private_copy_path != b.private_copy_path
    assert Path(a.private_copy_path).is_file()
    assert Path(b.private_copy_path).is_file()
    assert {s.session_id for s in pool.list_sessions()} == {a.session_id, b.session_id}


def test_spawn_argv_and_flags(scratch, target, install_spawn, make_pool):
    spawner = install_spawn("ok")
    pool = make_pool(max_workers=4)

    session = pool.open_session(str(target))
    argv = spawner.instances[0].argv

    assert argv[1:3] == ["-m", "idamesh.bootstrap.worker_main"]
    assert argv[3] == session.private_copy_path
    # Ephemeral HTTP transport is requested.
    assert "--transport" in argv and argv[argv.index("--transport") + 1] == "http"
    assert "--port" in argv and argv[argv.index("--port") + 1] == "0"
    assert "--host" in argv and argv[argv.index("--host") + 1] == "127.0.0.1"
    # The supervisor's own pid is passed so the worker's parent-pid watchdog can
    # tie its lifetime to this process.
    assert "--parent-pid" in argv
    assert argv[argv.index("--parent-pid") + 1] == str(os.getpid())
    # A random bearer token is passed and matches the one recorded on the session.
    assert "--token" in argv
    passed_token = argv[argv.index("--token") + 1]
    assert passed_token and passed_token == session.token

    fake = spawner.instances[0]
    if os.name == "nt":
        assert fake.creationflags & subprocess.CREATE_NO_WINDOW
        assert fake.creationflags & subprocess.CREATE_NEW_PROCESS_GROUP
        assert fake.start_new_session is False
    else:
        assert fake.start_new_session is True


def test_open_prefers_sibling_database_copy(
    scratch, tmp_path, install_spawn, make_pool
):
    """A ``.i64`` next to the input is cloned in preference to the raw binary."""
    binary = tmp_path / "prog.bin"
    binary.write_bytes(b"\x00raw-binary\x00")
    sibling = tmp_path / "prog.i64"
    sibling.write_bytes(b"IDA1prior-analysis-database")

    install_spawn("ok")
    pool = make_pool(max_workers=4)

    session = pool.open_session(str(binary))
    copy = Path(session.private_copy_path)

    assert copy.name == "prog.i64"
    assert copy.read_bytes() == sibling.read_bytes()


# --------------------------------------------------------------------------- #
# Share-by-id
# --------------------------------------------------------------------------- #


def test_preferred_session_id_shares_worker(
    scratch, target, install_spawn, make_pool
):
    spawner = install_spawn("ok")
    pool = make_pool(max_workers=4)

    first = pool.open_session(str(target))
    again = pool.open_session(str(target), preferred_session_id=first.session_id)

    # Sharing reuses the live worker — no second process, same record.
    assert again is first
    assert len(spawner.instances) == 1
    assert len(pool.list_sessions()) == 1


def test_unknown_preferred_id_mints_new_session_with_that_id(
    scratch, target, install_spawn, make_pool
):
    spawner = install_spawn("ok")
    pool = make_pool(max_workers=4)

    session = pool.open_session(str(target), preferred_session_id="chosen-id")

    assert session.session_id == "chosen-id"
    assert len(spawner.instances) == 1


# --------------------------------------------------------------------------- #
# Concurrency cap
# --------------------------------------------------------------------------- #


def test_concurrency_cap_enforced(scratch, target, install_spawn, make_pool):
    spawner = install_spawn("ok")
    pool = make_pool(max_workers=2)

    pool.open_session(str(target))
    pool.open_session(str(target))
    with pytest.raises(ConcurrencyLimitError):
        pool.open_session(str(target))

    # The rejected open never spawned a third process.
    assert len(spawner.instances) == 2
    assert len(pool.list_sessions()) == 2


def test_cap_reaps_dead_before_rejecting(scratch, target, install_spawn, make_pool):
    """A dead worker frees a slot: the cap counts only live sessions."""
    spawner = install_spawn("ok")
    pool = make_pool(max_workers=2)

    a = pool.open_session(str(target))
    pool.open_session(str(target))
    # First worker dies; opening again must succeed (dead one is reaped first).
    a.process.die(0)

    c = pool.open_session(str(target))
    assert c.session_id != a.session_id
    assert a.session_id not in {s.session_id for s in pool.list_sessions()}
    assert len(pool.list_sessions()) == 2


def test_max_workers_zero_is_unlimited(scratch, target, install_spawn, make_pool):
    install_spawn("ok")
    pool = make_pool(max_workers=0)

    for _ in range(6):
        pool.open_session(str(target))
    assert len(pool.list_sessions()) == 6


# --------------------------------------------------------------------------- #
# Close removes the scratch dir
# --------------------------------------------------------------------------- #


def test_close_session_removes_scratch_and_terminates(
    scratch, target, install_spawn, make_pool
):
    spawner = install_spawn("ok")
    pool = make_pool(max_workers=4)

    session = pool.open_session(str(target))
    session_scratch = Path(session.private_copy_path).parent
    assert session_scratch.is_dir()
    fake = spawner.instances[0]

    assert pool.close_session(session.session_id) is True

    # Process terminated, scratch dir gone, session forgotten.
    assert fake.terminate_calls >= 1
    assert not session_scratch.exists()
    assert pool.get(session.session_id) is None
    assert pool.list_sessions() == []
    # The user's original file is untouched.
    assert target.is_file()


def test_close_during_spawn_reaps_the_worker(
    scratch, target, install_spawn, make_pool
):
    """Closing a session while its worker is still in initial analysis must
    terminate that worker, not orphan it.

    The worker's process handle is attached to the session the instant it is
    launched (before the blocking readiness wait), so an ``idb_close`` arriving
    mid-spawn can reach and kill it. Regression for a real orphan observed live:
    a worker doing a fresh full auto-analysis kept running (and its scratch dir
    survived) after ``idb_close`` returned success, because the placeholder still
    carried ``process=None``.
    """
    spawner = install_spawn("hang")  # never reports readiness
    pool = make_pool(max_workers=4, handshake_timeout=30.0)

    outcome: dict = {}

    def do_open() -> None:
        try:
            pool.open_session(str(target))
            outcome["ok"] = True
        except SessionSpawnError as exc:
            outcome["err"] = str(exc)

    opener = threading.Thread(target=do_open)
    opener.start()

    # Wait until the worker is spawned AND attached to the registered session
    # (i.e. open_session is now blocked on the handshake).
    fake = None
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        sessions = pool.list_sessions()
        if spawner.instances and sessions and sessions[0].process is spawner.instances[0]:
            fake = spawner.instances[0]
            break
        time.sleep(0.005)
    assert fake is not None, "worker was never attached to the session mid-spawn"
    session_id = pool.list_sessions()[0].session_id
    session_scratch = Path(pool.list_sessions()[0].private_copy_path).parent

    # Close while the open is still blocked on the handshake.
    assert pool.close_session(session_id) is True
    # The in-flight worker was actually terminated, not left running.
    assert fake.terminate_calls >= 1

    # Let the parked reader see EOF so the blocked open unwinds cleanly.
    fake.stdout.release()
    opener.join(timeout=5.0)
    assert not opener.is_alive()
    # Nothing is left registered and the scratch dir is gone.
    assert pool.list_sessions() == []
    assert not session_scratch.exists()


def test_close_unknown_session_returns_false(scratch, install_spawn, make_pool):
    install_spawn("ok")
    pool = make_pool(max_workers=4)
    assert pool.close_session("nope") is False


def test_close_all_terminates_every_worker(
    scratch, target, install_spawn, make_pool
):
    spawner = install_spawn("ok")
    pool = make_pool(max_workers=4)

    pool.open_session(str(target))
    pool.open_session(str(target))
    dirs = [Path(s.private_copy_path).parent for s in pool.list_sessions()]

    pool.close_all()

    assert pool.list_sessions() == []
    for fake in spawner.instances:
        assert fake.terminate_calls >= 1
    for d in dirs:
        assert not d.exists()


# --------------------------------------------------------------------------- #
# Reap drops dead sessions
# --------------------------------------------------------------------------- #


def test_reap_drops_dead_sessions(scratch, target, install_spawn, make_pool):
    spawner = install_spawn("ok")
    pool = make_pool(max_workers=4)

    alive = pool.open_session(str(target))
    dead = pool.open_session(str(target))
    dead_scratch = Path(dead.private_copy_path).parent

    dead.process.die(0)
    reaped = pool.reap()

    assert reaped == [dead.session_id]
    assert {s.session_id for s in pool.list_sessions()} == {alive.session_id}
    # A reaped session's scratch dir is cleaned up too.
    assert not dead_scratch.exists()


def test_get_discards_dead_session(scratch, target, install_spawn, make_pool):
    install_spawn("ok")
    pool = make_pool(max_workers=4)

    session = pool.open_session(str(target))
    session.process.die(1)

    assert pool.get(session.session_id) is None


# --------------------------------------------------------------------------- #
# Spawn / handshake failure paths
# --------------------------------------------------------------------------- #


def test_early_exit_before_handshake_raises_and_cleans_up(
    scratch, target, install_spawn, make_pool
):
    install_spawn("eof")
    pool = make_pool(max_workers=4)

    with pytest.raises(SessionSpawnError) as excinfo:
        pool.open_session(str(target))

    message = str(excinfo.value)
    # The exit code and the captured stderr are both surfaced.
    assert "exit code 3" in message
    assert "boom" in message
    # Nothing is registered and no session dir is left under the scratch root.
    assert pool.list_sessions() == []
    if scratch.exists():
        assert list(scratch.iterdir()) == []


def test_malformed_handshake_raises(scratch, target, install_spawn, make_pool):
    spawner = install_spawn("bad_line")
    pool = make_pool(max_workers=4)

    with pytest.raises(SessionSpawnError) as excinfo:
        pool.open_session(str(target))

    assert "invalid readiness line" in str(excinfo.value)
    # The child that produced garbage was killed.
    assert spawner.instances[0].poll() is not None
    assert pool.list_sessions() == []


def test_handshake_timeout_raises_and_kills(
    scratch, target, install_spawn, make_pool
):
    spawner = install_spawn("hang")
    pool = make_pool(max_workers=4, handshake_timeout=0.3)

    try:
        with pytest.raises(SessionSpawnError) as excinfo:
            pool.open_session(str(target))
        assert "readiness" in str(excinfo.value)
        assert spawner.instances[0].terminate_calls >= 1
        assert pool.list_sessions() == []
    finally:
        # Let the parked reader thread unwind.
        spawner.instances[0].stdout.release()


def test_missing_input_file_raises_spawn_error(scratch, tmp_path, install_spawn, make_pool):
    install_spawn("ok")
    pool = make_pool(max_workers=4)

    with pytest.raises(SessionSpawnError):
        pool.open_session(str(tmp_path / "does-not-exist.bin"))
    assert pool.list_sessions() == []


# --------------------------------------------------------------------------- #
# scratch_copy scope guards (path-traversal defence)
# --------------------------------------------------------------------------- #


def test_scratch_root_honours_env_override(scratch):
    root = scratch_copy.scratch_root()
    assert root == Path(str(scratch))
    assert root.is_dir()


def test_session_dir_rejects_traversal(scratch):
    for bad in ("..", ".", "", "a/b", "a\\b", "../escape"):
        with pytest.raises(ValueError):
            scratch_copy.session_dir(bad)


def test_cleanup_is_scoped_and_never_escapes(scratch, tmp_path):
    # A file living outside any session dir must survive a crafted cleanup.
    outside = tmp_path / "precious.txt"
    outside.write_text("keep me")

    real = "sess-1234abcd"
    d = scratch_copy.session_dir(real)
    d.mkdir(parents=True, exist_ok=True)
    (d / "copy.bin").write_bytes(b"x")

    # A traversal id is refused silently (best-effort, never raises).
    scratch_copy.cleanup_session_dir("../../../precious")
    assert outside.exists()

    # A real id cleans exactly its own dir.
    scratch_copy.cleanup_session_dir(real)
    assert not d.exists()
    assert outside.exists()


def test_cleanup_missing_dir_is_noop(scratch):
    # No dir yet — cleanup must not raise.
    scratch_copy.cleanup_session_dir("never-created-9999")


# --------------------------------------------------------------------------- #
# Configurable open/handshake timeout (IDA_MCP_OPEN_TIMEOUT)
# --------------------------------------------------------------------------- #


def test_open_timeout_defaults_when_env_absent(monkeypatch):
    monkeypatch.delenv(OPEN_TIMEOUT_ENV, raising=False)
    assert _resolve_open_timeout(None) == DEFAULT_HANDSHAKE_TIMEOUT
    # The default is generous enough to cover a large binary's auto-analysis.
    assert DEFAULT_HANDSHAKE_TIMEOUT >= 600.0


def test_open_timeout_reads_env(monkeypatch):
    monkeypatch.setenv(OPEN_TIMEOUT_ENV, "1234.5")
    assert _resolve_open_timeout(None) == pytest.approx(1234.5)


def test_open_timeout_explicit_wins_over_env(monkeypatch):
    monkeypatch.setenv(OPEN_TIMEOUT_ENV, "1234.5")
    assert _resolve_open_timeout(9.0) == pytest.approx(9.0)


def test_open_timeout_bad_or_nonpositive_env_falls_back(monkeypatch):
    for bad in ("not-a-number", "0", "-5"):
        monkeypatch.setenv(OPEN_TIMEOUT_ENV, bad)
        assert _resolve_open_timeout(None) == DEFAULT_HANDSHAKE_TIMEOUT


def test_pool_picks_up_open_timeout_env(monkeypatch, make_pool):
    monkeypatch.setenv(OPEN_TIMEOUT_ENV, "42")
    pool = make_pool()
    assert pool._handshake_timeout == pytest.approx(42.0)


def test_handshake_timeout_message_names_the_env_var(
    scratch, target, install_spawn, make_pool
):
    spawner = install_spawn("hang")
    pool = make_pool(max_workers=4, handshake_timeout=0.2)
    try:
        with pytest.raises(SessionSpawnError) as excinfo:
            pool.open_session(str(target))
        message = str(excinfo.value)
        # The remedy (raise IDA_MCP_OPEN_TIMEOUT) is spelled out.
        assert OPEN_TIMEOUT_ENV in message
        assert "readiness" in message
    finally:
        spawner.instances[0].stdout.release()


def test_each_worker_gets_a_distinct_token(scratch, target, install_spawn, make_pool):
    install_spawn("ok")
    pool = make_pool(max_workers=4)
    a = pool.open_session(str(target))
    b = pool.open_session(str(target))
    assert a.token and b.token
    assert a.token != b.token
