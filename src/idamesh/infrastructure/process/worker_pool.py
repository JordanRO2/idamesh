"""The worker pool: spawn, track, reap headless idalib workers (idapro-free).

The pool is the supervisor's only handle on the OS processes it owns. It mints a
:class:`~idamesh.infrastructure.process.session.WorkerSession` per open database,
materializes a private copy of the target, spawns a windowless headless worker
over an ephemeral HTTP port, waits for the worker's readiness handshake to learn
that port, and registers the session in an in-process map. There is **no**
filesystem discovery in this phase — the pool tracks only workers it spawned.

Concurrency model: an ``RLock`` guards the session map. The expensive steps
(copy + spawn + handshake-wait) run *outside* the lock so parallel opens do not
serialize on each other; the map is mutated under the lock at the boundaries.

The three heavy seams — :meth:`_materialize_private_copy`, :meth:`_spawn_worker`,
and :meth:`_await_handshake` — are kept separate from the identity, registry, and
reaping logic the pool otherwise owns.
"""

from __future__ import annotations

import os
import queue
import secrets
import subprocess
import sys
import threading
from collections import deque
from pathlib import Path
from typing import List, Optional, Tuple

from idamesh.infrastructure.process.handshake import parse_handshake_line
from idamesh.infrastructure.process.session import Backend, WorkerSession

#: Default cap on concurrently-owned workers (env ``IDA_MCP_MAX_WORKERS``);
#: ``0`` means unlimited. A copy of a binary is a full idalib process, so
#: ``RAM ≈ N × per-IDB footprint`` — this is the guard rail.
DEFAULT_MAX_WORKERS = 4

#: The module a worker is launched as.
WORKER_MODULE = "idamesh.bootstrap.worker_main"

#: Windows: no console flash, own process group. POSIX: ``start_new_session``.
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

#: Seconds to wait for a spawned worker's readiness handshake before giving up.
#: The worker emits its handshake only *after* it has fully opened the database
#: and run initial auto-analysis, so this must be generous enough to cover a large
#: binary's analysis. Overridable per deployment via ``IDA_MCP_OPEN_TIMEOUT``.
DEFAULT_HANDSHAKE_TIMEOUT = 600.0

#: Env var (seconds, float) overriding the readiness/open timeout.
OPEN_TIMEOUT_ENV = "IDA_MCP_OPEN_TIMEOUT"


class WorkerPoolError(RuntimeError):
    """Base class for pool failures (surfaced to the client as actionable text)."""


class ConcurrencyLimitError(WorkerPoolError):
    """Raised when opening would exceed ``max_workers`` (after reaping dead ones)."""


class SessionSpawnError(WorkerPoolError):
    """Raised when a worker fails to start, copy its target, or report readiness."""


class _StderrDrain:
    """Continuously drains a child's stderr on a daemon thread.

    Two problems it solves at once. First, the worker redirects idalib's native
    fd-1 banner/progress onto its stderr; if nobody reads that pipe it can fill
    (~64 KiB) and wedge the worker *before* it emits its stdout handshake — a
    deadlock. Second, on a spawn failure the captured text is the only diagnostic
    we can surface. Only a bounded tail is retained so a long-lived, chatty worker
    cannot grow this without bound.
    """

    _MAX_BYTES = 64 * 1024

    def __init__(self, stream: "Optional[object]") -> None:
        self._stream = stream
        self._chunks: "deque[bytes]" = deque()
        self._size = 0
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        if stream is not None:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def _run(self) -> None:
        try:
            for line in iter(self._stream.readline, b""):  # type: ignore[union-attr]
                if not line:
                    break
                with self._lock:
                    self._chunks.append(line)
                    self._size += len(line)
                    while self._size > self._MAX_BYTES and len(self._chunks) > 1:
                        self._size -= len(self._chunks.popleft())
        except Exception:  # noqa: BLE001 — draining is best-effort
            pass

    def text(self) -> str:
        with self._lock:
            data = b"".join(self._chunks)
        return data.decode("utf-8", errors="replace").strip()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)


def _kill_process(process: "Optional[subprocess.Popen]") -> None:
    """Best-effort terminate→kill of a raw process handle (never raises)."""
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    except Exception:  # noqa: BLE001 — teardown is best-effort
        pass


def _resolve_max_workers(explicit: Optional[int]) -> int:
    if explicit is not None:
        return max(0, explicit)
    raw = os.environ.get("IDA_MCP_MAX_WORKERS")
    if raw is None:
        return DEFAULT_MAX_WORKERS
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_MAX_WORKERS


def _resolve_open_timeout(explicit: Optional[float]) -> float:
    """The readiness/open timeout in seconds.

    An explicit value wins; otherwise ``IDA_MCP_OPEN_TIMEOUT`` (a float number of
    seconds) is honored, falling back to :data:`DEFAULT_HANDSHAKE_TIMEOUT`. A
    non-positive or unparseable env value falls back to the default rather than
    disabling the bound.
    """
    if explicit is not None:
        return float(explicit)
    raw = os.environ.get(OPEN_TIMEOUT_ENV)
    if raw is None:
        return DEFAULT_HANDSHAKE_TIMEOUT
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_HANDSHAKE_TIMEOUT
    return value if value > 0 else DEFAULT_HANDSHAKE_TIMEOUT


class WorkerPool:
    """Owns the lifecycle of the headless workers the supervisor spawns."""

    def __init__(
        self,
        *,
        max_workers: Optional[int] = None,
        host: str = "127.0.0.1",
        python_executable: Optional[str] = None,
        worker_module: str = WORKER_MODULE,
        handshake_timeout: Optional[float] = None,
        env: Optional[dict] = None,
    ) -> None:
        self._max_workers = _resolve_max_workers(max_workers)
        self._host = host
        self._python = python_executable or sys.executable
        self._worker_module = worker_module
        # The readiness handshake fires only after full auto-analysis, so the wait
        # must cover a large binary's initial analysis; env-overridable.
        self._handshake_timeout = _resolve_open_timeout(handshake_timeout)
        self._env = env
        self._sessions: "dict[str, WorkerSession]" = {}
        self._lock = threading.RLock()

    # -- public API ----------------------------------------------------------

    def open_session(
        self,
        input_path: str,
        *,
        preferred_session_id: Optional[str] = None,
    ) -> WorkerSession:
        """Open ``input_path`` and return its session.

        With no reachable ``preferred_session_id`` this **always mints a fresh
        worker over a private copy** — opening the same binary twice yields two
        workers/databases (real N-copies parallelism). Passing a live
        ``preferred_session_id`` **shares** that worker instead.
        """
        with self._lock:
            if preferred_session_id:
                existing = self._sessions.get(preferred_session_id)
                if existing is not None and self._is_alive(existing):
                    existing.touch()
                    return existing
            # Prune dead workers before the cap check so it counts only live ones.
            self._reap_locked()
            if self._max_workers and len(self._sessions) >= self._max_workers:
                raise ConcurrencyLimitError(
                    f"worker limit reached ({self._max_workers}); release a session "
                    "with idb_close or raise IDA_MCP_MAX_WORKERS"
                )
            session_id = preferred_session_id or self._mint_session_id(input_path)
            # Reserve the id so a concurrent open cannot pick the same one.
            placeholder = WorkerSession(
                session_id=session_id,
                input_path=input_path,
                private_copy_path="",
                host=self._host,
                port=0,
                backend=Backend.HEADLESS_WORKER,
            )
            self._sessions[session_id] = placeholder

        # Heavy work outside the lock. On any failure, unregister the reservation.
        try:
            private_copy = self._materialize_private_copy(session_id, input_path)
            placeholder.private_copy_path = str(private_copy)
            # _spawn_worker attaches the process handle to ``placeholder`` the
            # instant the worker is launched — *before* the blocking readiness wait
            # — so a concurrent idb_close during a large binary's initial analysis
            # can reach and kill the worker instead of orphaning it.
            process, port, token = self._spawn_worker(
                session_id, private_copy, placeholder
            )
        except Exception as exc:  # noqa: BLE001 — cleaned up and rethrown
            self._discard(session_id)
            self._cleanup_scratch(placeholder)
            if isinstance(exc, WorkerPoolError):
                raise
            raise SessionSpawnError(f"failed to open {input_path!r}: {exc}") from exc

        with self._lock:
            still_registered = self._sessions.get(session_id) is placeholder
            if still_registered:
                placeholder.port = port
                placeholder.token = token
        if not still_registered:
            # idb_close popped us while we were still spawning: reap the worker we
            # just finished bringing up rather than leak it as an untracked orphan.
            _kill_process(process)
            self._cleanup_scratch(placeholder)
            raise SessionSpawnError(
                f"open of {input_path!r} was cancelled (session closed during spawn)"
            )

        placeholder.touch()
        return placeholder

    def list_sessions(self) -> List[WorkerSession]:
        """All live sessions in stable creation order."""
        with self._lock:
            self._reap_locked()
            return sorted(self._sessions.values(), key=lambda s: s.created_at)

    def get(self, session_id: str) -> Optional[WorkerSession]:
        """The session for ``session_id``, or ``None`` if unknown/dead."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if not self._is_alive(session):
                self._discard_locked(session_id)
                return None
            return session

    def close_session(self, session_id: str) -> bool:
        """Terminate the worker and remove the session. ``True`` if one existed."""
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        self._terminate(session)
        self._cleanup_scratch(session)
        return True

    def reap(self) -> List[str]:
        """Drop sessions whose worker has died; return their ids."""
        with self._lock:
            return self._reap_locked()

    def close_all(self) -> None:
        """Terminate every worker and clear the map (supervisor shutdown)."""
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            self._terminate(session)
            self._cleanup_scratch(session)

    # -- heavy seams ----------------------------------

    def _materialize_private_copy(self, session_id: str, input_path: str) -> Path:
        """Copy ``input_path`` into the per-session scratch dir; return the path
        the worker should open. Delegates to
        :mod:`idamesh.infrastructure.process.scratch_copy`."""
        from idamesh.infrastructure.process.scratch_copy import (
            materialize_private_copy,
        )

        return materialize_private_copy(session_id, input_path)

    def _spawn_worker(
        self, session_id: str, private_copy: Path, session: "WorkerSession"
    ) -> "Tuple[subprocess.Popen, int, Optional[str]]":
        """Launch a windowless headless worker over the private copy and wait for
        its readiness handshake.

        Builds the argv (``python -m <worker_module> <private_copy> --transport
        http --host <host> --port 0 --parent-pid <supervisor pid> --token
        <random>``), spawns with ``CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP``
        (Windows) / ``start_new_session`` (POSIX) and stdout+stderr piped, drains
        stderr concurrently (so idalib's fd-1 banner cannot wedge the pipe before
        the handshake), then awaits the bound port. Returns ``(process,
        bound_port, token)`` where ``token`` is a fresh per-worker bearer secret
        the worker requires on its loopback ``/mcp`` endpoint. On a
        copy/spawn/handshake failure the child is killed and a
        :class:`SessionSpawnError` — enriched with the worker's captured stderr —
        is raised.

        Two robustness wires go in here. ``--parent-pid`` gives the worker this
        supervisor's pid so it self-terminates if the supervisor hard-crashes
        (no orphaned idalib processes). ``--token`` gives it a random bearer
        secret so its otherwise-open loopback endpoint rejects any local process
        that is not this supervisor (which forwards the same token).
        """
        # ``token_hex`` (not ``token_urlsafe``): a url-safe secret can begin with
        # '-', which argparse then mistakes for another option on the worker command
        # line ("argument --token: expected one argument"), failing the spawn ~a few
        # percent of the time. Hex is pure [0-9a-f] and always argv-safe.
        token = secrets.token_hex(32)
        argv = [
            self._python,
            "-m",
            self._worker_module,
            str(private_copy),
            "--transport",
            "http",
            "--host",
            self._host,
            "--port",
            "0",
            "--parent-pid",
            str(os.getpid()),
            "--token",
            token,
        ]
        popen_kwargs: dict = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }
        if self._env is not None:
            popen_kwargs["env"] = self._env
        if os.name == "nt":
            popen_kwargs["creationflags"] = _CREATE_NO_WINDOW | _CREATE_NEW_PROCESS_GROUP
        else:
            # New session/process group so a supervisor Ctrl-C does not storm the
            # worker mid-analysis; we reap it explicitly instead.
            popen_kwargs["start_new_session"] = True

        try:
            process = subprocess.Popen(argv, **popen_kwargs)  # noqa: S603
        except OSError as exc:
            raise SessionSpawnError(
                f"could not launch worker for session {session_id!r}: {exc}"
            ) from exc

        # Make the worker reapable before we block on its readiness handshake: an
        # idb_close (or a failed open) during the initial auto-analysis can then
        # terminate this exact process via the session record instead of leaving it
        # to run to completion as an orphan.
        session.process = process

        stderr_drain = _StderrDrain(process.stderr)
        try:
            port = self._await_handshake(process)
        except SessionSpawnError as exc:
            _kill_process(process)
            stderr_drain.join(timeout=2.0)
            detail = stderr_drain.text()
            message = f"worker for session {session_id!r} {exc}"
            if detail:
                message += f"\n--- worker stderr ---\n{detail}"
            raise SessionSpawnError(message) from exc

        return process, port, token

    def _await_handshake(self, process: "subprocess.Popen") -> int:
        """Read the worker's single readiness line from its stdout (bounded by
        ``handshake_timeout``) and return the bound port.

        Reading runs on a background thread so a wedged worker cannot block the
        supervisor forever. On timeout the process is killed; on an early exit or
        a malformed line a :class:`SessionSpawnError` is raised (the caller
        enriches it with captured stderr). The line is validated by
        :func:`idamesh.infrastructure.process.handshake.parse_handshake_line`.
        """
        stdout = process.stdout
        if stdout is None:  # pragma: no cover — spawn always pipes stdout
            raise SessionSpawnError("was spawned without a readable stdout pipe")

        result: "queue.Queue[Optional[bytes]]" = queue.Queue(maxsize=1)

        def _read_line() -> None:
            try:
                line = stdout.readline()
            except Exception:  # noqa: BLE001 — surfaced as an empty/EOF read
                line = b""
            result.put(line)

        reader = threading.Thread(target=_read_line, daemon=True)
        reader.start()

        try:
            line = result.get(timeout=self._handshake_timeout)
        except queue.Empty:
            _kill_process(process)
            raise SessionSpawnError(
                f"did not report readiness within {self._handshake_timeout:g}s "
                "(the worker emits readiness only after initial auto-analysis "
                f"finishes; raise {OPEN_TIMEOUT_ENV} to allow a large binary more "
                "time to analyze)"
            )

        if not line:
            # EOF before any handshake line — the worker exited early. Give it a
            # beat to settle so we can report a real exit code.
            code = process.poll()
            if code is None:
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _kill_process(process)
                    code = process.poll()
            raise SessionSpawnError(
                f"exited before reporting readiness (exit code {code})"
            )

        try:
            return parse_handshake_line(line)
        except Exception as exc:  # HandshakeError and any decode fault
            raise SessionSpawnError(f"sent an invalid readiness line: {exc}") from exc

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _mint_session_id(input_path: str) -> str:
        """``"<source-stem>-<8 hex>"`` — unique so auto-minted ids never collide."""
        stem = Path(input_path).stem or "session"
        # Keep the stem tame for a session id (letters/digits/._- only).
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in stem)
        return f"{safe}-{secrets.token_hex(4)}"

    @staticmethod
    def _is_alive(session: WorkerSession) -> bool:
        """Cheap liveness: an owned worker's process must not have exited."""
        process = session.process
        if process is None:
            # A reservation mid-spawn (no process yet) counts as pending-alive; an
            # adopted GUI with no owned process is assumed live (discovery gates it
            # in a later phase).
            return session.backend != Backend.HEADLESS_WORKER or session.port == 0
        return process.poll() is None

    def _reap_locked(self) -> List[str]:
        dead = [
            sid
            for sid, session in self._sessions.items()
            if session.process is not None and session.process.poll() is not None
        ]
        for sid in dead:
            session = self._sessions.pop(sid, None)
            if session is not None:
                self._cleanup_scratch(session)
        return dead

    def _discard(self, session_id: str) -> None:
        with self._lock:
            self._discard_locked(session_id)

    def _discard_locked(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is not None:
            self._terminate(session)
            self._cleanup_scratch(session)

    @staticmethod
    def _terminate(session: WorkerSession) -> None:
        """Best-effort kill of an owned worker process (never raises)."""
        process = session.process
        if process is None or process.poll() is not None:
            return
        try:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        except Exception:  # noqa: BLE001 — teardown is best-effort
            pass

    @staticmethod
    def _cleanup_scratch(session: WorkerSession) -> None:
        """Remove the session's private scratch dir (best-effort)."""
        if session.backend != Backend.HEADLESS_WORKER:
            return
        try:
            from idamesh.infrastructure.process.scratch_copy import cleanup_session_dir

            cleanup_session_dir(session.session_id)
        except Exception:  # noqa: BLE001 — never fail teardown on cleanup
            pass
