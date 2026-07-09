"""Headless ``idalib`` worker entry point (composition root).

Opens exactly one database, builds the container wired with the IDA adapters, and
serves MCP on the process main thread. ``import idapro`` and the other SDK imports
happen lazily inside :func:`main`, so this module is importable without IDA.

Two transports are supported via ``--transport``:

* **stdio** (default) — newline-framed JSON on the process's real stdout. The read
  loop runs on the main thread, so the :class:`InlineExecutor` runs each use-case
  on the very thread that owns the database (idalib is main-thread-affine).
* **http** — a threaded streamable-HTTP server. Because its request handlers run on
  background threads and idalib rejects off-main-thread SDK calls, the worker binds
  a :class:`_MainThreadPump` executor: request threads enqueue the use-case and the
  main thread (pumping a job queue) executes it against the database.

Two stdout hazards are handled up front: idalib prints a native banner to file
descriptor 1, which would corrupt stdio framing, so the real stdout is duplicated
away and descriptor 1 is pointed at stderr before any SDK import. The reserved
stream then carries only framed protocol output (stdio) or a single readiness line
(http).
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import threading
from typing import BinaryIO, Callable, Optional, Sequence, TypeVar

T = TypeVar("T")


class _MainThreadPump:
    """A :class:`~idamesh.domain.ports.execution.MainThreadExecutor` that marshals
    jobs onto the thread that constructed it.

    Off-thread callers enqueue a job and block until the pump — driven from the
    owning (main) thread via :meth:`pump_forever` — runs it and hands back the
    value or re-raises its exception. On-thread callers run inline.
    """

    def __init__(self) -> None:
        self._owner_id = threading.get_ident()
        self._jobs: "queue.Queue[tuple]" = queue.Queue()
        self._stop = threading.Event()

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        if threading.get_ident() == self._owner_id:
            return job()
        done = threading.Event()
        box: dict[str, object] = {}
        self._jobs.put((job, box, done))
        done.wait()
        if "error" in box:
            raise box["error"]  # type: ignore[misc]
        return box["value"]  # type: ignore[return-value]

    def on_kernel_thread(self) -> bool:
        return threading.get_ident() == self._owner_id

    def pump_forever(self) -> None:
        """Run queued jobs on the calling thread until :meth:`stop` is signalled."""
        while not self._stop.is_set():
            try:
                job, box, done = self._jobs.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                box["value"] = job()
            except BaseException as exc:  # noqa: BLE001 — ferried to the caller
                box["error"] = exc
            finally:
                done.set()

    def stop(self) -> None:
        self._stop.set()


def _reserve_stdout() -> BinaryIO:
    """Duplicate the real stdout and point fd 1 at stderr.

    Everything the SDK prints to descriptor 1 then lands on stderr; the returned
    unbuffered binary stream is the only path to the client's stdout.
    """
    saved_fd = os.dup(1)
    os.dup2(2, 1)
    return os.fdopen(saved_fd, "wb", buffering=0)


def _bootstrap_idalib(database: str, *, run_auto_analysis: bool = True) -> None:
    """Load idalib and open ``database``. Raises ``RuntimeError`` on failure."""
    idadir = os.environ.get("IDADIR")
    if idadir and os.path.isdir(idadir):
        try:
            os.add_dll_directory(idadir)
        except (OSError, AttributeError):
            pass

    import idapro

    rc = idapro.open_database(database, run_auto_analysis)
    if rc != 0:
        raise RuntimeError(f"idapro.open_database failed for {database!r} (rc={rc})")

    import ida_auto

    ida_auto.auto_wait()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="idamesh-worker",
        description="Headless idalib MCP worker for a single database.",
    )
    parser.add_argument("database", help="path to the target binary or IDA database")
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="MCP transport to serve (default: stdio)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host")
    parser.add_argument("--port", type=int, default=13337, help="HTTP bind port (0 = ephemeral)")
    parser.add_argument("--server-version", default="0.0.1", help="advertised server version")
    parser.add_argument(
        "--token",
        default=None,
        help=(
            "bearer token required on the worker's HTTP endpoint; the supervisor "
            "forwards it so its calls succeed while other local processes get 401"
        ),
    )
    parser.add_argument(
        "--parent-pid",
        type=int,
        default=None,
        help=(
            "pid of the supervisor that spawned this worker; when set, the worker "
            "self-terminates if that process dies (no orphaned idalib workers)"
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run a headless worker over one database. Returns a process exit code."""
    args = _build_parser().parse_args(list(argv) if argv is not None else None)

    reserved_stdout = _reserve_stdout()

    try:
        _bootstrap_idalib(args.database)
    except Exception as exc:  # noqa: BLE001 — report and exit non-zero
        sys.stderr.write(f"worker: failed to open database: {exc}\n")
        sys.stderr.flush()
        return 2

    # Imported here so the module stays importable without IDA present.
    from idamesh.bootstrap.container import build_worker_container
    from idamesh.infrastructure.transport.http import HttpTransport
    from idamesh.infrastructure.transport.stdio import StdioTransport

    exit_code = 0
    watchdog = None
    try:
        if args.transport == "http":
            pump = _MainThreadPump()
            container = build_worker_container(
                server_version=args.server_version, executor=pump
            )
            transport = HttpTransport(
                container.router,
                host=args.host,
                port=args.port,
                bearer_token=args.token,
                supported_protocol_versions=container.protocol_versions,
            )
            transport.serve(block=False)
            # Tie our lifetime to the spawning supervisor: if it hard-crashes we
            # stop the pump (which unwinds into the db-close teardown below)
            # instead of lingering as an orphan. An idle-but-alive supervisor
            # keeps us up — liveness follows the parent, not request activity.
            if args.parent_pid is not None:
                from idamesh.infrastructure.process.parent_watchdog import (
                    ParentWatchdog,
                )

                watchdog = ParentWatchdog(
                    args.parent_pid, on_parent_dead=pump.stop
                ).start()
            # Readiness/port handshake (frozen contract; see
            # idamesh.infrastructure.process.handshake): emit exactly one JSON
            # line carrying ``ready: true`` and the actual bound ``port`` on the
            # reserved real stdout, flush, then serve. The supervisor reads this
            # line to learn where to connect. ``transport``/``host`` are extra
            # informational keys a reader must tolerate but need not depend on.
            reserved_stdout.write(
                json.dumps(
                    {
                        "ready": True,
                        "port": transport.bound_port,
                        "transport": "http",
                        "host": args.host,
                    }
                ).encode("utf-8")
                + b"\n"
            )
            reserved_stdout.flush()
            try:
                pump.pump_forever()
            except KeyboardInterrupt:
                pass
            finally:
                if watchdog is not None:
                    watchdog.stop()
                transport.stop()
        else:
            container = build_worker_container(server_version=args.server_version)
            transport = StdioTransport(
                container.router,
                stdin=sys.stdin.buffer,
                stdout=reserved_stdout,
            )
            try:
                transport.serve(block=True)
            except KeyboardInterrupt:
                pass
    finally:
        try:
            import idapro

            idapro.close_database(False)
        except Exception:  # noqa: BLE001 — best-effort teardown
            pass

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
