"""Parent-process liveness watchdog for headless workers (idapro-free).

A worker the supervisor spawns runs detached (its own process group / session) so
a supervisor ``Ctrl-C`` cannot storm it mid-analysis. The flip side is that a
supervisor that *hard-crashes* would leak its workers as orphans: each is a full
``idalib`` process holding memory with nobody left to reap it.

The chosen remedy is a **parent-pid watchdog** (not an idle-TTL): a worker started
with ``--parent-pid <supervisor pid>`` polls whether that pid is still alive and
cleanly shuts itself down once the supervisor is gone. A merely-idle-but-alive
session is never touched — liveness is tied to the parent's existence, so a session
stays up exactly as long as its supervisor does.

Liveness is decided cross-platform by :func:`parent_alive`:

* **POSIX** — ``os.kill(pid, 0)`` sends no signal but performs the existence/
  permission check: it returns cleanly when the process exists, raises
  ``ProcessLookupError`` when it does not, and ``PermissionError`` when it exists
  but is owned by another user (still *alive*).
* **Windows** — ``OpenProcess`` the pid for query access, then read its exit code
  with ``GetExitCodeProcess``: a live process reports ``STILL_ACTIVE`` (259). This
  reads the real exit state rather than trusting a lingering handle, so a
  zombie/exited pid is correctly reported dead. A pid that cannot be opened is
  treated as gone.

This module imports only the standard library (and, on Windows, ``ctypes``), so it
is safe in the supervisor's idapro-free graph and unit-testable with the pid check
faked.
"""

from __future__ import annotations

import os
import threading
from typing import Callable, Optional

#: Windows ``GetExitCodeProcess`` sentinel for a still-running process.
_STILL_ACTIVE = 259
#: ``OpenProcess`` access mask: query limited info is enough to read an exit code.
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

#: Default seconds between liveness polls.
DEFAULT_POLL_INTERVAL = 5.0


def _parent_alive_posix(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but owned by another user — still alive.
        return True
    except OSError:
        # Any other error is ambiguous; err on the side of "alive" so a transient
        # fault never kills an otherwise-healthy worker.
        return True
    return True


def _parent_alive_windows(pid: int) -> bool:  # pragma: no cover - exercised on Windows
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION, False, wintypes.DWORD(pid)
    )
    if not handle:
        # Could not open it: either it does not exist or we lack rights. Treat a
        # non-existent process as dead; there is no cheaper authoritative probe.
        return False
    try:
        code = wintypes.DWORD()
        ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        if not ok:
            return True  # ambiguous — keep the worker alive
        return code.value == _STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def parent_alive(pid: int) -> bool:
    """Whether the process ``pid`` is currently alive (cross-platform).

    ``pid <= 0`` is treated as "no real parent" and reported alive so a bogus id
    never triggers a shutdown.
    """
    if pid <= 0:
        return True
    if os.name == "nt":
        return _parent_alive_windows(pid)
    return _parent_alive_posix(pid)


class ParentWatchdog:
    """Polls a parent pid on a daemon thread and fires ``on_parent_dead`` once.

    The callback runs on the watchdog thread the first time the parent is observed
    gone; the thread then exits. :meth:`stop` cancels the watch (e.g. on a normal
    shutdown) so the callback never fires after the worker is already stopping.
    ``alive_check`` is injectable purely so the alive/dead decision can be unit
    tested without a real process.
    """

    def __init__(
        self,
        parent_pid: int,
        on_parent_dead: Callable[[], None],
        *,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        alive_check: Callable[[int], bool] = parent_alive,
    ) -> None:
        self._parent_pid = parent_pid
        self._on_parent_dead = on_parent_dead
        self._poll_interval = max(0.0, float(poll_interval))
        self._alive_check = alive_check
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "ParentWatchdog":
        """Begin watching on a daemon thread; returns ``self`` for chaining."""
        if self._thread is not None:
            return self
        self._thread = threading.Thread(
            target=self._run, name="parent-watchdog", daemon=True
        )
        self._thread.start()
        return self

    def _run(self) -> None:
        # Interruptible wait between polls so ``stop`` unblocks promptly. If the
        # parent is already gone, fire immediately.
        while not self._stop.is_set():
            if not self._alive_check(self._parent_pid):
                # Re-check the cancel flag: a ``stop`` that landed while a slow
                # ``alive_check`` was in flight must win, so we never fire the
                # shutdown callback after the worker is already stopping.
                if self._stop.is_set():
                    return
                self._on_parent_dead()
                return
            # ``Event.wait`` returns True when set — a clean cancel — so break out.
            if self._stop.wait(self._poll_interval):
                return

    def stop(self) -> None:
        """Cancel the watch; the callback will not fire afterwards."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
