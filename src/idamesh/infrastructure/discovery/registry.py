"""Filesystem instance registry (idapro-free).

Running IDA instances — the resident GUI plugin and, in principle, headless
workers — advertise themselves by dropping one small JSON file per instance into a
well-known directory under the IDA user dir. The supervisor, which must never load
``idapro``, reads that directory to *discover* and adopt live instances it did not
spawn. Both sides therefore need this module to be pure stdlib.

Layout (the base user dir is resolved by :func:`ida_user_dir`; the
``IDA_MCP_USER_DIR`` environment variable overrides it, so an idapro-free reader —
and the tests — can point it anywhere)::

    {ida_user_dir}/mcp/instances/instance_<port>.json

One record::

    { "session_id": "gui-target-1a2b3c",
      "backend": "gui",              # "gui" (adopted) | "worker" (headless)
      "host": "127.0.0.1", "port": 13337,
      "token": "…",                  # bearer to present when forwarding here
      "pid": 12345,
      "binary": "target.exe", "idb_path": "…/target.exe",
      "started_at": "<iso-8601 utc>" }

Writes are atomic (temp file + :func:`os.replace`). Reads *self-heal*: a record is
dropped (its file unlinked) when its JSON is corrupt, a required key is missing,
its ``pid`` is dead, or — when a ``port_check`` is supplied — its endpoint no
longer accepts a connection (this catches OS pid reuse). Records come back
oldest-first for deterministic ordering.

The unambiguous key is ``session_id``: N duplicate workers of one binary produce N
records with the same ``idb_path`` but distinct ``port``/``pid``/``session_id``, so
path lookup is intentionally ambiguous and :meth:`DiscoveryRegistry.find_by_session`
resolves the exact one.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Mapping, Optional

from idamesh.infrastructure.process.parent_watchdog import parent_alive

#: The two advertised backends. ``gui`` is a live interactive IDA the supervisor
#: adopts (never reaps); ``worker`` is a headless idalib instance.
BACKEND_GUI = "gui"
BACKEND_WORKER = "worker"

#: Environment override for the base IDA user directory (lets the idapro-free
#: reader and the tests run with no IDA install).
USER_DIR_ENV = "IDA_MCP_USER_DIR"
#: IDA's own user-dir variable (may be an ``os.pathsep``-joined list; first wins).
IDAUSR_ENV = "IDAUSR"

#: Subdirectories under the user dir where instance records live.
_REGISTRY_SUBPATH = ("mcp", "instances")
#: Instance-file prefix; the full name is ``instance_<port>.json``.
_FILE_PREFIX = "instance_"
_FILE_SUFFIX = ".json"

#: Keys a record must carry to be considered valid.
_REQUIRED_KEYS = ("session_id", "backend", "host", "port")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ida_user_dir() -> Path:
    """Resolve the base IDA user directory without importing IDA.

    Order: ``IDA_MCP_USER_DIR`` → the first entry of ``IDAUSR`` → the platform
    default (``%APPDATA%/Hex-Rays/IDA Pro`` on Windows, ``~/.idapro`` elsewhere).
    """
    override = os.environ.get(USER_DIR_ENV)
    if override:
        return Path(override)
    idausr = os.environ.get(IDAUSR_ENV)
    if idausr:
        first = idausr.split(os.pathsep)[0].strip()
        if first:
            return Path(first)
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Roaming"
        return root / "Hex-Rays" / "IDA Pro"
    return Path.home() / ".idapro"


def registry_dir() -> Path:
    """The directory instance records live in (``{ida_user_dir}/mcp/instances``)."""
    return ida_user_dir().joinpath(*_REGISTRY_SUBPATH)


@dataclass
class DiscoveryEntry:
    """One advertised MCP instance."""

    session_id: str
    backend: str
    host: str
    port: int
    token: Optional[str] = None
    pid: Optional[int] = None
    binary: Optional[str] = None
    idb_path: Optional[str] = None
    started_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict:
        """The JSON document written to disk."""
        return {
            "session_id": self.session_id,
            "backend": self.backend,
            "host": self.host,
            "port": self.port,
            "token": self.token,
            "pid": self.pid,
            "binary": self.binary,
            "idb_path": self.idb_path,
            "started_at": self.started_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "DiscoveryEntry":
        """Parse and validate a record; raise ``ValueError`` if malformed.

        The required keys must be present and ``port`` must be a plain integer
        (JSON ``true``/``false`` are ``bool`` — a subclass of ``int`` — so they are
        rejected explicitly).
        """
        if not isinstance(data, Mapping):
            raise ValueError("instance record is not an object")
        for key in _REQUIRED_KEYS:
            if key not in data or data[key] is None:
                raise ValueError(f"instance record missing required key {key!r}")
        port = data["port"]
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError(f"instance record has a non-integer port: {port!r}")
        session_id = data["session_id"]
        backend = data["backend"]
        host = data["host"]
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("instance record has an empty session_id")
        if not isinstance(backend, str) or not backend:
            raise ValueError("instance record has an empty backend")
        if not isinstance(host, str) or not host:
            raise ValueError("instance record has an empty host")
        pid = data.get("pid")
        if pid is not None and (isinstance(pid, bool) or not isinstance(pid, int)):
            raise ValueError(f"instance record has a non-integer pid: {pid!r}")
        return cls(
            session_id=session_id,
            backend=backend,
            host=host,
            port=port,
            token=_opt_str(data.get("token")),
            pid=pid,
            binary=_opt_str(data.get("binary")),
            idb_path=_opt_str(data.get("idb_path")),
            started_at=_opt_str(data.get("started_at")) or _utc_now_iso(),
        )


def _opt_str(value: object) -> Optional[str]:
    return value if isinstance(value, str) else None


class DiscoveryRegistry:
    """Reader/writer of the filesystem instance registry.

    ``directory`` overrides the resolved :func:`registry_dir` (used by tests). The
    liveness probes are injectable: ``alive_check(pid)`` decides whether a record's
    process still exists (default the cross-platform :func:`parent_alive`), and an
    optional ``port_check(host, port)`` gates on the endpoint still accepting a
    connection (defence against OS pid reuse). Neither is invoked when a record
    carries no ``pid`` / no ``port_check`` is configured.
    """

    def __init__(
        self,
        directory: Optional[os.PathLike] = None,
        *,
        alive_check: Callable[[int], bool] = parent_alive,
        port_check: Optional[Callable[[str, int], bool]] = None,
    ) -> None:
        self._directory = Path(directory) if directory is not None else None
        self._alive_check = alive_check
        self._port_check = port_check

    # -- location -----------------------------------------------------------

    @property
    def directory(self) -> Path:
        """The instance directory (resolved lazily so an env change is honored)."""
        return self._directory if self._directory is not None else registry_dir()

    def _file_for_port(self, port: int) -> Path:
        return self.directory / f"{_FILE_PREFIX}{port}{_FILE_SUFFIX}"

    # -- writing ------------------------------------------------------------

    def write(self, entry: DiscoveryEntry) -> Path:
        """Atomically write ``entry``'s record; return the file path.

        Creates the registry directory if absent (tight permissions on POSIX,
        best-effort). The write is temp-file + :func:`os.replace`, so a concurrent
        reader never sees a partially written file.
        """
        directory = self.directory
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        target = self._file_for_port(entry.port)
        payload = json.dumps(entry.to_dict(), ensure_ascii=False, indent=2)
        fd, tmp_name = tempfile.mkstemp(
            prefix=_FILE_PREFIX, suffix=_FILE_SUFFIX + ".tmp", dir=str(directory)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(tmp_name, target)
        except BaseException:
            _silent_unlink(Path(tmp_name))
            raise
        return target

    # -- removal ------------------------------------------------------------

    def remove_port(self, port: int) -> bool:
        """Remove the record for ``port``; ``True`` if a file was deleted."""
        path = self._file_for_port(port)
        if path.exists():
            _silent_unlink(path)
            return not path.exists()
        return False

    def remove_session(self, session_id: str) -> bool:
        """Remove the record whose ``session_id`` matches; ``True`` if one was."""
        for path, entry in self._iter_valid_files():
            if entry.session_id == session_id:
                _silent_unlink(path)
                return not path.exists()
        return False

    # -- reading ------------------------------------------------------------

    def read_all(self) -> List[DiscoveryEntry]:
        """Every live, valid record, oldest-first.

        Self-heals as it scans: a corrupt/incomplete record, a dead ``pid``, or (if
        a ``port_check`` is configured) an unreachable endpoint has its file
        unlinked and is omitted.
        """
        directory = self.directory
        if not directory.is_dir():
            return []
        entries: List[DiscoveryEntry] = []
        for path in sorted(directory.glob(f"{_FILE_PREFIX}*{_FILE_SUFFIX}")):
            entry = self._read_valid(path)
            if entry is None:
                continue
            if not self._is_live(entry):
                _silent_unlink(path)
                continue
            entries.append(entry)
        entries.sort(key=lambda e: (e.started_at, e.port))
        return entries

    def find_by_session(self, session_id: str) -> Optional[DiscoveryEntry]:
        """The live record for ``session_id`` (the unambiguous key), or ``None``."""
        for entry in self.read_all():
            if entry.session_id == session_id:
                return entry
        return None

    # -- internals ----------------------------------------------------------

    def _iter_valid_files(self):
        directory = self.directory
        if not directory.is_dir():
            return
        for path in sorted(directory.glob(f"{_FILE_PREFIX}*{_FILE_SUFFIX}")):
            entry = self._read_valid(path)
            if entry is not None:
                yield path, entry

    def _read_valid(self, path: Path) -> Optional[DiscoveryEntry]:
        try:
            text = path.read_text(encoding="utf-8")
            data = json.loads(text)
            return DiscoveryEntry.from_dict(data)
        except (OSError, ValueError, TypeError):
            # Corrupt or incomplete — drop it so the registry self-heals.
            _silent_unlink(path)
            return None

    def _is_live(self, entry: DiscoveryEntry) -> bool:
        if entry.pid is not None and not self._alive_check(entry.pid):
            return False
        if self._port_check is not None and not self._port_check(entry.host, entry.port):
            return False
        return True


def _silent_unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def tcp_port_open(host: str, port: int, *, timeout: float = 0.5) -> bool:
    """Whether a TCP connect to ``host:port`` succeeds within ``timeout``.

    A ready-made ``port_check`` for :class:`DiscoveryRegistry` that catches an OS
    pid that was reused after an instance died. Kept separate so the default
    registry stays purely pid-based (a live pid whose socket is briefly busy is not
    falsely evicted).
    """
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
