"""Resident IDA GUI plugin (composition root for the live-database runtime).

This is the fourth composition root, alongside the headless worker and the
supervisor. It runs *inside* the user's interactive IDA (``idaq``) and serves the
same MCP surface over the **live** database the user is looking at, so an agent can
drive the real GUI session and the supervisor can adopt it.

Wiring, on plugin load:

* build the worker container over the live database, binding
  :class:`~idamesh.infrastructure.ida.execute_sync.ExecuteSyncExecutor` — the MCP
  HTTP server runs on a background thread, so every use-case is marshalled onto
  IDA's kernel (UI) thread via ``execute_sync(MFF_WRITE)``;
* serve MCP over :class:`~idamesh.infrastructure.transport.http.HttpTransport` on a
  configurable loopback port (default 13337) guarded by a bearer token;
* register this instance in the filesystem discovery registry
  (``backend="gui"``, its host/port/token/pid/session) so the supervisor can find
  and route to it.

Lifecycle: start on ``init`` (kept resident with ``PLUGIN_FIX``), stop on ``term``
(the transport is shut down and the discovery record removed). A supervisor is
**not** auto-launched by default — that is opt-in via ``IDAMESH_AUTOLAUNCH_SUPERVISOR``.

**Import-clean without IDA.** Every ``idaapi``/``ida_*`` import is deferred into a
method body or into :func:`PLUGIN_ENTRY` (the plugin class subclasses
``idaapi.plugin_t``, which only exists inside IDA), so this module imports cleanly
under plain CPython for unit tests and the architecture import-contract checks.
The plugin loader/entry code here is authored fresh for idamesh.
"""

from __future__ import annotations

import os
import secrets
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Tuple

#: Loopback bind + default port for the plugin's MCP endpoint (env-overridable).
DEFAULT_PLUGIN_HOST = "127.0.0.1"
DEFAULT_PLUGIN_PORT = 13337

#: Environment surface (all optional).
ENV_HOST = "IDAMESH_PLUGIN_HOST"
ENV_PORT = "IDAMESH_PLUGIN_PORT"
ENV_TOKEN = "IDAMESH_PLUGIN_TOKEN"
ENV_AUTOLAUNCH = "IDAMESH_AUTOLAUNCH_SUPERVISOR"

#: Default supervisor endpoint probed/spawned by the opt-in auto-launch.
DEFAULT_SUPERVISOR_HOST = "127.0.0.1"
DEFAULT_SUPERVISOR_PORT = 8745
SUPERVISOR_MODULE = "idamesh.bootstrap.supervisor_main"


@dataclass(frozen=True)
class PluginConfig:
    """The resolved runtime configuration for one plugin load."""

    host: str
    port: int
    token: str
    autolaunch: bool


def _parse_port(raw: Optional[str], default: int) -> int:
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


def _truthy(raw: Optional[str]) -> bool:
    return str(raw).strip().lower() in {"1", "true", "yes", "on"} if raw else False


def resolve_plugin_config(env: Optional[Mapping[str, str]] = None) -> PluginConfig:
    """Resolve the plugin configuration from the environment (pure, testable).

    A missing ``IDAMESH_PLUGIN_TOKEN`` mints a fresh random bearer secret so the
    endpoint is never unauthenticated by accident; a pinned token (so a client can
    be configured out-of-band) is honored when present. ``port`` ``0`` requests an
    OS-assigned ephemeral port.
    """
    env = os.environ if env is None else env
    host = env.get(ENV_HOST) or DEFAULT_PLUGIN_HOST
    port = _parse_port(env.get(ENV_PORT), DEFAULT_PLUGIN_PORT)
    token = env.get(ENV_TOKEN) or secrets.token_hex(16)
    autolaunch = _truthy(env.get(ENV_AUTOLAUNCH))
    return PluginConfig(host=host, port=port, token=token, autolaunch=autolaunch)


def _safe_stem(name: str) -> str:
    stem = Path(name).stem or "idb"
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in stem)


class PluginServer:
    """Owns the live-database MCP endpoint and its discovery registration.

    Split out from the ``plugin_t`` shell so its start/stop can be reasoned about
    (and the pure parts unit-tested) without IDA. ``start`` builds the container
    over the live database, binds the HTTP transport, and writes the discovery
    record; ``stop`` reverses both. The ``registry`` is injectable for tests.
    """

    def __init__(
        self,
        config: Optional[PluginConfig] = None,
        *,
        registry: Optional[object] = None,
    ) -> None:
        self._config = config or resolve_plugin_config()
        self._registry = registry
        self._transport = None
        self._container = None
        self._session_id: Optional[str] = None
        self._bound_port: Optional[int] = None
        self._started = False

    # -- accessors (handy for logging / tests) ------------------------------

    @property
    def config(self) -> PluginConfig:
        return self._config

    @property
    def session_id(self) -> Optional[str]:
        return self._session_id

    @property
    def bound_port(self) -> Optional[int]:
        return self._bound_port

    @property
    def is_running(self) -> bool:
        return self._started

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> "PluginServer":
        """Build the container, serve MCP, and register in discovery.

        Called from the plugin's ``init`` on IDA's UI thread, so the direct SDK
        reads for the database identity are main-thread-safe. Raises on a genuine
        wiring failure (the caller decides whether to skip the plugin).
        """
        if self._started:
            return self

        from idamesh.bootstrap.container import build_worker_container
        from idamesh.infrastructure.ida.execute_sync import ExecuteSyncExecutor
        from idamesh.infrastructure.transport.http import HttpTransport

        # start() runs on IDA's kernel/UI thread (see the method docstring), so
        # this ident IS the kernel thread. Pin it so ExecuteSyncExecutor.
        # on_kernel_thread() is a deterministic ident comparison rather than a
        # fragile is_main_thread() probe: every HTTP background-thread request then
        # always marshals through execute_sync(MFF_WRITE) onto this thread.
        executor = ExecuteSyncExecutor(kernel_thread_id=threading.get_ident())
        container = build_worker_container(executor=executor)
        transport = HttpTransport(
            container.router,
            host=self._config.host,
            port=self._config.port,
            bearer_token=self._config.token,
            supported_protocol_versions=container.protocol_versions,
        )
        transport.serve(block=False)

        self._container = container
        self._transport = transport
        self._bound_port = transport.bound_port

        binary, idb_path = self._database_identity()
        self._session_id = f"gui-{_safe_stem(binary or 'idb')}-{secrets.token_hex(3)}"
        self._register(binary, idb_path)

        if self._config.autolaunch:
            self._maybe_autolaunch()

        self._started = True
        return self

    def stop(self) -> None:
        """Remove the discovery record and shut the transport down (never raises)."""
        try:
            self._deregister()
        finally:
            transport, self._transport = self._transport, None
            if transport is not None:
                try:
                    transport.stop()
                except Exception:  # noqa: BLE001 — teardown is best-effort
                    pass
            self._started = False

    # -- discovery ----------------------------------------------------------

    def _discovery_registry(self):
        if self._registry is not None:
            return self._registry
        from idamesh.infrastructure.discovery import DiscoveryRegistry

        self._registry = DiscoveryRegistry()
        return self._registry

    def _register(self, binary: str, idb_path: str) -> None:
        from idamesh.infrastructure.discovery import BACKEND_GUI, DiscoveryEntry

        entry = DiscoveryEntry(
            session_id=self._session_id or "gui",
            backend=BACKEND_GUI,
            host=self._config.host,
            port=self._bound_port or self._config.port,
            token=self._config.token,
            pid=os.getpid(),
            binary=binary or None,
            idb_path=idb_path or None,
        )
        self._discovery_registry().write(entry)

    def _deregister(self) -> None:
        if self._bound_port is None:
            return
        try:
            self._discovery_registry().remove_port(self._bound_port)
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass

    # -- IDA-side reads (lazy SDK) ------------------------------------------

    def _database_identity(self) -> Tuple[str, str]:
        """The open database's ``(binary_name, input_path)`` (best-effort).

        Wrapped so a headless/odd environment (or a call before a database is
        loaded) yields empty strings rather than failing the whole start.
        """
        try:
            import ida_nalt

            idb_path = ida_nalt.get_input_file_path() or ""
            binary = ida_nalt.get_root_filename() or os.path.basename(idb_path)
            return binary or "", idb_path or ""
        except Exception:  # noqa: BLE001 — identity is informational only
            return "", ""

    # -- opt-in supervisor auto-launch --------------------------------------

    def _maybe_autolaunch(self) -> None:
        """Best-effort: ensure one shared supervisor is running (opt-in only).

        Probes the configured supervisor endpoint; if something already answers a
        TCP connect, do nothing (N GUIs share one supervisor). Otherwise spawn it
        detached and windowless, with ``IDADIR``/``PYTHONPATH`` prepared so its
        headless workers can import ``idalib``. Any failure is swallowed — a broken
        auto-launch must never break the GUI.
        """
        try:
            from idamesh.infrastructure.discovery import tcp_port_open

            host = os.environ.get("IDA_MCP_SUPERVISOR_HOST", DEFAULT_SUPERVISOR_HOST)
            port = _parse_port(
                os.environ.get("IDA_MCP_SUPERVISOR_PORT"), DEFAULT_SUPERVISOR_PORT
            )
            if tcp_port_open(host, port):
                return  # a supervisor is already up — one shared singleton.
            self._spawn_supervisor(host, port)
        except Exception:  # noqa: BLE001 — never let auto-launch break the plugin
            pass

    def _spawn_supervisor(self, host: str, port: int) -> None:
        import subprocess

        python = os.environ.get("IDA_MCP_SUPERVISOR_PYTHON") or sys.executable
        argv = [
            python,
            "-m",
            SUPERVISOR_MODULE,
            "--host",
            host,
            "--port",
            str(port),
        ]
        env = dict(os.environ)
        # Point spawned workers at an IDA install for idalib and at our source.
        idadir = env.get("IDADIR")
        if idadir:
            env["IDADIR"] = idadir
        src = str(Path(__file__).resolve().parents[2])
        existing = env.get("PYTHONPATH", "")
        if src and src not in existing.split(os.pathsep):
            env["PYTHONPATH"] = src + (os.pathsep + existing if existing else "")

        popen_kwargs: dict = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "env": env,
        }
        if os.name == "nt":
            no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            popen_kwargs["creationflags"] = no_window | new_group
        else:
            popen_kwargs["start_new_session"] = True
        subprocess.Popen(argv, **popen_kwargs)  # noqa: S603 — detached singleton


def PLUGIN_ENTRY():  # noqa: N802 — IDA's required entry-point symbol
    """IDA calls this to obtain the plugin object (imports ``idaapi`` lazily)."""
    import idaapi

    # Resolve PluginServer through an explicit import, not the bare module global:
    # IDA loads the plugin via the installed loader stub and runs PLUGIN_ENTRY with
    # that stub module's namespace as its globals (the stub only imported
    # PLUGIN_ENTRY), so a bare ``PluginServer`` reference NameErrors. The import
    # resolves through sys.modules and is independent of this function's globals.
    from idamesh.bootstrap.plugin_main import PluginServer

    server = PluginServer()

    class IdameshPlugin(idaapi.plugin_t):
        """A resident plugin that serves MCP over the live database."""

        # PLUGIN_FIX keeps the plugin loaded for the whole session; PLUGIN_HIDE
        # keeps it out of the Edit/Plugins menu (it has no interactive action).
        flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE
        wanted_name = "idamesh"
        wanted_hotkey = ""
        comment = "Serve the idamesh MCP endpoint over the live IDA database."
        help = (
            "Starts an MCP server bound to loopback over the open database and "
            "registers it for the idamesh supervisor to adopt."
        )

        def init(self):
            try:
                server.start()
            except Exception as exc:  # noqa: BLE001 — report and decline to load
                try:
                    idaapi.msg(f"[idamesh] failed to start: {exc}\n")
                except Exception:  # noqa: BLE001
                    pass
                return idaapi.PLUGIN_SKIP
            try:
                idaapi.msg(
                    f"[idamesh] MCP endpoint on {server.config.host}:"
                    f"{server.bound_port} (session {server.session_id})\n"
                )
            except Exception:  # noqa: BLE001
                pass
            return idaapi.PLUGIN_KEEP

        def run(self, arg):  # noqa: D401 — no interactive action; resident only
            return None

        def term(self):
            server.stop()

    return IdameshPlugin()
