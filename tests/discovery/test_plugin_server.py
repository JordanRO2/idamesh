"""Tests for the GUI plugin's server/config layer (headless, no IDA).

The ``plugin_t`` shell needs ``idaapi`` and cannot run without a live IDA, but its
:class:`PluginServer` and the pure config resolver can. Because the worker
container's IDA adapters import lazily and the plugin's database-identity read is
wrapped, ``PluginServer.start`` actually stands a real MCP HTTP endpoint up over an
(empty) container with no IDA present — enough to prove the discovery registration
round-trips and is torn down on stop. The live-database behaviour itself is only
verifiable inside real IDA.
"""

from __future__ import annotations

from idamesh.bootstrap.plugin_main import (
    DEFAULT_PLUGIN_HOST,
    DEFAULT_PLUGIN_PORT,
    PluginConfig,
    PluginServer,
    resolve_plugin_config,
)
from idamesh.infrastructure.discovery import DiscoveryRegistry


# --------------------------------------------------------------------------- #
# config resolution (pure)
# --------------------------------------------------------------------------- #


def test_config_defaults_mint_a_token():
    cfg = resolve_plugin_config({})
    assert cfg.host == DEFAULT_PLUGIN_HOST
    assert cfg.port == DEFAULT_PLUGIN_PORT
    assert cfg.token  # a random bearer secret is always present
    assert cfg.autolaunch is False


def test_config_reads_env_overrides():
    cfg = resolve_plugin_config(
        {
            "IDAMESH_PLUGIN_HOST": "127.0.0.1",
            "IDAMESH_PLUGIN_PORT": "9999",
            "IDAMESH_PLUGIN_TOKEN": "pinned",
            "IDAMESH_AUTOLAUNCH_SUPERVISOR": "1",
        }
    )
    assert cfg.port == 9999
    assert cfg.token == "pinned"
    assert cfg.autolaunch is True


def test_config_bad_port_falls_back():
    assert resolve_plugin_config({"IDAMESH_PLUGIN_PORT": "not-a-port"}).port == DEFAULT_PLUGIN_PORT


def test_config_autolaunch_is_off_by_default_for_unknown_value():
    assert resolve_plugin_config({"IDAMESH_AUTOLAUNCH_SUPERVISOR": "maybe"}).autolaunch is False


# --------------------------------------------------------------------------- #
# server start/stop + discovery registration (integration, no IDA)
# --------------------------------------------------------------------------- #


def test_server_registers_and_deregisters(tmp_path):
    registry = DiscoveryRegistry(tmp_path / "instances", alive_check=lambda pid: True)
    # Ephemeral port so the test never collides with a real 13337.
    config = PluginConfig(host="127.0.0.1", port=0, token="tok-abc", autolaunch=False)
    server = PluginServer(config, registry=registry)

    server.start()
    try:
        assert server.is_running
        assert server.bound_port and server.bound_port > 0
        entries = registry.read_all()
        assert len(entries) == 1
        entry = entries[0]
        assert entry.backend == "gui"
        assert entry.host == "127.0.0.1"
        assert entry.port == server.bound_port
        assert entry.token == "tok-abc"
        assert entry.session_id == server.session_id
        assert entry.session_id.startswith("gui-")
    finally:
        server.stop()

    # Stop removes the record and marks the server down.
    assert server.is_running is False
    assert registry.read_all() == []


def test_server_start_is_idempotent(tmp_path):
    registry = DiscoveryRegistry(tmp_path / "instances", alive_check=lambda pid: True)
    config = PluginConfig(host="127.0.0.1", port=0, token="t", autolaunch=False)
    server = PluginServer(config, registry=registry)
    try:
        server.start()
        first_port = server.bound_port
        server.start()  # second call is a no-op
        assert server.bound_port == first_port
        assert len(registry.read_all()) == 1
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# PLUGIN_ENTRY under IDA's namespace handling (regression)
# --------------------------------------------------------------------------- #


def test_plugin_entry_resolves_pluginserver_under_alien_globals(monkeypatch):
    """IDA loads the plugin through the installed loader stub and runs
    ``PLUGIN_ENTRY`` with that stub module's namespace as its globals — a namespace
    that does not contain ``PluginServer``. Regression for the ``NameError: name
    'PluginServer' is not defined`` seen live: the entry must resolve it via an
    explicit import, not a bare module global.
    """
    import builtins
    import sys
    import types

    from idamesh.bootstrap.plugin_main import PLUGIN_ENTRY

    # Minimal fake idaapi so the plugin_t subclass + flags resolve without IDA.
    fake = types.ModuleType("idaapi")
    fake.plugin_t = type("plugin_t", (), {})
    fake.PLUGIN_FIX = 1
    fake.PLUGIN_HIDE = 2
    fake.PLUGIN_SKIP = 0
    fake.PLUGIN_KEEP = 3
    fake.msg = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, "idaapi", fake)
    kernwin = types.ModuleType("ida_kernwin")
    kernwin.UI_Hooks = type("UI_Hooks", (), {"hook": lambda self: True, "unhook": lambda self: True})
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    # Re-home PLUGIN_ENTRY into a foreign globals dict, as IDA effectively does.
    alien = types.FunctionType(PLUGIN_ENTRY.__code__, {"__builtins__": builtins})
    plugin = alien()  # must NOT raise NameError on PluginServer

    assert isinstance(plugin, fake.plugin_t)


# --------------------------------------------------------------------------- #
# supervisor auto-launch interpreter selection
# --------------------------------------------------------------------------- #


def test_supervisor_python_prefers_env_then_launch_spec_then_python_exe(
    tmp_path, monkeypatch
):
    import json
    import sys

    from idamesh.bootstrap import plugin_main

    monkeypatch.setenv("IDA_MCP_USER_DIR", str(tmp_path))
    monkeypatch.delenv("IDA_MCP_SUPERVISOR_PYTHON", raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "ida64.exe"))
    # No env, no launch.json, sys.executable is the IDA binary -> nothing to launch.
    assert plugin_main._supervisor_python() is None

    (tmp_path / "mcp").mkdir()
    (tmp_path / "mcp" / "launch.json").write_text(json.dumps({"python": "/opt/py/python3"}))
    assert plugin_main._supervisor_python() == "/opt/py/python3"

    monkeypatch.setenv("IDA_MCP_SUPERVISOR_PYTHON", "/env/python")
    assert plugin_main._supervisor_python() == "/env/python"

    monkeypatch.delenv("IDA_MCP_SUPERVISOR_PYTHON")
    (tmp_path / "mcp" / "launch.json").unlink()
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python3.12"))
    assert plugin_main._supervisor_python() == str(tmp_path / "python3.12")


def test_spawn_supervisor_skips_when_no_python(tmp_path, monkeypatch):
    import subprocess
    import sys

    from idamesh.bootstrap.plugin_main import PluginConfig, PluginServer

    monkeypatch.setenv("IDA_MCP_USER_DIR", str(tmp_path))
    monkeypatch.delenv("IDA_MCP_SUPERVISOR_PYTHON", raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "ida64.exe"))
    popen = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: popen.append(a))
    server = PluginServer(PluginConfig("127.0.0.1", 0, "t", True))
    server._spawn_supervisor("127.0.0.1", 8745)
    assert popen == []


def test_start_stops_transport_when_registration_fails(tmp_path):
    import pytest

    class _LockedRegistry:
        def write(self, entry):
            raise PermissionError("registry file locked")

        def remove_port(self, port):
            return False

    config = PluginConfig(host="127.0.0.1", port=0, token="t", autolaunch=False)
    server = PluginServer(config, registry=_LockedRegistry())
    with pytest.raises(PermissionError):
        server.start()
    assert server.is_running is False
    assert server._transport is None  # listener was shut down, not leaked


def test_database_identity_separates_input_path_from_idb_path(monkeypatch):
    import sys
    import types

    nalt = types.ModuleType("ida_nalt")
    nalt.get_input_file_path = lambda: "C:/bins/target.exe"
    nalt.get_root_filename = lambda: "target.exe"
    loader = types.ModuleType("ida_loader")
    loader.PATH_TYPE_IDB = 1
    loader.get_path = lambda kind: "C:/bins/target.exe.i64" if kind == 1 else ""
    monkeypatch.setitem(sys.modules, "ida_nalt", nalt)
    monkeypatch.setitem(sys.modules, "ida_loader", loader)

    server = PluginServer(PluginConfig("127.0.0.1", 0, "t", False))
    assert server._database_identity() == (
        "target.exe",
        "C:/bins/target.exe",
        "C:/bins/target.exe.i64",
    )


def test_refresh_identity_fills_the_record_once_a_database_is_open(tmp_path, monkeypatch):
    registry = DiscoveryRegistry(tmp_path / "instances", alive_check=lambda pid: True)
    config = PluginConfig(host="127.0.0.1", port=0, token="tok", autolaunch=False)
    server = PluginServer(config, registry=registry)
    server.start()  # no IDA here: identity reads empty, as at IDA startup
    try:
        assert registry.read_all()[0].idb_path is None
        monkeypatch.setattr(
            server,
            "_database_identity",
            lambda: ("Rag2.exe", "I:/old/Rag2.exe", "C:/new/Rag2.exe.i64"),
        )

        server.refresh_identity()

        entry = registry.read_all()[0]
        assert (entry.binary, entry.input_path, entry.idb_path) == (
            "Rag2.exe",
            "I:/old/Rag2.exe",
            "C:/new/Rag2.exe.i64",
        )
        assert entry.session_id == server.session_id
        assert entry.session_id.startswith("gui-Rag2-")  # named after the loaded binary
        assert len(registry.read_all()) == 1  # same per-port record, not a second one
    finally:
        server.stop()
