"""Unit tests for ``idamesh install`` path-writing (idapro-free).

The install writes a plugin loader stub and a launch spec. These drive the pure
:func:`install_files` (and the CLI ``main``) against a temp user dir — no IDA — and
lock in: both files land in the right places, the loader stub is a valid Python
module that fixes ``sys.path`` and re-exports ``PLUGIN_ENTRY``, the launch spec
records the interpreter/source/module, an existing loader is preserved without
``--force`` and overwritten with it, and the CLI dispatches the subcommand.
"""

from __future__ import annotations

import ast
import json

from idamesh.cli import main as cli_main
from idamesh.cli.install import (
    LAUNCH_SPEC_FILENAME,
    LOADER_FILENAME,
    SUPERVISOR_MODULE,
    install_files,
    main as install_main,
)


def test_install_writes_loader_and_launch_spec(tmp_path):
    user_dir = tmp_path / "ida-user"
    result = install_files(
        user_dir=user_dir,
        python="/usr/bin/python3",
        src="/code/idamesh/src",
    )

    loader = user_dir / "plugins" / LOADER_FILENAME
    launch = user_dir / "mcp" / LAUNCH_SPEC_FILENAME
    assert loader.is_file()
    assert launch.is_file()
    assert result["loader"] == str(loader)
    assert result["launch_spec"] == str(launch)
    assert result["loader_written"] is True


def test_loader_stub_is_valid_python_and_exports_entry(tmp_path):
    user_dir = tmp_path / "ida-user"
    install_files(user_dir=user_dir, python="py", src="/code/src")
    text = (user_dir / "plugins" / LOADER_FILENAME).read_text(encoding="utf-8")

    # Parses as Python.
    ast.parse(text)
    # Re-exports the real entry point and injects the source path.
    assert "from idamesh.bootstrap.plugin_main import PLUGIN_ENTRY" in text
    assert "/code/src" in text
    assert "sys.path.insert" in text


def test_launch_spec_contents(tmp_path):
    user_dir = tmp_path / "ida-user"
    install_files(
        user_dir=user_dir,
        python="/opt/py/python",
        src="/opt/idamesh/src",
        host="127.0.0.1",
        port=9000,
    )
    spec = json.loads((user_dir / "mcp" / LAUNCH_SPEC_FILENAME).read_text(encoding="utf-8"))
    assert spec["python"] == "/opt/py/python"
    assert spec["src"] == "/opt/idamesh/src"
    assert spec["module"] == SUPERVISOR_MODULE
    assert spec["host"] == "127.0.0.1"
    assert spec["port"] == 9000
    assert "written_at" in spec


def test_existing_loader_preserved_without_force(tmp_path):
    user_dir = tmp_path / "ida-user"
    install_files(user_dir=user_dir, python="py", src="/first")
    loader = user_dir / "plugins" / LOADER_FILENAME
    loader.write_text("# hand-edited\n", encoding="utf-8")

    result = install_files(user_dir=user_dir, python="py", src="/second")
    assert result["loader_written"] is False
    assert loader.read_text(encoding="utf-8") == "# hand-edited\n"


def test_force_overwrites_loader(tmp_path):
    user_dir = tmp_path / "ida-user"
    install_files(user_dir=user_dir, python="py", src="/first")
    loader = user_dir / "plugins" / LOADER_FILENAME
    loader.write_text("# hand-edited\n", encoding="utf-8")

    result = install_files(user_dir=user_dir, python="py", src="/second", force=True)
    assert result["loader_written"] is True
    assert "/second" in loader.read_text(encoding="utf-8")


def test_custom_plugins_dir(tmp_path):
    user_dir = tmp_path / "ida-user"
    plugins = tmp_path / "elsewhere" / "plugins"
    result = install_files(
        user_dir=user_dir, plugins_dir=plugins, python="py", src="/s"
    )
    assert (plugins / LOADER_FILENAME).is_file()
    assert result["plugins_dir"] == str(plugins)


def test_cli_install_main_writes_into_user_dir(tmp_path):
    user_dir = tmp_path / "cli-user"
    rc = install_main(["--user-dir", str(user_dir), "--python", "py", "--src", "/s"])
    assert rc == 0
    assert (user_dir / "plugins" / LOADER_FILENAME).is_file()
    assert (user_dir / "mcp" / LAUNCH_SPEC_FILENAME).is_file()


def test_cli_dispatches_install_subcommand(tmp_path):
    user_dir = tmp_path / "dispatch-user"
    rc = cli_main(["install", "--user-dir", str(user_dir), "--python", "py", "--src", "/s"])
    assert rc == 0
    assert (user_dir / "plugins" / LOADER_FILENAME).is_file()
