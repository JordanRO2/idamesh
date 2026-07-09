"""Unit tests for the per-session private-copy source selection (no IDA).

Locks in the N-copies clone fix: IDA names a database by appending the suffix to
the full input name (``program.exe`` -> ``program.exe.i64``), so the sibling database
must be found by that append form — the previous extension-*replacing* form
(``program.i64``) never matched a real database for an input with an extension, which
forced every N-copies open to re-analyze from scratch. Also covers the locked-.i64
fallback to the raw input.
"""

from __future__ import annotations

import shutil

import pytest

from idamesh.infrastructure.process.scratch_copy import (
    _preferred_source,
    materialize_private_copy,
)


def _touch(path):
    path.write_bytes(b"\x00")
    return path


def test_prefers_appended_database_name(tmp_path):
    exe = _touch(tmp_path / "program.exe")
    i64 = _touch(tmp_path / "program.exe.i64")  # IDA's actual naming
    assert _preferred_source(exe) == i64


def test_falls_back_to_replacing_form(tmp_path):
    exe = _touch(tmp_path / "program.exe")
    alt = _touch(tmp_path / "program.i64")  # extension-replacing form only
    assert _preferred_source(exe) == alt


def test_append_form_wins_over_replacing_form(tmp_path):
    exe = _touch(tmp_path / "program.exe")
    _touch(tmp_path / "program.i64")
    appended = _touch(tmp_path / "program.exe.i64")
    assert _preferred_source(exe) == appended


def test_input_that_is_a_database_is_used_directly(tmp_path):
    i64 = _touch(tmp_path / "program.exe.i64")
    assert _preferred_source(i64) == i64


def test_no_sibling_returns_input(tmp_path):
    exe = _touch(tmp_path / "program.exe")
    assert _preferred_source(exe) == exe


def test_materialize_prefers_i64(tmp_path, monkeypatch):
    exe = _touch(tmp_path / "program.exe")
    _touch(tmp_path / "program.exe.i64")
    monkeypatch.setenv("IDA_MCP_WORKER_SCRATCH", str(tmp_path / "scratch"))
    dest = materialize_private_copy("sess-1", str(exe))
    assert dest.name == "program.exe.i64"
    assert dest.is_file()


def test_materialize_falls_back_when_preferred_source_locked(tmp_path, monkeypatch):
    exe = _touch(tmp_path / "program.exe")
    _touch(tmp_path / "program.exe.i64")
    monkeypatch.setenv("IDA_MCP_WORKER_SCRATCH", str(tmp_path / "scratch"))

    original = shutil.copyfile

    def flaky_copyfile(src, dst, *a, **k):
        if str(src).endswith(".i64"):  # simulate the .i64 being locked in the GUI
            raise OSError("locked")
        return original(src, dst, *a, **k)

    monkeypatch.setattr(shutil, "copyfile", flaky_copyfile)

    dest = materialize_private_copy("sess-2", str(exe))
    assert dest.name == "program.exe"  # fell back to the raw input
    assert dest.is_file()
