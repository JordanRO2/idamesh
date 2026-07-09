"""Unit tests for :class:`IdaDecompilerGateway` (no IDA; fake ida_* modules).

Locks in the two INTERR-52813 / idalib fixes:

* the invocation passes ``DECOMP_NO_WAIT | DECOMP_NO_CACHE`` plus an explicit
  ``hexrays_failure_t`` — the ``DECOMP_NO_CACHE`` bit is what keeps a scripted
  decompile from evicting a live GUI pseudocode view's cached microcode (the
  INTERR 52813 "deleted stale microcode" trigger);
* pseudocode text extraction falls back to ``str(cfunc)`` when the
  ``get_pseudocode()`` strvec yields untyped ``SwigPyObject`` elements (the idalib
  binding, where ``sv[i].line`` is unavailable), and uses the typed per-line access
  otherwise (the full GUI binding).
"""

from __future__ import annotations

import sys
import types

import pytest

from idamesh.domain.values.address import Address
from idamesh.infrastructure.ida.decompiler_adapter import (
    DecompilationError,
    IdaDecompilerGateway,
)


class _DecompilationFailure(Exception):
    pass


class _Strvec:
    """Minimal ``strvec_t`` stand-in: ``size()`` + indexing."""

    def __init__(self, items):
        self._items = items

    def size(self):
        return len(self._items)

    def __getitem__(self, i):
        return self._items[i]


class _Cfunc:
    def __init__(self, sv, text):
        self._sv = sv
        self._text = text

    def get_pseudocode(self):
        return self._sv

    def __str__(self):
        return self._text


def _install_fakes(monkeypatch, *, cfunc, hf_code=0):
    """Install fake ida_hexrays / ida_lines / ida_funcs; return the call recorder."""
    recorder = {}

    class _Failure:
        def __init__(self):
            self.code = hf_code

    def _decompile(target, hf, flags):
        recorder["target"] = target
        recorder["hf"] = hf
        recorder["flags"] = flags
        if isinstance(cfunc, BaseException):
            raise cfunc
        return cfunc

    fake_hexrays = types.SimpleNamespace(
        init_hexrays_plugin=lambda: True,
        DECOMP_NO_WAIT=0x1,
        DECOMP_NO_CACHE=0x2,
        hexrays_failure_t=_Failure,
        DecompilationFailure=_DecompilationFailure,
        decompile=_decompile,
    )
    fake_lines = types.SimpleNamespace(tag_remove=lambda s: s)
    fake_funcs = types.SimpleNamespace(get_func_name=lambda ea: "the_func")

    monkeypatch.setitem(sys.modules, "ida_hexrays", fake_hexrays)
    monkeypatch.setitem(sys.modules, "ida_lines", fake_lines)
    monkeypatch.setitem(sys.modules, "ida_funcs", fake_funcs)
    return recorder


def test_decompile_uses_no_cache_no_wait_flags_and_typed_lines(monkeypatch):
    sv = _Strvec([types.SimpleNamespace(line="int f()"), types.SimpleNamespace(line="{ }")])
    cfunc = _Cfunc(sv, "SHOULD-NOT-BE-USED")
    rec = _install_fakes(monkeypatch, cfunc=cfunc)

    pc = IdaDecompilerGateway().decompile(Address(0x401000))

    # The cache-isolation + no-waitbox flags must be present (this is the fix).
    assert rec["flags"] == 0x1 | 0x2
    assert rec["hf"] is not None
    assert rec["target"] == 0x401000
    # Typed strvec path used (not the str() fallback).
    assert pc.lines == ("int f()", "{ }")
    assert pc.text == "int f()\n{ }"


def test_pseudocode_falls_back_to_str_when_strvec_untyped(monkeypatch):
    # idalib: sv[i] is an untyped object with no ``.line`` -> AttributeError.
    sv = _Strvec([object(), object()])
    cfunc = _Cfunc(sv, "line1\nline2\nline3\n")
    _install_fakes(monkeypatch, cfunc=cfunc)

    pc = IdaDecompilerGateway().decompile(Address(0x401000))

    # Falls back to str(cfunc).splitlines() (trailing blank dropped).
    assert pc.lines == ("line1", "line2", "line3")
    assert pc.text == "line1\nline2\nline3"


def test_decompile_none_raises_with_failure_code(monkeypatch):
    _install_fakes(monkeypatch, cfunc=None, hf_code=42)

    with pytest.raises(DecompilationError) as exc:
        IdaDecompilerGateway().decompile(Address(0x401000))
    assert "code=42" in str(exc.value)


def test_decompilation_failure_becomes_domain_error(monkeypatch):
    _install_fakes(monkeypatch, cfunc=_DecompilationFailure("boom"))

    with pytest.raises(DecompilationError) as exc:
        IdaDecompilerGateway().decompile(Address(0x401000))
    assert "decompilation failed" in str(exc.value)
