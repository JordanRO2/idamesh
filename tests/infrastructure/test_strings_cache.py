"""Unit tests for StringsCache's SDK-level build (no IDA; fake ida_* modules).

Locks in the UTF-16 strings fix:

* the scan is widened to 1-byte / UTF-16 / UTF-32 (``strtypes``) before building,
  so a binary whose text is UTF-16 lists its strings — and the caller's previous
  Strings-window options are restored afterward;
* enumeration reads the string list directly (``get_strlist_item``), not via
  ``idautils.Strings`` (which would re-run its own 1-byte-only setup);
* each item is decoded with a single UTF-8 decode, because ``get_strlit_contents``
  already returns the width-decoded text UTF-8 encoded (a width-based re-decode
  garbles Unicode).
"""

from __future__ import annotations

import sys
import types

import pytest

from idamesh.infrastructure.ida.cache.strings_cache import StringsCache


class _Opts:
    def __init__(self):
        self.strtypes = [0]
        self.minlen = 5
        self.display_only_existing_strings = True


def _install(monkeypatch, items):
    """items: list of (ea, length, strtype, utf8_contents_bytes)."""
    opts = _Opts()
    state = {"build_strtypes": None, "build_existing": None}

    def build_strlist():
        state["build_strtypes"] = list(opts.strtypes)
        state["build_existing"] = opts.display_only_existing_strings

    def get_strlist_item(info, i):
        ea, length, strtype, _ = items[i]
        info.ea, info.length, info.type = ea, length, strtype
        return True

    ida_strlist = types.SimpleNamespace(
        get_strlist_options=lambda: opts,
        build_strlist=build_strlist,
        get_strlist_qty=lambda: len(items),
        get_strlist_item=get_strlist_item,
        string_info_t=lambda: types.SimpleNamespace(ea=0, length=0, type=0),
    )
    ida_nalt = types.SimpleNamespace(
        STRTYPE_C=0, STRTYPE_C_16=1, STRTYPE_C_32=2,
        STRWIDTH_MASK=0x03, STRWIDTH_2B=0x01, STRWIDTH_4B=0x02,
    )
    contents = {ea: raw for (ea, _l, _t, raw) in items}
    ida_bytes = types.SimpleNamespace(
        get_strlit_contents=lambda ea, length, strtype: contents.get(ea)
    )
    monkeypatch.setitem(sys.modules, "ida_strlist", ida_strlist)
    monkeypatch.setitem(sys.modules, "ida_nalt", ida_nalt)
    monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)
    return opts, state


def test_build_widens_scan_to_unicode_then_restores(monkeypatch):
    opts, state = _install(
        monkeypatch,
        [(0x1000, 5, 0, b"hello"), (0x2000, 10, 1, b"World")],
    )

    rows = StringsCache()._build()

    # The build ran with 1-byte + UTF-16 + UTF-32 widths, in scan mode.
    assert state["build_strtypes"] == [0, 1, 2]
    assert state["build_existing"] is False
    # The caller's options were restored afterward.
    assert opts.strtypes == [0]
    assert opts.display_only_existing_strings is True

    by_addr = {r.address.value: r for r in rows}
    assert by_addr[0x1000].kind == "C"
    assert by_addr[0x1000].value == "hello"
    # A UTF-16 (width-2) item is classified unicode and decoded correctly (the
    # contents come back already UTF-8 encoded from get_strlit_contents).
    assert by_addr[0x2000].kind == "unicode"
    assert by_addr[0x2000].value == "World"


def test_build_is_resilient_to_missing_sdk(monkeypatch):
    # If the string-list SDK is unavailable, _ensure degrades quietly and _build
    # still runs against whatever get_strlist_qty reports (here, nothing).
    ida_strlist = types.SimpleNamespace(
        get_strlist_options=lambda: (_ for _ in ()).throw(RuntimeError("no opts")),
        get_strlist_qty=lambda: 0,
        get_strlist_item=lambda info, i: False,
        string_info_t=lambda: types.SimpleNamespace(ea=0, length=0, type=0),
        build_strlist=lambda: None,
    )
    monkeypatch.setitem(sys.modules, "ida_strlist", ida_strlist)
    monkeypatch.setitem(sys.modules, "ida_nalt", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "ida_bytes", types.SimpleNamespace(
        get_strlit_contents=lambda *a: None))
    assert StringsCache()._build() == ()
