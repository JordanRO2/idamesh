"""Unit tests for :class:`IdaGlobalRepository` (no IDA; fake ida_* modules).

Locks in the idalib fix: ``idautils.Names()`` walks the name-list index, which
idalib leaves unbuilt (``get_nlist_size() == 0``) even after auto-analysis, so a
bare enumeration returns zero named globals on a database that actually has them.
The adapter must rebuild the nlist on demand before enumerating, and skip the
rebuild once it is populated.
"""

from __future__ import annotations

import sys
import types

import pytest

from idamesh.infrastructure.ida.globals_adapter import IdaGlobalRepository


def _install(monkeypatch, *, nlist_size, names):
    state = {"rebuilt": False, "size": nlist_size}

    def rebuild_nlist():
        state["rebuilt"] = True
        state["size"] = len(names)

    monkeypatch.setitem(
        sys.modules,
        "ida_name",
        types.SimpleNamespace(
            get_nlist_size=lambda: state["size"],
            rebuild_nlist=rebuild_nlist,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "idautils",
        types.SimpleNamespace(Names=lambda: iter(list(names))),
    )
    # get_full_flags returns the ea itself; is_data treats 0x1000 as data.
    monkeypatch.setitem(
        sys.modules,
        "ida_bytes",
        types.SimpleNamespace(
            get_full_flags=lambda ea: ea,
            is_data=lambda fl: fl == 0x1000,
            get_item_size=lambda ea: 4,
        ),
    )
    monkeypatch.setitem(sys.modules, "idc", types.SimpleNamespace(get_type=lambda ea: None))
    return state


def test_collect_rebuilds_nlist_when_empty(monkeypatch):
    state = _install(
        monkeypatch,
        nlist_size=0,
        names=[(0x1000, "g_config"), (0x2000, "some_func")],
    )

    rows = IdaGlobalRepository._collect()

    assert state["rebuilt"] is True  # empty nlist -> rebuilt
    assert [g.name for g in rows] == ["g_config"]  # only the is_data item
    assert rows[0].size == 4


def test_collect_skips_rebuild_when_nlist_populated(monkeypatch):
    state = _install(monkeypatch, nlist_size=5, names=[(0x1000, "g_x")])

    rows = IdaGlobalRepository._collect()

    assert state["rebuilt"] is False  # already populated -> no rebuild
    assert [g.name for g in rows] == ["g_x"]
