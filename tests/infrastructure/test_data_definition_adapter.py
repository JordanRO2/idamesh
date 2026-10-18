"""Unit tests for :class:`IdaDataDefinitionGateway` (no IDA; fake ida_* modules).

``make_data`` deletes the existing items before defining, so anything checkable
must be refused *before* ``del_items`` runs.
"""

from __future__ import annotations

import sys
import types

import pytest

from idamesh.domain.values.address import Address
from idamesh.infrastructure.ida.data_definition_adapter import IdaDataDefinitionGateway


class _Tif:
    def get_size(self):
        return 16

    def dstr(self):
        return "char[16]"


def _install(monkeypatch, *, mapped):
    deleted = []
    monkeypatch.setitem(
        sys.modules,
        "ida_bytes",
        types.SimpleNamespace(
            DELIT_SIMPLE=0,
            is_mapped=lambda ea: ea in mapped,
            del_items=lambda *args: deleted.append(args),
            create_dword=lambda ea, size: True,
            get_item_size=lambda ea: 16,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_typeinf",
        types.SimpleNamespace(
            get_idati=lambda: object(),
            tinfo_t=_Tif,
            parse_decl=lambda tif, til, text, flags: "ok",
            PT_SIL=0,
            BADSIZE=-1,
            TINFO_DEFINITE=1,
            apply_tinfo=lambda ea, tif, flags: True,
        ),
    )
    return deleted


def test_typed_define_refused_before_deleting_when_span_unmapped(monkeypatch):
    deleted = _install(monkeypatch, mapped={0x1000})  # last byte 0x100f unmapped
    with pytest.raises(ValueError, match="not mapped"):
        IdaDataDefinitionGateway().make_data(Address(0x1000), "char[16]", 0)
    assert deleted == []


def test_sized_define_refused_before_deleting_when_span_unmapped(monkeypatch):
    deleted = _install(monkeypatch, mapped={0x1000})  # last byte 0x1003 unmapped
    with pytest.raises(ValueError, match="not mapped"):
        IdaDataDefinitionGateway().make_data(Address(0x1000), "", 4)
    assert deleted == []


def test_typed_define_proceeds_when_span_mapped(monkeypatch):
    deleted = _install(monkeypatch, mapped=set(range(0x1000, 0x1010)))
    result = IdaDataDefinitionGateway().make_data(Address(0x1000), "char[16]", 0)
    assert result == ("char[16]", 16)
    assert len(deleted) == 1
