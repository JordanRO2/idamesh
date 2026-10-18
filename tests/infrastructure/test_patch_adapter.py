"""Unit tests for :meth:`IdaPatchGateway.assemble` (no IDA; fake ida_* modules)."""

from __future__ import annotations

import sys
import types

import pytest

from idamesh.domain.values.address import Address
from idamesh.infrastructure.ida.patch_adapter import IdaPatchGateway


def _install(monkeypatch, *, encoding, is_code, item_size):
    monkeypatch.setitem(
        sys.modules,
        "idautils",
        types.SimpleNamespace(Assemble=lambda ea, text: (True, encoding)),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_bytes",
        types.SimpleNamespace(
            get_full_flags=lambda ea: ea,
            is_code=lambda fl: is_code,
            get_item_size=lambda ea: item_size,
        ),
    )


def test_assemble_refuses_encoding_longer_than_existing_instruction(monkeypatch):
    _install(monkeypatch, encoding=b"\xe9\x00\x00\x00\x00", is_code=True, item_size=2)
    with pytest.raises(ValueError, match="5 bytes"):
        IdaPatchGateway().assemble(Address(0x401000), "jmp 0x401005")


def test_assemble_allows_equal_or_shorter_encoding(monkeypatch):
    _install(monkeypatch, encoding=b"\x90", is_code=True, item_size=2)
    assert IdaPatchGateway().assemble(Address(0x401000), "nop") == b"\x90"


def test_assemble_skips_size_check_on_undefined_bytes(monkeypatch):
    _install(monkeypatch, encoding=b"\xe9\x00\x00\x00\x00", is_code=False, item_size=1)
    assert len(IdaPatchGateway().assemble(Address(0x401000), "jmp 0x401005")) == 5
