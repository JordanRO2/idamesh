"""Unit tests for the address value objects and the ``Selector`` classifier.

These exercise the *actual* behavior of ``domain/values/address.py`` directly,
without IDA — the value objects are pure. They pin the parse/classification rules
(hex vs decimal vs symbol), range validation against ``INVALID_EA``, ordering,
and symbol resolution through a fake resolver.
"""

from __future__ import annotations

import dataclasses

import pytest

from idamesh.domain.values.address import (
    INVALID_EA,
    Address,
    AddressRange,
    Ea,
    Selector,
    SelectorKind,
    SymbolResolver,
)


# -- Address construction / validation --------------------------------------- #


def test_address_accepts_zero_and_high_valid_value():
    assert Address(0).value == 0
    assert Address(INVALID_EA - 1).value == INVALID_EA - 1


def test_address_rejects_negative_value():
    with pytest.raises(ValueError):
        Address(-1)


def test_address_rejects_the_invalid_sentinel():
    with pytest.raises(ValueError):
        Address(INVALID_EA)


def test_address_rejects_bool_and_non_int():
    with pytest.raises(ValueError):
        Address(True)  # bool is an int subclass but not a valid address
    with pytest.raises(ValueError):
        Address("0x1000")  # type: ignore[arg-type]


def test_address_is_frozen():
    addr = Address(0x401000)
    with pytest.raises(dataclasses.FrozenInstanceError):
        addr.value = 1  # type: ignore[misc]


def test_ea_is_a_spelling_alias_for_address():
    assert Ea is Address


# -- Address.parse ----------------------------------------------------------- #


def test_parse_hex_prefixed_string():
    assert Address.parse("0x401000") == Address(0x401000)
    assert Address.parse("0X401000") == Address(0x401000)


def test_parse_pure_digits_are_decimal_not_hex():
    # "401000" is all decimal digits, so base-10 wins over the hex fallback.
    assert Address.parse("401000") == Address(401000)
    assert Address.parse("123") == Address(123)


def test_parse_bare_hex_falls_back_to_base_16():
    # No 0x prefix and non-decimal digits -> decimal parse fails, hex rescue wins.
    assert Address.parse("deadbeef") == Address(0xDEADBEEF)
    assert Address.parse("ff") == Address(0xFF)


def test_parse_int_passthrough():
    assert Address.parse(0x1000) == Address(0x1000)
    assert Address.parse(0) == Address(0)


def test_parse_strips_surrounding_whitespace():
    assert Address.parse("  0x1000  ") == Address(0x1000)


def test_parse_rejects_empty_and_blank():
    with pytest.raises(ValueError):
        Address.parse("")
    with pytest.raises(ValueError):
        Address.parse("   ")


def test_parse_rejects_bool():
    with pytest.raises(ValueError):
        Address.parse(True)


def test_parse_rejects_unparseable_string():
    with pytest.raises(ValueError):
        Address.parse("not-an-address")


def test_parse_rejects_non_str_non_int():
    with pytest.raises(ValueError):
        Address.parse(1.5)  # type: ignore[arg-type]


# -- Address behavior -------------------------------------------------------- #


def test_is_valid_true_for_constructed_address():
    assert Address(0).is_valid is True
    assert Address(0x401000).is_valid is True


def test_hex_is_lowercase_0x_prefixed():
    assert Address(0x401000).hex() == "0x401000"
    assert Address(0).hex() == "0x0"
    assert Address(0xDEADBEEF).hex() == "0xdeadbeef"


def test_int_dunder_returns_raw_value():
    assert int(Address(0x1234)) == 0x1234


def test_ordering_and_sorting():
    assert Address(1) < Address(2)
    assert Address(2) > Address(1)
    unordered = [Address(3), Address(1), Address(2)]
    assert sorted(unordered) == [Address(1), Address(2), Address(3)]


def test_equality_and_hashing():
    assert Address(0x1000) == Address(0x1000)
    assert Address(0x1000) != Address(0x1001)
    assert len({Address(0x1000), Address(0x1000), Address(0x2000)}) == 2


# -- AddressRange ------------------------------------------------------------ #


def test_address_range_size_and_contains():
    rng = AddressRange(Address(0x1000), Address(0x1010))
    assert rng.size == 0x10
    assert rng.contains(Address(0x1000)) is True
    assert rng.contains(Address(0x100F)) is True
    assert rng.contains(Address(0x1010)) is False  # half-open [start, end)
    assert rng.contains(Address(0xFFF)) is False


def test_address_range_allows_empty_span():
    rng = AddressRange(Address(0x1000), Address(0x1000))
    assert rng.size == 0
    assert rng.contains(Address(0x1000)) is False


def test_address_range_rejects_inverted_span():
    with pytest.raises(ValueError):
        AddressRange(Address(0x2000), Address(0x1000))


# -- Selector classification ------------------------------------------------- #


def test_selector_parse_classifies_hex():
    sel = Selector.parse("0x401000")
    assert sel.kind is SelectorKind.HEX
    assert sel.raw == "0x401000"

    upper = Selector.parse("0XABC")
    assert upper.kind is SelectorKind.HEX


def test_selector_parse_classifies_decimal():
    sel = Selector.parse("4198400")
    assert sel.kind is SelectorKind.DEC
    assert sel.raw == "4198400"


def test_selector_parse_classifies_symbol():
    sel = Selector.parse("main")
    assert sel.kind is SelectorKind.SYMBOL
    assert sel.raw == "main"


def test_selector_bare_hex_is_a_symbol_not_hex():
    # Unlike Address.parse, a bare hex word with no 0x prefix is classified as a
    # symbol name (it could equally be an identifier).
    sel = Selector.parse("deadbeef")
    assert sel.kind is SelectorKind.SYMBOL


def test_selector_parse_int_is_decimal():
    sel = Selector.parse(255)
    assert sel.kind is SelectorKind.DEC
    assert sel.raw == "255"


def test_selector_parse_rejects_bool_empty_and_non_str():
    with pytest.raises(ValueError):
        Selector.parse(True)
    with pytest.raises(ValueError):
        Selector.parse("")
    with pytest.raises(ValueError):
        Selector.parse("   ")
    with pytest.raises(ValueError):
        Selector.parse(1.5)  # type: ignore[arg-type]


# -- Selector.resolve -------------------------------------------------------- #


class _FakeResolver:
    """A ``SymbolResolver`` backed by an in-memory name->EA table."""

    def __init__(self, table: dict[str, int]) -> None:
        self._table = table

    def resolve_symbol(self, name: str) -> int | None:
        return self._table.get(name)


def test_fake_resolver_satisfies_the_protocol_structurally():
    assert isinstance(_FakeResolver({}), SymbolResolver)


def test_selector_resolve_hex_parses_without_resolver():
    resolved = Selector.parse("0x401000").resolve(_FakeResolver({}))
    assert resolved == Address(0x401000)


def test_selector_resolve_decimal_parses_without_resolver():
    resolved = Selector.parse("4198400").resolve(_FakeResolver({}))
    assert resolved == Address(4198400)


def test_selector_resolve_symbol_uses_resolver():
    resolver = _FakeResolver({"main": 0x401500})
    resolved = Selector.parse("main").resolve(resolver)
    assert resolved == Address(0x401500)


def test_selector_resolve_unknown_symbol_raises():
    resolver = _FakeResolver({"main": 0x401500})
    with pytest.raises(ValueError):
        Selector.parse("nope").resolve(resolver)
