"""Address value objects and the polymorphic ``Selector``.

An :class:`Address` is a validated effective-address (EA): a non-negative
integer that is not the invalid sentinel. ``Ea`` is a spelling alias so call
sites can use whichever reads best. :class:`Selector` captures the pervasive
"an address *or* a symbol name" input: it classifies a raw client value as a
hexadecimal literal, a decimal literal, or a symbol name, and (given a resolver)
turns it into a concrete :class:`Address`. Only the *classification* and the
*resolution interface* live here; the actual name lookup is provided by an
adapter through :class:`SymbolResolver`, keeping this module free of I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

#: The SDK's "no address" sentinel (``BADADDR``) on a 64-bit database. Reproduced
#: as an interoperability fact; a resolved :class:`Address` never equals it.
INVALID_EA: int = 0xFFFFFFFFFFFFFFFF


class SelectorKind(Enum):
    """How a raw :class:`Selector` value was classified."""

    HEX = "hex"
    DEC = "dec"
    SYMBOL = "symbol"


@runtime_checkable
class SymbolResolver(Protocol):
    """Anything that can turn a symbol name into an EA integer (or ``None``)."""

    def resolve_symbol(self, name: str) -> int | None:
        """Return the EA a symbol name binds to, or ``None`` if unknown."""
        ...


@dataclass(frozen=True, order=True)
class Address:
    """A validated effective address."""

    value: int

    def __post_init__(self) -> None:
        """Reject negative values and the invalid sentinel."""
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise ValueError(f"address must be an int, got {type(self.value).__name__}")
        if self.value < 0 or self.value >= INVALID_EA:
            raise ValueError(f"address out of range: {self.value!r}")

    @classmethod
    def parse(cls, raw: str | int) -> "Address":
        """Build an address from a hex string (``0x…``/bare hex), a decimal
        string, or an ``int``. Raises ``ValueError`` on an unparseable value."""
        if isinstance(raw, bool):
            raise ValueError("boolean is not a valid address")
        if isinstance(raw, int):
            return cls(raw)
        if not isinstance(raw, str):
            raise ValueError(f"cannot parse address from {type(raw).__name__}")
        text = raw.strip()
        if not text:
            raise ValueError("empty address string")
        try:
            if text[:2].lower() == "0x":
                return cls(int(text, 16))
            return cls(int(text, 10))
        except ValueError:
            pass
        try:
            return cls(int(text, 16))
        except ValueError as exc:
            raise ValueError(f"unparseable address: {raw!r}") from exc

    @property
    def is_valid(self) -> bool:
        """``True`` when the address is within the representable, non-sentinel range."""
        return 0 <= self.value < INVALID_EA

    def hex(self) -> str:
        """Canonical ``0x``-prefixed lowercase hexadecimal rendering."""
        return f"0x{self.value:x}"

    def __int__(self) -> int:
        return self.value


#: Spelling alias — the polymorphic address VO is referred to as either name.
Ea = Address


@dataclass(frozen=True)
class AddressRange:
    """A half-open ``[start, end)`` span of addresses."""

    start: Address
    end: Address

    def __post_init__(self) -> None:
        """Reject an inverted or empty-with-start>end range."""
        if self.end.value < self.start.value:
            raise ValueError(
                f"inverted address range: {self.start.hex()} > {self.end.hex()}"
            )

    @property
    def size(self) -> int:
        """Number of addressable units the range covers."""
        return self.end.value - self.start.value

    def contains(self, ea: Address) -> bool:
        """``True`` when ``ea`` falls inside the half-open span."""
        return self.start.value <= int(ea) < self.end.value


@dataclass(frozen=True)
class Selector:
    """A classified address-or-symbol input, resolvable to an :class:`Address`."""

    raw: str
    kind: SelectorKind

    @classmethod
    def parse(cls, raw: str | int) -> "Selector":
        """Classify a raw client value as hex, decimal, or a symbol name."""
        if isinstance(raw, bool):
            raise ValueError("boolean is not a valid selector")
        if isinstance(raw, int):
            return cls(str(raw), SelectorKind.DEC)
        if not isinstance(raw, str):
            raise ValueError(f"cannot parse selector from {type(raw).__name__}")
        text = raw.strip()
        if not text:
            raise ValueError("empty selector")
        if text[:2].lower() == "0x":
            return cls(text, SelectorKind.HEX)
        if text.isdigit():
            return cls(text, SelectorKind.DEC)
        return cls(text, SelectorKind.SYMBOL)

    def resolve(self, resolver: SymbolResolver) -> Address:
        """Resolve to a concrete address. Numeric kinds parse directly; the
        ``SYMBOL`` kind delegates to ``resolver``. Raises ``ValueError`` when a
        symbol cannot be resolved."""
        if self.kind is SelectorKind.HEX:
            return Address(int(self.raw, 16))
        if self.kind is SelectorKind.DEC:
            return Address(int(self.raw, 10))
        ea = resolver.resolve_symbol(self.raw)
        if ea is None:
            raise ValueError(f"cannot resolve symbol: {self.raw!r}")
        return Address(ea)
