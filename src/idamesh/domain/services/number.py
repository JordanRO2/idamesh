"""The number-conversion service — a pure, IDA-free integer reinterpreter.

:class:`NumberService` parses one integer token — written in hexadecimal
(``0x``), binary (``0b``), octal (``0o``), plain decimal, or as a quoted
character literal (``'A'``) — and renders it across every representation a
:class:`~idamesh.domain.entities.number_conversion.NumberConversion` carries: the
signed decimal value, the unsigned and two's-complement signed interpretations at
a caller-chosen bit width, and the hexadecimal/binary/octal renderings, plus the
ASCII character when printable. Keeping this here as a stateless domain service
makes it fully unit-testable without any IDA present; the whole parse-and-render
policy (base detection, width masking, printability rule) is ours.
"""

from __future__ import annotations

from idamesh.domain.entities.number_conversion import NumberConversion

#: Default bit width used when a caller does not specify one.
DEFAULT_BITS: int = 64
#: Inclusive bounds on an accepted bit width.
MIN_BITS: int = 1
MAX_BITS: int = 512
#: Printable ASCII range whose code points render as a ``char``.
_PRINTABLE_LO: int = 0x20
_PRINTABLE_HI: int = 0x7E


class NumberService:
    """Parse an integer token and render it across representations."""

    def convert(self, value: str, bits: int = DEFAULT_BITS) -> NumberConversion:
        """Parse ``value`` and render it at a ``bits``-wide two's-complement view.

        ``value`` is classified by prefix — ``0x`` hexadecimal, ``0b`` binary,
        ``0o`` octal, a quoted single-character literal, or otherwise plain
        decimal — with an optional leading sign. The parsed integer is reduced
        modulo ``2**bits`` to obtain its unsigned view, and reinterpreted as a
        two's-complement signed value at the same width; the hexadecimal, binary,
        and octal renderings are taken from that unsigned view. The ``char`` field
        is the ASCII character for the unsigned value when it lands in the
        printable range, otherwise ``None``. Raises ``ValueError`` on an
        unparseable token or an out-of-range bit width.
        """
        width = self._validate_bits(bits)
        parsed = self._parse(value)

        modulus = 1 << width
        unsigned = parsed % modulus
        sign_bit = 1 << (width - 1)
        signed = unsigned - modulus if unsigned & sign_bit else unsigned

        char = chr(unsigned) if _PRINTABLE_LO <= unsigned <= _PRINTABLE_HI else None

        return NumberConversion(
            input=value,
            bits=width,
            decimal=parsed,
            unsigned=unsigned,
            signed=signed,
            hex=f"0x{unsigned:x}",
            binary=f"0b{unsigned:b}",
            octal=f"0o{unsigned:o}",
            char=char,
        )

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _validate_bits(bits: int) -> int:
        """Coerce and bounds-check the requested bit width."""
        if isinstance(bits, bool) or not isinstance(bits, int):
            raise ValueError(f"bits must be an int, got {type(bits).__name__}")
        if bits < MIN_BITS or bits > MAX_BITS:
            raise ValueError(f"bits out of range [{MIN_BITS}, {MAX_BITS}]: {bits}")
        return bits

    @staticmethod
    def _parse(value: str) -> int:
        """Parse a signed integer from a hex/bin/oct/decimal/char token."""
        if not isinstance(value, str):
            raise ValueError(f"cannot parse a number from {type(value).__name__}")
        text = value.strip()
        if not text:
            raise ValueError("empty number token")

        sign = 1
        body = text
        if body[0] in "+-":
            sign = -1 if body[0] == "-" else 1
            body = body[1:].strip()
        if not body:
            raise ValueError(f"unparseable number: {value!r}")

        # A quoted single-character literal denotes its code point.
        if len(body) >= 2 and body[0] == body[-1] and body[0] in ("'", '"'):
            inner = body[1:-1]
            if len(inner) != 1:
                raise ValueError(f"not a single-character literal: {value!r}")
            return sign * ord(inner)

        prefix = body[:2].lower()
        try:
            if prefix == "0x":
                magnitude = int(body, 16)
            elif prefix == "0b":
                magnitude = int(body, 2)
            elif prefix == "0o":
                magnitude = int(body, 8)
            else:
                magnitude = int(body, 10)
        except ValueError as exc:
            raise ValueError(f"unparseable number: {value!r}") from exc
        return sign * magnitude
