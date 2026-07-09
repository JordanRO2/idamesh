"""Unit tests for ``int_convert`` — the pure integer reinterpreter (no IDA).

Three layers are exercised without any database present: the pure
:class:`~idamesh.domain.services.number.NumberService` (base detection across
hex/binary/octal/decimal/char, two's-complement signing, width masking, and the
printability rule), the :class:`~idamesh.application.contexts.int_convert`
use-case that wraps it, the ``int_convert_view`` wire projection, and the catalog
registration end-to-end — where a bad token or an out-of-range bit width must
surface as a :class:`ToolError` (rendered as an ``isError`` result) rather than a
protocol fault. A minimal inline executor stands in for the kernel-thread
marshaller, mirroring how the fakes replace the IDA adapters elsewhere.
"""

from __future__ import annotations

from typing import Callable, Optional, TypeVar

import pytest

from idamesh.application.contexts.int_convert import IntConvertUseCase
from idamesh.application.dto.int_convert import (
    DEFAULT_BITS,
    IntConvertCommand,
    IntConvertResult,
)
from idamesh.domain.entities.number_conversion import NumberConversion
from idamesh.domain.services.number import (
    MAX_BITS,
    MIN_BITS,
    NumberService,
)
from idamesh.interface.catalog.int_convert import (
    int_convert_view,
    register_int_convert,
)
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


class _InlineExecutor:
    """A no-marshal ``MainThreadExecutor``: runs the job on the calling thread."""

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# -- NumberService: base detection -----------------------------------------


@pytest.mark.parametrize(
    "value,expected_decimal",
    [
        ("0xff", 255),
        ("0xFF", 255),  # case-insensitive hex digits and prefix
        ("0XfF", 255),
        ("255", 255),  # plain decimal
        ("0b1010", 10),  # binary
        ("0B1010", 10),
        ("0o17", 15),  # octal
        ("0O17", 15),
        ("'A'", 65),  # single-quoted char literal
        ('"A"', 65),  # double-quoted char literal
        ("' '", 0x20),  # space is a valid char literal
        ("0", 0),
    ],
)
def test_parse_detects_base_from_prefix(value: str, expected_decimal: int) -> None:
    conversion = NumberService().convert(value, bits=64)
    assert conversion.decimal == expected_decimal
    assert conversion.input == value  # the original token is preserved verbatim


def test_convert_renders_every_representation() -> None:
    conversion = NumberService().convert("0x41", bits=64)

    assert conversion == NumberConversion(
        input="0x41",
        bits=64,
        decimal=65,
        unsigned=65,
        signed=65,
        hex="0x41",
        binary="0b1000001",
        octal="0o101",
        char="A",
    )


def test_hex_binary_octal_reflect_the_unsigned_view() -> None:
    # 0x1FF at 8 bits masks to 0xFF; the renderings track the masked value while
    # ``decimal`` keeps the full parsed magnitude.
    conversion = NumberService().convert("0x1FF", bits=8)

    assert conversion.decimal == 0x1FF
    assert conversion.unsigned == 0xFF
    assert conversion.hex == "0xff"
    assert conversion.binary == "0b11111111"
    assert conversion.octal == "0o377"


def test_leading_sign_is_accepted() -> None:
    assert NumberService().convert("+42", bits=64).decimal == 42
    assert NumberService().convert("-42", bits=64).decimal == -42
    assert NumberService().convert("-0x10", bits=64).decimal == -16


# -- NumberService: signed vs unsigned at width -----------------------------


@pytest.mark.parametrize(
    "value,bits,unsigned,signed",
    [
        # All-ones at each width reads as unsigned max and signed -1.
        ("0xFF", 8, 0xFF, -1),
        ("0xFFFF", 16, 0xFFFF, -1),
        ("0xFFFFFFFF", 32, 0xFFFFFFFF, -1),
        ("0xFFFFFFFFFFFFFFFF", 64, 0xFFFFFFFFFFFFFFFF, -1),
        # The sign bit alone is the most-negative value at each width.
        ("0x80", 8, 0x80, -128),
        ("0x8000", 16, 0x8000, -32768),
        ("0x80000000", 32, 0x80000000, -(2**31)),
        # One below the sign bit is the largest positive at that width.
        ("0x7F", 8, 0x7F, 127),
        ("0x7FFF", 16, 0x7FFF, 32767),
        # A small positive value is identical signed and unsigned.
        ("5", 8, 5, 5),
    ],
)
def test_two_complement_signing_at_width(
    value: str, bits: int, unsigned: int, signed: int
) -> None:
    conversion = NumberService().convert(value, bits=bits)
    assert conversion.bits == bits
    assert conversion.unsigned == unsigned
    assert conversion.signed == signed


@pytest.mark.parametrize(
    "bits,unsigned,hex_str",
    [
        (8, 0xFF, "0xff"),
        (16, 0xFFFF, "0xffff"),
        (32, 0xFFFFFFFF, "0xffffffff"),
        (64, 0xFFFFFFFFFFFFFFFF, "0xffffffffffffffff"),
    ],
)
def test_negative_one_is_all_ones_at_width(
    bits: int, unsigned: int, hex_str: str
) -> None:
    # -1 is the canonical two's-complement wrap: it masks to all-ones.
    conversion = NumberService().convert("-1", bits=bits)
    assert conversion.decimal == -1
    assert conversion.unsigned == unsigned
    assert conversion.signed == -1
    assert conversion.hex == hex_str


def test_negative_input_wraps_to_two_complement() -> None:
    conversion = NumberService().convert("-128", bits=8)
    assert conversion.unsigned == 0x80
    assert conversion.signed == -128
    assert conversion.hex == "0x80"


# -- NumberService: width masking / overflow --------------------------------


def test_value_exactly_at_modulus_masks_to_zero() -> None:
    conversion = NumberService().convert("256", bits=8)
    assert conversion.decimal == 256
    assert conversion.unsigned == 0
    assert conversion.signed == 0
    assert conversion.hex == "0x0"


def test_large_value_masks_into_width() -> None:
    conversion = NumberService().convert("0x123456789", bits=32)
    assert conversion.unsigned == 0x23456789
    assert conversion.signed == 0x23456789  # top nibble 2 -> sign bit clear


def test_wide_bit_width_is_supported() -> None:
    conversion = NumberService().convert("-1", bits=128)
    assert conversion.unsigned == (1 << 128) - 1
    assert conversion.signed == -1


# -- NumberService: char rendering / printability ---------------------------


@pytest.mark.parametrize(
    "value,expected_char",
    [
        ("0x20", " "),  # low printable boundary (space)
        ("0x41", "A"),
        ("0x7e", "~"),  # high printable boundary (tilde)
        ("0x1f", None),  # below printable range
        ("0x7f", None),  # DEL — not printable
        ("0x00", None),
        ("0x100", None),  # masked-in value out of ASCII high boundary at 64 bits
    ],
)
def test_char_is_only_the_printable_ascii(
    value: str, expected_char: Optional[str]
) -> None:
    assert NumberService().convert(value, bits=64).char == expected_char


def test_char_reflects_the_masked_unsigned_value() -> None:
    # 0x141 masked at 8 bits is 0x41 = 'A'.
    conversion = NumberService().convert("0x141", bits=8)
    assert conversion.unsigned == 0x41
    assert conversion.char == "A"


# -- NumberService: bad input ------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "",  # empty
        "   ",  # whitespace only
        "0xZZ",  # bad hex digits
        "0b12",  # non-binary digit
        "0o89",  # non-octal digit
        "abc",  # not a number in any base
        "12.5",  # not an integer
        "+",  # sign with no body
        "-",  # sign with no body
        "0x",  # prefix with no digits
        "'AB'",  # multi-character literal
        "''",  # empty char literal
    ],
)
def test_unparseable_token_raises_value_error(value: str) -> None:
    with pytest.raises(ValueError):
        NumberService().convert(value, bits=64)


def test_non_string_value_raises_value_error() -> None:
    with pytest.raises(ValueError):
        NumberService().convert(123, bits=64)  # type: ignore[arg-type]


# -- NumberService: bit-width validation ------------------------------------


@pytest.mark.parametrize("bits", [MIN_BITS, 8, 16, 32, 64, MAX_BITS])
def test_bit_width_within_bounds_is_accepted(bits: int) -> None:
    assert NumberService().convert("1", bits=bits).bits == bits


@pytest.mark.parametrize("bits", [0, -1, MIN_BITS - 1, MAX_BITS + 1, 10_000])
def test_out_of_range_bit_width_raises(bits: int) -> None:
    with pytest.raises(ValueError):
        NumberService().convert("1", bits=bits)


def test_bool_is_rejected_as_bit_width() -> None:
    # ``bool`` is an ``int`` subtype; the service refuses it explicitly.
    with pytest.raises(ValueError):
        NumberService().convert("1", bits=True)  # type: ignore[arg-type]


# -- use-case ---------------------------------------------------------------


def test_use_case_wraps_conversion() -> None:
    use_case = IntConvertUseCase(NumberService())

    result = use_case.execute(IntConvertCommand(value="0xFF", bits=8))

    assert isinstance(result, IntConvertResult)
    assert result.conversion.unsigned == 0xFF
    assert result.conversion.signed == -1
    assert result.conversion.bits == 8


def test_use_case_defaults_to_64_bits() -> None:
    use_case = IntConvertUseCase(NumberService())

    result = use_case.execute(IntConvertCommand(value="-1"))

    assert DEFAULT_BITS == 64
    assert result.conversion.bits == 64
    assert result.conversion.unsigned == (1 << 64) - 1
    assert result.conversion.signed == -1


def test_use_case_propagates_bad_input() -> None:
    use_case = IntConvertUseCase(NumberService())

    with pytest.raises(ValueError):
        use_case.execute(IntConvertCommand(value="nope"))


def test_use_case_propagates_out_of_range_bits() -> None:
    use_case = IntConvertUseCase(NumberService())

    with pytest.raises(ValueError):
        use_case.execute(IntConvertCommand(value="1", bits=0))


# -- view -------------------------------------------------------------------


def test_view_projects_every_field() -> None:
    conversion = NumberConversion(
        input="0xFF",
        bits=8,
        decimal=255,
        unsigned=255,
        signed=-1,
        hex="0xff",
        binary="0b11111111",
        octal="0o377",
        char=None,
    )

    view = int_convert_view(conversion)

    # decimal/unsigned/signed are decimal *strings* (big-int-safe wire shape);
    # hex/binary/octal stay their prefixed string renderings.
    assert view == {
        "input": "0xFF",
        "bits": 8,
        "hex": "0xff",
        "decimal": "255",
        "unsigned": "255",
        "signed": "-1",
        "binary": "0b11111111",
        "octal": "0o377",
        "char": None,
    }


def test_view_renders_wide_magnitude_without_precision_loss() -> None:
    # A value above 2**53 would corrupt in a JSON double; as a string it is exact.
    conversion = NumberService().convert("0xFFFFFFFFFFFFFFFF", bits=64)

    view = int_convert_view(conversion)

    assert view["unsigned"] == "18446744073709551615"
    assert view["decimal"] == "18446744073709551615"
    assert view["signed"] == "-1"


def test_view_preserves_printable_char() -> None:
    conversion = NumberService().convert("0x41", bits=64)

    view = int_convert_view(conversion)

    assert view["char"] == "A"
    assert view["signed"] == "65"


# -- catalog: end-to-end + isError -------------------------------------------


def _registered_tool():
    """Register ``int_convert`` on a fresh registry and return its spec."""
    registry = Registry()
    register_int_convert(
        registry,
        int_convert_use_case=IntConvertUseCase(NumberService()),
        executor=_InlineExecutor(),
    )
    spec = registry.get_tool("int_convert")
    assert spec is not None
    return spec


def test_catalog_invocation_returns_wire_view() -> None:
    spec = _registered_tool()

    view = spec.invoke(value="0xFF", bits=8)

    assert view == {
        "input": "0xFF",
        "bits": 8,
        "hex": "0xff",
        "decimal": "255",
        "unsigned": "255",
        "signed": "-1",
        "binary": "0b11111111",
        "octal": "0o377",
        "char": None,
    }


def test_catalog_uses_default_bits() -> None:
    spec = _registered_tool()

    view = spec.invoke(value="0x41")

    assert view["bits"] == 64
    assert view["char"] == "A"
    assert view["decimal"] == "65"


def test_catalog_bad_token_surfaces_as_tool_error() -> None:
    spec = _registered_tool()

    with pytest.raises(ToolError):
        spec.invoke(value="not-a-number")


def test_catalog_out_of_range_bits_surfaces_as_tool_error() -> None:
    spec = _registered_tool()

    with pytest.raises(ToolError):
        spec.invoke(value="1", bits=0)
