"""Unit tests for the domain entities (immutable records + one alias property).

These are pure value/entity objects — no IDA — so they run under plain pytest.
The tests pin field defaults, the ``Function.start_ea`` alias, enum values, and
immutability.
"""

from __future__ import annotations

import dataclasses

import pytest

from idamesh.domain.entities.decompilation import Pseudocode
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.metadata import (
    DatabaseMetadata,
    Endianness,
    HealthStatus,
)
from idamesh.domain.values.address import Address


# -- Function ---------------------------------------------------------------- #


def test_function_defaults_and_required_fields():
    fn = Function(ea=Address(0x401000), name="main", size=64)
    assert fn.ea == Address(0x401000)
    assert fn.name == "main"
    assert fn.size == 64
    assert fn.end_ea is None
    assert fn.flags == 0
    assert fn.is_library is False
    assert fn.is_thunk is False


def test_function_start_ea_aliases_ea():
    fn = Function(ea=Address(0x401000), name="main", size=64)
    assert fn.start_ea is fn.ea
    assert fn.start_ea == Address(0x401000)


def test_function_full_construction():
    fn = Function(
        ea=Address(0x401000),
        name="lib_fn",
        size=32,
        end_ea=Address(0x401020),
        flags=0x4,
        is_library=True,
        is_thunk=True,
    )
    assert fn.end_ea == Address(0x401020)
    assert fn.flags == 0x4
    assert fn.is_library is True
    assert fn.is_thunk is True


def test_function_is_frozen():
    fn = Function(ea=Address(0x401000), name="main", size=64)
    with pytest.raises(dataclasses.FrozenInstanceError):
        fn.name = "renamed"  # type: ignore[misc]


# -- DatabaseMetadata -------------------------------------------------------- #


def test_database_metadata_defaults():
    md = DatabaseMetadata(
        path="/tmp/target.exe",
        module="target.exe",
        architecture="metapc",
        bits=64,
        endianness=Endianness.LITTLE,
    )
    assert md.entrypoint is None
    assert md.image_base is None
    assert md.function_count == 0
    assert md.segment_count == 0
    assert md.string_count is None
    assert md.compiler is None
    assert md.filetype is None
    assert md.sha256 is None


def test_database_metadata_full_construction():
    md = DatabaseMetadata(
        path="/tmp/target.exe",
        module="target.exe",
        architecture="metapc",
        bits=64,
        endianness=Endianness.LITTLE,
        entrypoint=Address(0x401000),
        image_base=Address(0x400000),
        function_count=12,
        segment_count=5,
        string_count=88,
        compiler="MSVC",
        filetype="PE",
        sha256="0" * 64,
    )
    assert md.entrypoint == Address(0x401000)
    assert md.image_base == Address(0x400000)
    assert md.function_count == 12
    assert md.endianness.value == "little"


def test_database_metadata_is_frozen():
    md = DatabaseMetadata(
        path="p", module="m", architecture="a", bits=32, endianness=Endianness.BIG
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        md.bits = 64  # type: ignore[misc]


# -- Endianness -------------------------------------------------------------- #


def test_endianness_values():
    assert Endianness.LITTLE.value == "little"
    assert Endianness.BIG.value == "big"
    assert Endianness("little") is Endianness.LITTLE
    assert Endianness("big") is Endianness.BIG


# -- HealthStatus ------------------------------------------------------------ #


def test_health_status_defaults():
    health = HealthStatus(
        ok=True,
        database_open=False,
        server_version="0.0.1",
        protocol_versions=("2025-11-25", "2024-11-05"),
    )
    assert health.ok is True
    assert health.database_open is False
    assert health.server_version == "0.0.1"
    assert health.protocol_versions == ("2025-11-25", "2024-11-05")
    assert health.idb_path is None
    assert health.uptime_s is None


def test_health_status_full_construction():
    health = HealthStatus(
        ok=True,
        database_open=True,
        server_version="1.2.3",
        protocol_versions=("2025-11-25",),
        idb_path="/tmp/target.i64",
        uptime_s=12.5,
    )
    assert health.idb_path == "/tmp/target.i64"
    assert health.uptime_s == 12.5


# -- Pseudocode -------------------------------------------------------------- #


def test_pseudocode_defaults():
    pc = Pseudocode(ea=Address(0x401000), text="int main() { return 0; }")
    assert pc.ea == Address(0x401000)
    assert pc.text == "int main() { return 0; }"
    assert pc.lines == ()
    assert pc.name is None


def test_pseudocode_full_construction():
    pc = Pseudocode(
        ea=Address(0x401000),
        text="a\nb",
        lines=("a", "b"),
        name="main",
    )
    assert pc.lines == ("a", "b")
    assert pc.name == "main"


def test_pseudocode_is_frozen():
    pc = Pseudocode(ea=Address(0x401000), text="x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        pc.text = "y"  # type: ignore[misc]
