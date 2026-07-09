"""Wire-shape ``TypedDict``s and converters for the Phase-1 tool results.

The catalog binds tools to use-cases that return rich *domain* objects; a client
sees a flat, JSON-native projection instead. These ``TypedDict`` shapes give the
schema compiler an object-rooted ``outputSchema`` for each tool, and the small
converters render domain value objects (addresses as ``0x`` hex, enums as their
value) into that shape. The field *names* mirror the interoperability contract;
the projection choices are ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.domain.entities.data import Global
from idamesh.domain.entities.decompilation import Pseudocode
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.metadata import DatabaseMetadata, HealthStatus
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import Page


class MetadataView(TypedDict):
    """Flat projection of :class:`DatabaseMetadata`."""

    path: str
    module: str
    architecture: str
    bits: int
    endianness: str
    entrypoint: Optional[str]
    image_base: Optional[str]
    function_count: int
    segment_count: int
    string_count: Optional[int]
    compiler: Optional[str]
    filetype: Optional[str]
    sha256: Optional[str]


class HealthView(TypedDict):
    """Flat projection of :class:`HealthStatus`."""

    ok: bool
    database_open: bool
    server_version: str
    protocol_versions: List[str]
    idb_path: Optional[str]
    uptime_s: Optional[float]


class FunctionView(TypedDict):
    """One function row in a ``list_funcs`` page."""

    name: str
    start: str
    end: Optional[str]
    size: int
    is_library: bool
    is_thunk: bool


class ListFuncsView(TypedDict):
    """A page of :class:`FunctionView` rows plus continuation metadata."""

    items: List[FunctionView]
    offset: int
    count: int
    total: Optional[int]
    truncated: bool
    next_cursor: Optional[str]


class GlobalView(TypedDict):
    """One global (named data symbol) row in a ``list_globals`` page."""

    name: str
    address: str
    size: int
    type: Optional[str]


class ListGlobalsView(TypedDict):
    """A page of :class:`GlobalView` rows plus continuation metadata."""

    items: List[GlobalView]
    offset: int
    count: int
    total: Optional[int]
    truncated: bool
    next_cursor: Optional[str]


class DecompileView(TypedDict):
    """Pseudocode for one function."""

    name: Optional[str]
    address: str
    pseudocode: str
    lines: List[str]


def _hex_or_none(address: Optional[Address]) -> Optional[str]:
    return address.hex() if address is not None else None


def metadata_view(metadata: DatabaseMetadata) -> MetadataView:
    return MetadataView(
        path=metadata.path,
        module=metadata.module,
        architecture=metadata.architecture,
        bits=metadata.bits,
        endianness=metadata.endianness.value,
        entrypoint=_hex_or_none(metadata.entrypoint),
        image_base=_hex_or_none(metadata.image_base),
        function_count=metadata.function_count,
        segment_count=metadata.segment_count,
        string_count=metadata.string_count,
        compiler=metadata.compiler,
        filetype=metadata.filetype,
        sha256=metadata.sha256,
    )


def health_view(health: HealthStatus) -> HealthView:
    return HealthView(
        ok=health.ok,
        database_open=health.database_open,
        server_version=health.server_version,
        protocol_versions=list(health.protocol_versions),
        idb_path=health.idb_path,
        uptime_s=health.uptime_s,
    )


def function_view(function: Function) -> FunctionView:
    return FunctionView(
        name=function.name,
        start=function.ea.hex(),
        end=_hex_or_none(function.end_ea),
        size=function.size,
        is_library=function.is_library,
        is_thunk=function.is_thunk,
    )


def list_funcs_view(page: Page[Function]) -> ListFuncsView:
    return ListFuncsView(
        items=[function_view(item) for item in page.items],
        offset=page.offset,
        count=page.count,
        total=page.total,
        truncated=page.truncated,
        next_cursor=page.next_cursor,
    )


def global_view(item: Global) -> GlobalView:
    return GlobalView(
        name=item.name,
        address=item.ea.hex(),
        size=item.size,
        type=item.type_name,
    )


def list_globals_view(page: Page[Global]) -> ListGlobalsView:
    return ListGlobalsView(
        items=[global_view(item) for item in page.items],
        offset=page.offset,
        count=page.count,
        total=page.total,
        truncated=page.truncated,
        next_cursor=page.next_cursor,
    )


def decompile_view(pseudocode: Pseudocode) -> DecompileView:
    return DecompileView(
        name=pseudocode.name,
        address=pseudocode.ea.hex(),
        pseudocode=pseudocode.text,
        lines=list(pseudocode.lines),
    )
