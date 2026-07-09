"""Catalog registration and wire-shape projection for ``type_inspect``.

The ``TypeMemberView`` / ``TypeInspectView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`type_inspect_view` renders the
resolved type into that flat shape, expanding each aggregate member's
``name`` / ``type`` / ``offset`` / ``size``. The field names mirror the
interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.types import TypeInspectUseCase
from idamesh.application.dto.types import TypeInspectCommand, TypeInspectResult
from idamesh.domain.entities.type_info import TypeInfo, TypeMember
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class TypeMemberView(TypedDict):
    """One member of an inspected aggregate type."""

    name: str
    type: str
    offset: int
    size: int


class TypeInspectView(TypedDict):
    """The full definition of one inspected type."""

    name: str
    kind: str
    size: int
    members: List[TypeMemberView]


def type_member_view(member: TypeMember) -> TypeMemberView:
    """Project one :class:`TypeMember` into its wire shape."""
    return TypeMemberView(
        name=member.name,
        type=member.type_name,
        offset=member.offset,
        size=member.size,
    )


def type_inspect_view(info: TypeInfo) -> TypeInspectView:
    """Project an inspected :class:`TypeInfo` into its wire shape."""
    return TypeInspectView(
        name=info.name,
        kind=info.kind,
        size=info.size,
        members=[type_member_view(member) for member in info.members],
    )


def register_type_inspect(
    registry: Registry,
    *,
    type_inspect_use_case: TypeInspectUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``type_inspect`` against the type-inspection use-case."""

    @registry.tool(name="type_inspect")
    def type_inspect(name: str) -> TypeInspectView:
        """Inspect the definition of the type named ``name`` from the database's
        local type catalog. The result reports the type's ``name``, its coarse
        ``kind`` (e.g. struct / union / enum / typedef / pointer), its byte
        ``size``, and its ``members`` — one row per field with the member ``name``,
        rendered ``type``, byte ``offset`` from the start of the aggregate, and
        member ``size``. ``members`` is empty for non-aggregate types. An unknown
        type name yields an error result rather than failing the protocol request.
        Read-only."""
        command = TypeInspectCommand(name=name)
        result = run_use_case(
            executor, lambda: type_inspect_use_case.execute(command)
        )
        return type_inspect_view(result.type_info)
