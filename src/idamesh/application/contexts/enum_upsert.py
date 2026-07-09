"""The ``enum_upsert`` use-case: create-or-extend an enumeration type.

Validates the enum name and the member map, then hands the reconciliation to the
:class:`~idamesh.domain.ports.enum.EnumGateway`, which creates the enum when
missing and merges the members without clobbering ones the caller did not mention,
returning the member count afterward. No address is involved. The input guards and
the result assembly are the application's; the create-or-extend SDK edit is the
gateway's.
"""

from __future__ import annotations

from typing import Dict, Mapping

from idamesh.application.dto.enum_upsert import (
    EnumUpsertCommand,
    EnumUpsertResult,
)
from idamesh.domain.entities.enum_definition import EnumDefinition
from idamesh.domain.ports.enum import EnumGateway


def _require_name(name: str) -> str:
    """Return ``name`` if it is a non-empty, non-blank string, else raise."""
    if not isinstance(name, str):
        raise ValueError(f"name must be a string, got {type(name).__name__}")
    stripped = name.strip()
    if not stripped:
        raise ValueError("enum name must not be empty")
    return stripped


def _require_members(members: Mapping[str, int]) -> Dict[str, int]:
    """Return a validated ``{name: value}`` dict, else raise.

    Each key must be a non-blank identifier string and each value a non-boolean
    integer; an empty map is refused since an upsert with no members is not a
    change.
    """
    if not isinstance(members, Mapping):
        raise ValueError("members must be an object mapping names to values")
    if not members:
        raise ValueError("members must not be empty")
    validated: Dict[str, int] = {}
    for key, value in members.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError(f"member name must be a non-empty string: {key!r}")
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"member {key!r} value must be an integer: {value!r}")
        validated[key.strip()] = value
    return validated


class EnumUpsertUseCase:
    """Create or extend an enum, merging its members non-destructively."""

    def __init__(self, enums: EnumGateway) -> None:
        self._enums = enums

    def execute(self, command: EnumUpsertCommand) -> EnumUpsertResult:
        """Create-or-extend enum ``command.name`` from ``command.members``.

        The name and members are validated, then the enum gateway ensures the enum
        exists and reconciles its members, reporting the total member count
        afterward. The completed upsert is wrapped as an
        :class:`~idamesh.domain.entities.enum_definition.EnumDefinition`. An invalid
        name, an empty or malformed member map, or a member the database refuses
        surfaces as an error the interface layer renders as an ``isError`` result.
        """
        name = _require_name(command.name)
        members = _require_members(command.members)
        member_count = self._enums.upsert(name, members)
        definition = EnumDefinition(name=name, member_count=member_count)
        return EnumUpsertResult(definition=definition)
