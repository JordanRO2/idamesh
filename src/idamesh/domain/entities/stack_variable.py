"""Stack-variable entities: :class:`StackVariableDefinition` and :class:`StackVariableDeletion`.

Back the ``declare_stack`` and ``delete_stack`` tools. A
:class:`StackVariableDefinition` records one completed frame-variable definition —
the owning ``function`` (its resolved entry address) and the variable ``name``. A
:class:`StackVariableDeletion` records one completed removal, carrying the same
pair. The *shapes* (the field sets a client parses) are the interoperability
contract; holding each outcome in an immutable record is ours. A refused
declare/delete never produces one — it surfaces as an error at the boundary
instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class StackVariableDefinition:
    """A completed frame-variable definition: the function and the variable name."""

    function: Address
    name: str


@dataclass(frozen=True)
class StackVariableDeletion:
    """A completed frame-variable removal: the function and the variable name."""

    function: Address
    name: str
