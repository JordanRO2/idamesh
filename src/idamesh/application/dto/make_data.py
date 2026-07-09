"""Command/Result DTOs for the ``make_data`` tool.

``MakeDataCommand`` carries a polymorphic address selector plus either a C ``type``
declaration or a raw ``size`` in bytes; ``MakeDataResult`` wraps the resulting
:class:`~idamesh.domain.entities.data_definition.DataDefinition`. The selector is
resolved in the use-case, which then routes the definition through the
data-definition gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.data_definition import DataDefinition


@dataclass(frozen=True)
class MakeDataCommand:
    """Input for ``make_data``.

    ``address`` is a polymorphic selector resolved to the item location. Supply a
    C ``type`` declaration to define a typed item sized to that type; otherwise
    supply a ``size`` in bytes (1/2/4/8 → byte/word/dword/qword) to define a
    primitive item. At least one of ``type`` or ``size`` must be given.
    """

    address: str
    type: str = ""
    size: int = 0


@dataclass(frozen=True)
class MakeDataResult:
    """Output for ``make_data`` — the completed data definition."""

    definition: DataDefinition
