"""Command/Result DTOs for ``read_struct``.

``read_struct`` resolves a polymorphic address, fetches the named struct's field
layout, reads the covering byte run, and decodes each field, returning a
:class:`~idamesh.domain.entities.struct_read.StructReadResult`. An unknown struct
name or an unresolvable/unreadable address is surfaced by the use-case as an error
the interface layer renders as an ``isError`` result.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.struct_read import StructReadResult


@dataclass(frozen=True)
class ReadStructCommand:
    """Input for ``read_struct``.

    ``address`` is a polymorphic selector — a hex literal (``0x…``), a decimal
    literal, or a symbol name — resolved to the start of the object; ``struct`` is
    the name of the aggregate type to interpret the memory as.
    """

    address: str
    struct: str


@dataclass(frozen=True)
class ReadStructResult:
    """Output for ``read_struct`` — the decoded struct read from memory."""

    result: StructReadResult
