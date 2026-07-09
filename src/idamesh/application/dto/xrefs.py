"""Command/Result DTOs for ``xrefs_to`` and ``callees``.

Both tools take one polymorphic ``address`` selector and return a set of shared
:class:`~idamesh.domain.entities.xref.Xref` edges, so their DTOs live together.
Each result echoes the resolved anchor address so the view can report which
target/function the edges belong to, and a ``truncated`` flag for when a
per-call cap elided some edges.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.xref import Xref
from idamesh.domain.values.address import Address

#: Per-call ceiling on the inbound edges ``xrefs_to`` returns for one target.
#: A busy target (e.g. a common helper) can be referenced thousands of times; we
#: cap the reply and raise ``truncated`` rather than flooding the client.
XREFS_TO_LIMIT: int = 100
#: Per-call ceiling on the distinct callees ``callees`` returns for one function.
#: Wide dispatchers reach many targets; the cap keeps the reply bounded and sets
#: ``truncated`` when it elides some.
CALLEES_LIMIT: int = 200


@dataclass(frozen=True)
class XrefsToCommand:
    """Input for ``xrefs_to``.

    ``address`` is a polymorphic selector — a hex literal (``0x…``), a decimal
    literal, or a symbol name — resolved to the target every reported edge
    points at.
    """

    address: str


@dataclass(frozen=True)
class XrefsToResult:
    """Output for ``xrefs_to`` — the edges pointing at ``target``."""

    target: Address
    xrefs: Tuple[Xref, ...]
    truncated: bool = False


@dataclass(frozen=True)
class CalleesCommand:
    """Input for ``callees``.

    ``address`` is a polymorphic selector resolved to an address inside (or at
    the entry of) the function whose direct callees are returned.
    """

    address: str


@dataclass(frozen=True)
class CalleesResult:
    """Output for ``callees`` — the call edges leaving ``func``."""

    func: Address
    callees: Tuple[Xref, ...]
    truncated: bool = False
