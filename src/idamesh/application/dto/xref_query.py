"""Command/Result DTOs for ``xref_query``.

A filtered query over the :class:`~idamesh.domain.ports.xrefs.XrefRepository`,
anchored at one resolved address. ``direction`` selects the inbound edges pointing
at the anchor (``"to"``) or the outbound call edges leaving the function that owns
it (``"from"``); ``kind`` / ``type`` filter the resulting edges. The result is a
bounded, ``truncated``-flagged list of matched
:class:`~idamesh.domain.entities.xref.Xref` edges.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.xref import Xref
from idamesh.domain.values.address import Address

#: Matches returned when an ``xref_query`` client omits ``limit``.
DEFAULT_XREF_QUERY_LIMIT: int = 100
#: Hard ceiling a requested ``xref_query`` ``limit`` is clamped to.
MAX_XREF_QUERY_LIMIT: int = 1000
#: The accepted ``direction`` values.
XREF_DIRECTIONS: Tuple[str, ...] = ("to", "from")
#: The accepted ``kind`` filter values (``"any"`` does not filter on kind).
XREF_KINDS: Tuple[str, ...] = ("any", "code", "data")
#: The accepted ``type`` filter values (``"any"`` does not filter on type).
XREF_TYPES: Tuple[str, ...] = (
    "any",
    "call",
    "jump",
    "read",
    "write",
    "offset",
    "ordinary",
)


@dataclass(frozen=True)
class XrefQueryCommand:
    """Input for ``xref_query``.

    ``address`` is a hex/decimal/symbol selector resolved to the anchor.
    ``direction`` is ``"to"`` (edges into the anchor) or ``"from"`` (call edges out
    of the owning function). ``kind`` (``code`` / ``data``) and ``type`` (``call``
    / ``jump`` / ``read`` / ``write`` / ``offset`` / ``ordinary``) filter the
    edges; ``"any"`` leaves that axis unfiltered. ``limit`` bounds the matches and
    is clamped to a server maximum.
    """

    address: str
    direction: str = "to"
    kind: str = "any"
    type: str = "any"
    limit: int = DEFAULT_XREF_QUERY_LIMIT


@dataclass(frozen=True)
class XrefQueryResult:
    """Output for ``xref_query`` — the matched edges around ``anchor``."""

    anchor: Address
    direction: str
    xrefs: Tuple[Xref, ...]
    truncated: bool = False
