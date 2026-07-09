"""The :class:`NamedEntity` entity — a unified named, addressed database item.

``entity_query`` returns one flat stream spanning three kinds of named entity —
functions, named globals, and imported symbols — so it needs a common shape to
carry a match regardless of which repository produced it. :class:`NamedEntity` is
that projection: a ``name`` + ``ea`` + a ``kind`` tag, with the kind-specific
extras (``size`` for functions/globals, ``module`` / ``ordinal`` for imports)
present only where they apply. The unification and the ``kind`` vocabulary are our
authored design; the underlying facts (an address, a name, a module) are the
interoperability contract a client parses.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address

#: ``kind`` tag for a match drawn from the function repository.
KIND_FUNCTION = "function"
#: ``kind`` tag for a match drawn from the named-global repository.
KIND_GLOBAL = "global"
#: ``kind`` tag for a match drawn from the import repository.
KIND_IMPORT = "import"


@dataclass(frozen=True)
class NamedEntity:
    """A named, addressed entity tagged with which repository produced it."""

    name: str
    ea: Address
    kind: str
    size: int | None = None
    module: str | None = None
    ordinal: int | None = None
