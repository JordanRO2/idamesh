"""The :class:`FuncRef` entity — a compact function reference (address + name).

A ``FuncRef`` is the minimal identity of a function: its entry ``address`` and
its ``name``. It backs the bulk ``export_funcs`` export and the ``lookup_funcs``
name search, both of which return just enough to feed a function into another
tool without the fuller :class:`~idamesh.domain.entities.function.Function`
shape. The *shape* (name + address per row) is the interoperability contract a
client parses; keeping a distinct lightweight entity, rather than reusing the
richer ``Function``, is our choice so these bulk endpoints stay compact.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class FuncRef:
    """A single function referenced by its entry address and name."""

    address: Address
    name: str
