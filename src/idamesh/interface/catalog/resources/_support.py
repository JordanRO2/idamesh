"""Shared helpers for the ``ida://…`` resource catalog.

Resource handlers reuse the tool catalog's kernel-thread marshalling
(:func:`idamesh.interface.catalog._support.run_use_case`), so a failed target
(unresolvable address, unknown type, unreadable region) is raised as a
:class:`~idamesh.interface.mcp.engine.ToolError`. The engine's ``resources_read``
maps that to a ``resources/read`` resource-not-found protocol error — never a
tool ``isError`` envelope, which resources do not have.

:func:`not_implemented` is the frozen-contract placeholder a builder swaps for
the real one-line ``run_use_case`` + view projection: the resource is already
registered (so it lists and its URI template compiles), but reading it raises a
clean resource-not-found until the body is filled in.
"""

from __future__ import annotations

from typing import NoReturn

from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.engine import ToolError

__all__ = ["run_use_case", "not_implemented"]


def not_implemented(uri: str) -> NoReturn:
    """Raise a resource-not-found ``ToolError`` for an unfilled resource stub."""
    raise ToolError(f"resource {uri!r} is not yet implemented")
