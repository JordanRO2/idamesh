"""Catalog registration and wire-shape projection for ``define_func`` (mutating).

The ``DefineFuncView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`define_func_view` renders the completed creation into that
flat shape (address as ``0x`` hex, ``ok`` always true on success, ``name`` null
when the new function is unnamed). The tool is marked ``@registry.mutating`` so its
advertised ``readOnlyHint`` is ``false``. The field names mirror the
interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import Optional, TypedDict

from idamesh.application.contexts.define_func import DefineFuncUseCase
from idamesh.application.dto.define_func import DefineFuncCommand
from idamesh.domain.entities.code_definition import FunctionDefinition
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class DefineFuncView(TypedDict):
    """The outcome of one ``define_func`` call."""

    address: str
    ok: bool
    name: Optional[str]


def define_func_view(definition: FunctionDefinition) -> DefineFuncView:
    """Project a :class:`FunctionDefinition` into its wire shape."""
    return DefineFuncView(
        address=definition.address.hex(),
        ok=True,
        name=definition.name,
    )


def register_define_func(
    registry: Registry,
    *,
    define_func_use_case: DefineFuncUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``define_func`` against the define-func use-case (mutating)."""

    @registry.tool(name="define_func")
    @registry.mutating
    def define_func(address: str) -> DefineFuncView:
        """Create a function at ``address``. The ``address`` may be a hexadecimal
        literal (``0x…``), a decimal literal, or a symbol name; it is resolved
        first, and should point at the entry instruction of the intended function.
        The analyzer infers the function's end. The result reports the resolved
        ``address`` (``0x`` hex), ``ok``, and the new function's ``name`` (null when
        it is unnamed). This modifies the database. An address with no decodable
        instruction to base a function on, or an unresolvable address, yields an
        error result rather than failing the protocol request."""
        command = DefineFuncCommand(address=address)
        result = run_mutation(
            executor, lambda: define_func_use_case.execute(command)
        )
        return define_func_view(result.definition)
