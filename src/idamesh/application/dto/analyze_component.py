"""Command/Result DTOs for ``analyze_component``.

The command carries the polymorphic ``address`` selector (the component root) and
the traversal ``depth``; the result wraps the aggregated
:class:`~idamesh.domain.entities.component.Component`.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.component import Component

#: Default number of call layers explored below the root when a client omits it.
DEFAULT_COMPONENT_DEPTH: int = 2
#: Hard ceiling the requested ``depth`` is clamped to.
MAX_COMPONENT_DEPTH: int = 5
#: Ceiling on distinct member functions a component materializes.
COMPONENT_MAX_NODES: int = 256


@dataclass(frozen=True)
class AnalyzeComponentCommand:
    """Input for ``analyze_component``.

    ``address`` is a polymorphic selector — a hex literal (``0x…``), a decimal
    literal, or a symbol name — resolved to the root function of the component.
    ``depth`` bounds how many call layers below the root are pulled in; it is
    clamped to :data:`MAX_COMPONENT_DEPTH`.
    """

    address: str
    depth: int = DEFAULT_COMPONENT_DEPTH


@dataclass(frozen=True)
class AnalyzeComponentResult:
    """Output for ``analyze_component`` — the call-subtree roll-up."""

    component: Component
