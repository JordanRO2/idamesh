"""Command/Result DTOs for the ``force_recompile`` tool.

``ForceRecompileCommand`` carries a polymorphic address selector;
``ForceRecompileResult`` wraps the resulting
:class:`~idamesh.domain.entities.recompilation.Recompilation`. The selector is
resolved in the use-case, which then routes the cache invalidation through the
recompile gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.recompilation import Recompilation


@dataclass(frozen=True)
class ForceRecompileCommand:
    """Input for ``force_recompile`` — the selector for a function address."""

    address: str


@dataclass(frozen=True)
class ForceRecompileResult:
    """Output for ``force_recompile`` — the completed cache invalidation."""

    recompilation: Recompilation
