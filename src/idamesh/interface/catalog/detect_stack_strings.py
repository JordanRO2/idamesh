"""Catalog registration and wire-shape projection for ``detect_stack_strings``.

The ``StackStringView`` / ``DetectStackStringsView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`detect_stack_strings_view`
renders each reconstructed stack string into that flat shape (address as ``0x``
hex). The field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.detect_stack_strings import (
    DetectStackStringsUseCase,
)
from idamesh.application.dto.detect_stack_strings import (
    DetectStackStringsCommand,
    DetectStackStringsResult,
)
from idamesh.domain.entities.stack_string import StackString
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class StackStringView(TypedDict):
    """One stack-assembled string in a ``detect_stack_strings`` result."""

    address: str
    value: str
    function: Optional[str]


class DetectStackStringsView(TypedDict):
    """The stack strings reconstructed over the scanned scope."""

    matches: List[StackStringView]
    truncated: bool


def stack_string_view(match: StackString) -> StackStringView:
    """Project one :class:`StackString` into its wire shape (address as ``0x`` hex)."""
    return StackStringView(
        address=match.address.hex(),
        value=match.value,
        function=match.function,
    )


def detect_stack_strings_view(
    result: DetectStackStringsResult,
) -> DetectStackStringsView:
    """Project a ``detect_stack_strings`` result into its wire shape."""
    return DetectStackStringsView(
        matches=[stack_string_view(match) for match in result.matches],
        truncated=result.truncated,
    )


def register_detect_stack_strings(
    registry: Registry,
    *,
    detect_stack_strings_use_case: DetectStackStringsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``detect_stack_strings`` against the stack-string use-case."""

    @registry.tool(name="detect_stack_strings")
    def detect_stack_strings(address: str = "") -> DetectStackStringsView:
        """Detect strings assembled on the stack byte-by-byte via immediate stores.

        Scans a function's decoded instructions for runs of immediate stores into
        consecutive stack slots (``mov [rsp/rbp+disp], imm``) whose bytes are
        printable, and reconstructs each run into a string — a common
        obfuscation / anti-static technique. Reports each as a ``value`` with its
        ``address`` (``0x`` hex, the first store that contributes to it) and the
        enclosing ``function``. Pass an ``address`` (hex/decimal/symbol) to scope
        the scan to the one function containing it; omit it for a bounded
        whole-database scan. ``truncated`` is set when a bound elided further
        matches. An empty result is valid, not an error. Read-only."""
        command = DetectStackStringsCommand(address=address)
        result = run_use_case(
            executor, lambda: detect_stack_strings_use_case.execute(command)
        )
        return detect_stack_strings_view(result)
