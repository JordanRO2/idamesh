"""The :class:`StackString` entity — one string assembled on the stack.

A stack string is a run of printable bytes written to consecutive stack slots by
immediate stores (``mov [rsp+disp], imm``), a common obfuscation / anti-static
technique. A finding records the reconstructed ``value``, the ``address`` of the
first store that contributes to it, and the enclosing ``function`` name.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class StackString:
    """A string reconstructed from immediate stores to consecutive stack slots."""

    address: Address
    value: str
    function: Optional[str] = None
