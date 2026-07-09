"""Entities for ``find_dangerous_callers`` — a dangerous API and its call sites.

A :class:`DangerousCaller` records one code location that calls a dangerous
imported API: the call-site ``address`` and the enclosing ``function`` name when
the site sits inside a function. A :class:`DangerousApiMatch` groups every such
call site under the ``api`` that was called. The *shape* a client parses is the
interoperability contract; the two-level grouping and the field selection are
ours. The classification of *which* APIs are dangerous lives in the pure
:class:`~idamesh.domain.services.dangerous_apis.DangerousApiService`, not here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class DangerousCaller:
    """One call site of a dangerous API and its enclosing function."""

    address: Address
    function: str | None = None


@dataclass(frozen=True)
class DangerousApiMatch:
    """A dangerous API and every call site that reaches it."""

    api: str
    callers: Tuple[DangerousCaller, ...]
