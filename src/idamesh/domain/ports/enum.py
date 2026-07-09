"""The enum gateway port: create-or-extend an enumeration type.

Backs the ``enum_upsert`` tool. :meth:`upsert` idempotently ensures an enum type
named ``name`` exists and reconciles its members against the supplied name→value
map — adding missing members and updating changed ones without destroying members
the caller did not mention — then returns the enum's total member count afterward.
An invalid enum name, a duplicate value the representation forbids, or a member the
database refuses raises a domain error the caller surfaces as an ``isError``
result. The create-or-extend (never clobber) policy is our design; the SDK-level
enum edit is the adapter's job.
"""

from __future__ import annotations

from typing import Mapping, Protocol


class EnumGateway(Protocol):
    """Write-side create-or-update of an enumeration type."""

    def upsert(self, name: str, members: Mapping[str, int]) -> int:
        """Create or update enum ``name`` from ``members``; return the member count.

        When no enum named ``name`` exists one is created; otherwise the existing
        enum is extended. Each entry of ``members`` (member name → integer value)
        is added when absent or updated when its value changed; members already
        present and not listed are left untouched. The return value is the enum's
        total member count once the reconciliation completes. Raises an error
        (surfaced by the caller as an ``isError`` result) when ``name`` is not a
        legal identifier or a member cannot be added.
        """
        ...
