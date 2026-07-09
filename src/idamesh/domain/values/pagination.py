"""The pagination contract as value objects.

Every list-shaped tool speaks ``{offset, count}`` and returns a :class:`Page`
carrying its items plus an opaque :class:`Cursor`. The cursor is tamper-evident:
it stamps the next offset together with a hash of the originating arguments, so a
cursor replayed against a different query is detectable rather than silently
returning mismatched rows.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Generic, Sequence, TypeVar

T = TypeVar("T")

#: Default page size when a client omits ``count``.
DEFAULT_COUNT: int = 100
#: Hard ceiling a request is clamped to regardless of the requested ``count``.
MAX_COUNT: int = 1000


@dataclass(frozen=True)
class Cursor:
    """An opaque, args-stamped pagination cursor."""

    offset: int
    args_hash: str

    def encode(self) -> str:
        """Serialize to the opaque base64 token clients round-trip verbatim."""
        raw = json.dumps(
            {"o": self.offset, "h": self.args_hash}, separators=(",", ":")
        ).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    @classmethod
    def decode(cls, token: str) -> "Cursor":
        """Parse an opaque token. Raises ``ValueError`` on a malformed token."""
        try:
            raw = base64.urlsafe_b64decode(token.encode("ascii"))
            obj = json.loads(raw)
            return cls(offset=int(obj["o"]), args_hash=str(obj["h"]))
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"malformed cursor token: {token!r}") from exc

    def matches(self, args_hash: str) -> bool:
        """``True`` when this cursor was minted for the same query arguments."""
        return self.args_hash == args_hash


@dataclass(frozen=True)
class PageRequest:
    """A validated slice request over an entity stream."""

    offset: int = 0
    count: int = DEFAULT_COUNT

    @classmethod
    def of(cls, offset: int | None, count: int | None) -> "PageRequest":
        """Build a request, applying defaults for omitted fields."""
        resolved_offset = 0 if offset is None else int(offset)
        resolved_count = DEFAULT_COUNT if count is None else int(count)
        if resolved_offset < 0:
            resolved_offset = 0
        if resolved_count < 0:
            resolved_count = DEFAULT_COUNT
        return cls(offset=resolved_offset, count=resolved_count)

    @classmethod
    def from_cursor(cls, token: str, *, args_hash: str) -> "PageRequest":
        """Rebuild a request from an opaque cursor, verifying the args hash.
        Raises ``ValueError`` if the cursor does not match ``args_hash``."""
        cursor = Cursor.decode(token)
        if not cursor.matches(args_hash):
            raise ValueError("cursor does not match the current query arguments")
        return cls(offset=cursor.offset, count=DEFAULT_COUNT)

    def clamp(self, max_count: int = MAX_COUNT) -> "PageRequest":
        """Return a copy with ``count`` bounded to ``max_count``."""
        clamped = self.count
        if clamped > max_count:
            clamped = max_count
        if clamped < 0:
            clamped = 0
        offset = self.offset if self.offset >= 0 else 0
        if clamped == self.count and offset == self.offset:
            return self
        return PageRequest(offset=offset, count=clamped)


@dataclass(frozen=True)
class Page(Generic[T]):
    """A materialized page of results plus its continuation metadata."""

    items: Sequence[T]
    offset: int
    count: int
    total: int | None = None
    truncated: bool = False
    next_cursor: str | None = None
