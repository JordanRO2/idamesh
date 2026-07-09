"""Overflow store: oversized results spill to a content-addressed MCP resource.

When a structured result exceeds the byte budget, the full payload is parked
here under its content hash and the client receives a shrunk preview plus an
``mcpref://overflow/<sha>`` URI it fetches back through ``resources/read``. This
works identically over stdio and HTTP and deduplicates identical payloads.
"""

from __future__ import annotations

import collections.abc as cabc
import enum
import hashlib
import json
import threading
from collections import OrderedDict
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Optional

#: URI scheme + host under which parked payloads are addressed.
OVERFLOW_URI_PREFIX: str = "mcpref://overflow/"


def json_default(obj: Any) -> Any:
    """Best-effort JSON coercion for non-native values (dataclasses, enums)."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, cabc.Mapping):
        return dict(obj)
    if isinstance(obj, (set, frozenset, tuple)):
        return list(obj)
    return str(obj)


def canonical_json(payload: Any) -> str:
    """A deterministic JSON rendering used for both hashing and size checks."""
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=json_default,
    )


@dataclass(frozen=True)
class OverflowRef:
    """A reference to a parked payload."""

    sha: str
    total_chars: int
    uri: str


class OverflowStore:
    """A thread-safe, bounded LRU of content-addressed payloads."""

    def __init__(self, *, max_entries: int = 128) -> None:
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._store: "OrderedDict[str, Any]" = OrderedDict()

    def put(self, payload: Any) -> OverflowRef:
        """Store a payload under ``sha256(canonical_json)`` and return its ref.
        Identical payloads collapse to one entry."""
        canonical = canonical_json(payload)
        sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with self._lock:
            if sha in self._store:
                self._store.move_to_end(sha)
            else:
                self._store[sha] = payload
                self._store.move_to_end(sha)
                while len(self._store) > self._max_entries:
                    self._store.popitem(last=False)
        return OverflowRef(sha=sha, total_chars=len(canonical), uri=OVERFLOW_URI_PREFIX + sha)

    def get(self, sha: str) -> Optional[Any]:
        """Retrieve a parked payload by hash, or ``None`` if evicted/absent."""
        with self._lock:
            if sha not in self._store:
                return None
            self._store.move_to_end(sha)
            return self._store[sha]

    def resolve_uri(self, uri: str) -> Optional[Any]:
        """Retrieve by full ``mcpref://overflow/<sha>`` URI."""
        if not uri.startswith(OVERFLOW_URI_PREFIX):
            return None
        return self.get(uri[len(OVERFLOW_URI_PREFIX):])

    def make_preview(
        self,
        payload: Any,
        *,
        budget_chars: int = 50_000,
        max_string: int = 1_000,
        max_items: int = 10,
        max_depth: int = 6,
    ) -> Any:
        """Structurally shrink ``payload`` to a size-safe preview (clip long
        strings, head-truncate long lists with a ``_more`` sentinel, recurse)."""

        def shrink(value: Any, depth: int) -> Any:
            if depth >= max_depth:
                return "… (truncated: max depth reached)"
            if isinstance(value, str):
                if len(value) > max_string:
                    return value[:max_string] + f"… ({len(value)} chars)"
                return value
            if isinstance(value, cabc.Mapping):
                return {key: shrink(val, depth + 1) for key, val in value.items()}
            if isinstance(value, (list, tuple)):
                items = list(value)
                head = [shrink(item, depth + 1) for item in items[:max_items]]
                if len(items) > max_items:
                    head.append({"_more": len(items) - max_items})
                return head
            if is_dataclass(value) and not isinstance(value, type):
                return shrink(asdict(value), depth)
            if isinstance(value, enum.Enum):
                return value.value
            return value

        return shrink(payload, 0)
