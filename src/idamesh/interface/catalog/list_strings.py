"""Catalog registration and wire-shape projection for ``list_strings``.

The ``StringItemView`` / ``ListStringsView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`list_strings_view` renders the
domain page into that flat shape (addresses as ``0x`` hex, the encoding ``kind``
projected to the wire key ``type``). The field names mirror the interoperability
contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.list_strings import ListStringsUseCase
from idamesh.application.dto.list_strings import ListStringsCommand
from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.domain.values.pagination import Page
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class StringItemView(TypedDict):
    """One extracted-string row in a ``list_strings`` page."""

    address: str
    length: int
    type: str
    value: str


class ListStringsView(TypedDict):
    """A page of :class:`StringItemView` rows plus continuation metadata."""

    items: List[StringItemView]
    offset: int
    count: int
    total: Optional[int]
    truncated: bool
    next_cursor: Optional[str]


def string_item_view(item: StringItem) -> StringItemView:
    """Project one :class:`StringItem` into its wire shape."""
    return StringItemView(
        address=item.address.hex(),
        length=item.length,
        type=item.kind,
        value=item.value,
    )


def list_strings_view(page: Page[StringItem]) -> ListStringsView:
    """Project a page of extracted strings into its wire shape."""
    return ListStringsView(
        items=[string_item_view(item) for item in page.items],
        offset=page.offset,
        count=page.count,
        total=page.total,
        truncated=page.truncated,
        next_cursor=page.next_cursor,
    )


def register_list_strings(
    registry: Registry,
    *,
    list_strings_use_case: ListStringsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``list_strings`` against the string-listing use-case."""

    @registry.tool(name="list_strings")
    def list_strings(offset: int = 0, count: int = 100) -> ListStringsView:
        """List the strings IDA extracted from the binary as a bounded page in
        address order. ``offset`` skips that many strings from the start;
        ``count`` caps how many are returned (clamped to a server maximum). Each
        row carries the string's ``address`` (``0x`` hex), its byte ``length``,
        its encoding ``type`` (for example a C/ASCII or a Unicode string), and its
        decoded ``value``. The result carries the total count and a ``truncated``
        flag so a caller can page through the whole set."""
        command = ListStringsCommand(offset=offset, count=count)
        result = run_use_case(
            executor, lambda: list_strings_use_case.execute(command)
        )
        return list_strings_view(result.page)
