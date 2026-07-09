"""A lazily-built, reusable cache of the database's extracted strings.

The SDK's string list (``idautils.Strings`` / ``ida_strlist``) is comparatively
expensive to walk, and every ``list_strings`` page would otherwise re-walk it.
This cache materializes the full address-ordered
:class:`~idamesh.domain.entities.string_item.StringItem` set once on first use
and hands back the same tuple across pages, mirroring how the global and import
repositories collect their rows. All ``ida_*`` imports happen lazily inside the
build step so this module loads without IDA present.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.values.address import Address


class StringsCache:
    """Materialize the extracted-string set once and reuse it across pages."""

    def __init__(self) -> None:
        self._rows: Optional[Tuple[StringItem, ...]] = None

    def rows(self) -> Tuple[StringItem, ...]:
        """Return the materialized string set, building it on first access."""
        cached = self._rows
        if cached is None:
            cached = self._build()
            self._rows = cached
        return cached

    def invalidate(self) -> None:
        """Drop the materialized set so the next access rebuilds it."""
        self._rows = None

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _build() -> Tuple[StringItem, ...]:
        import ida_bytes
        import ida_strlist

        StringsCache._ensure_strlist_covers_unicode()

        rows: List[StringItem] = []
        info = ida_strlist.string_info_t()
        # Iterate the string list *directly* rather than via ``idautils.Strings``:
        # that helper re-runs its own 1-byte-only setup when iterated, which would
        # discard the wider UTF-16/UTF-32 scan built just above and drop every
        # Unicode string.
        for index in range(ida_strlist.get_strlist_qty()):
            if not ida_strlist.get_strlist_item(info, index):
                continue
            try:
                address = Address(int(info.ea))
            except (ValueError, TypeError):
                continue
            length = int(getattr(info, "length", 0) or 0)
            if length < 0:
                length = 0
            strtype = int(getattr(info, "type", 0) or 0)
            rows.append(
                StringItem(
                    address=address,
                    length=length,
                    kind=_kind_of(strtype),
                    value=_decode_item(ida_bytes, int(info.ea), length, strtype),
                )
            )
        rows.sort(key=lambda row: row.address.value)
        return tuple(rows)

    @staticmethod
    def _ensure_strlist_covers_unicode() -> None:
        """Rebuild IDA's string list so it covers 1-byte, UTF-16, and UTF-32 text.

        IDA's default string-list scan considers only 1-byte (C) strings, and
        ``idalib`` never builds the list on its own — so a binary whose text is
        UTF-16 (common for Windows and Asian-locale software) would otherwise list
        no strings even though it has them. Widen the scan to the common character
        widths and rebuild, then restore the caller's previous options so an
        interactive Strings-window configuration is left as it was (the rebuilt
        list itself stands until the user refreshes it). Best-effort: any absent
        symbol or SDK-shape mismatch leaves whatever list already exists untouched.
        """
        try:
            import ida_nalt
            import ida_strlist
        except Exception:
            return
        try:
            opts = ida_strlist.get_strlist_options()
            widths = [ida_nalt.STRTYPE_C]
            for name in ("STRTYPE_C_16", "STRTYPE_C_32"):
                code = getattr(ida_nalt, name, None)
                if code is not None:
                    widths.append(code)
            saved_types = list(opts.strtypes)
            saved_existing = opts.display_only_existing_strings
            opts.strtypes = widths
            opts.display_only_existing_strings = False
            ida_strlist.build_strlist()
            opts.strtypes = saved_types
            opts.display_only_existing_strings = saved_existing
        except Exception:
            return


def _decode_item(ida_bytes: Any, ea: int, length: int, strtype: int) -> str:
    """Decode a string-list item's text.

    ``get_strlit_contents`` decodes the string's stored bytes at its native width
    (UTF-16 / UTF-32 / 1-byte) and returns the result already **UTF-8 encoded**, so
    the text is recovered with a single UTF-8 decode regardless of the source width
    (a naive width-based re-decode would garble a Unicode string). ``latin-1`` is a
    lossless last resort for a payload that is not valid UTF-8.
    """
    try:
        raw = ida_bytes.get_strlit_contents(ea, length if length > 0 else -1, strtype)
    except Exception:
        raw = None
    if not raw:
        return ""
    try:
        return raw.decode("utf-8", "replace")
    except Exception:
        return raw.decode("latin-1", "replace")


def _kind_of(strtype: int) -> str:
    """Project an IDA ``STRTYPE`` code to a short, human encoding name.

    The low bits of a ``STRTYPE`` carry the character width; a 2-byte width is a
    UTF-16/Unicode string and a 4-byte width a UTF-32 one, while the common
    single-byte width is a C/ASCII string.
    """
    try:
        import ida_nalt

        mask = getattr(ida_nalt, "STRWIDTH_MASK", 0x03)
        width = int(strtype) & int(mask)
        if width == getattr(ida_nalt, "STRWIDTH_2B", 0x01):
            return "unicode"
        if width == getattr(ida_nalt, "STRWIDTH_4B", 0x02):
            return "utf-32"
        return "C"
    except Exception:
        return "C"


