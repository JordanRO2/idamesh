"""IDA adapter implementing :class:`DatabaseGateway`.

Thin SDK wrapper: metadata reads and name/address resolution. All ``ida_*``
imports are lazy (inside methods) so the module imports without IDA present.

The metadata reads lean on the ``ida_ida`` "inf" accessors (arch / bitness /
byte-order / entry point / bounds), ``ida_nalt`` for the input-file identity,
and the segment / function counters. Every field beyond the load-bearing few is
read defensively so an SDK-surface difference between IDA builds degrades to a
missing optional rather than a hard failure.
"""

from __future__ import annotations

from typing import Optional

from idamesh.domain.entities.metadata import DatabaseMetadata, Endianness
from idamesh.domain.values.address import INVALID_EA, Address, Selector


def _address_or_none(value: int) -> Optional[Address]:
    """Wrap a raw EA as an :class:`Address`, or ``None`` if it is the sentinel."""
    if value is None or value < 0 or value >= INVALID_EA:
        return None
    try:
        return Address(value)
    except ValueError:
        return None


class IdaDatabaseGateway:
    """:class:`~idamesh.domain.ports.database.DatabaseGateway` over the IDA SDK."""

    def metadata(self) -> DatabaseMetadata:
        import ida_ida
        import ida_nalt

        module = ida_nalt.get_root_filename() or ""
        path = ida_nalt.get_input_file_path() or ""
        architecture = ida_ida.inf_get_procname() or ""
        bits = self._bitness(ida_ida)
        endianness = (
            Endianness.BIG
            if getattr(ida_ida, "inf_is_be", lambda: False)()
            else Endianness.LITTLE
        )
        entrypoint = _address_or_none(ida_ida.inf_get_start_ea())
        image_base = self._image_base()
        function_count = self._function_count()
        segment_count = self._segment_count()

        return DatabaseMetadata(
            path=path,
            module=module,
            architecture=architecture,
            bits=bits,
            endianness=endianness,
            entrypoint=entrypoint,
            image_base=image_base,
            function_count=function_count,
            segment_count=segment_count,
            string_count=None,
            compiler=self._compiler(),
            filetype=self._filetype(),
            sha256=self._sha256(),
        )

    def is_open(self) -> bool:
        import ida_ida

        try:
            min_ea = ida_ida.inf_get_min_ea()
        except Exception:
            return False
        return min_ea is not None and 0 <= min_ea < INVALID_EA

    def resolve_symbol(self, name: str) -> int | None:
        import idaapi
        import idc

        ea = idc.get_name_ea_simple(name)
        if ea == idaapi.BADADDR:
            return None
        return int(ea)

    def resolve(self, selector: Selector) -> Address:
        # ``self`` is a structural ``SymbolResolver`` (it has ``resolve_symbol``),
        # so the selector delegates symbol lookups straight back here.
        return selector.resolve(self)

    # -- defensive field readers -------------------------------------------

    @staticmethod
    def _bitness(ida_ida) -> int:
        getter = getattr(ida_ida, "inf_get_app_bitness", None)
        if getter is not None:
            try:
                value = int(getter())
                if value in (16, 32, 64):
                    return value
            except Exception:
                pass
        try:
            if ida_ida.inf_is_64bit():
                return 64
            if ida_ida.inf_is_32bit_exactly():
                return 32
        except Exception:
            pass
        return 32

    @staticmethod
    def _image_base() -> Optional[Address]:
        try:
            import idaapi

            return _address_or_none(idaapi.get_imagebase())
        except Exception:
            return None

    @staticmethod
    def _function_count() -> int:
        try:
            import ida_funcs

            return int(ida_funcs.get_func_qty())
        except Exception:
            return 0

    @staticmethod
    def _segment_count() -> int:
        try:
            import ida_segment

            return int(ida_segment.get_segm_qty())
        except Exception:
            return 0

    @staticmethod
    def _filetype() -> Optional[str]:
        try:
            import ida_loader

            name = ida_loader.get_file_type_name()
            return name or None
        except Exception:
            return None

    @staticmethod
    def _compiler() -> Optional[str]:
        try:
            import ida_typeinf

            comp_id = None
            try:
                import ida_ida

                comp_id = ida_ida.inf_get_cc_id()
            except Exception:
                comp_id = None
            if comp_id is not None:
                name = ida_typeinf.get_compiler_name(comp_id)
                if name:
                    return name
        except Exception:
            pass
        return None

    @staticmethod
    def _sha256() -> Optional[str]:
        try:
            import ida_nalt

            digest = ida_nalt.retrieve_input_file_sha256()
            if not digest:
                return None
            if isinstance(digest, (bytes, bytearray)):
                return bytes(digest).hex()
            return str(digest)
        except Exception:
            return None
