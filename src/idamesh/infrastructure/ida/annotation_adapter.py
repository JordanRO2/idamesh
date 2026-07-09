"""IDA adapter implementing :class:`~idamesh.domain.ports.annotations.AnnotationGateway`.

The IDA-side half of the merge-back — the only place that reads/writes the raw
user annotations. The two SDK seams are implemented here; every ``ida_*``
import happens inside a function (never at module load) so the worker container can
register the tools and the whole package stays importable with no IDA present.

The SDK calls (the ``[merger]`` set) mirror the frozen wire conventions in
:mod:`idamesh.application.annotation_wire` — int ``ea`` keys, ``(ea, scope)``
comment keys, ``(regular, repeatable)`` comment signatures:

* **export** — provenance from ``ida_nalt.get_input_file_path`` /
  ``retrieve_input_file_sha256`` / ``idaapi.get_imagebase`` /
  ``idaapi.get_kernel_version``; user names gated by
  ``ida_bytes.has_user_name(get_full_flags(ea))`` read with ``ida_name.get_name``;
  line comments via ``ida_bytes.get_cmt(ea, rpt)`` (keyed ``(ea, "line")``) and
  function comments via ``ida_funcs.get_func_cmt(func, rpt)`` (keyed
  ``(ea, "func")``); user prototypes gated by
  ``ida_nalt.get_aflags(ea) & AFL_USERTI`` and rendered with
  ``ida_typeinf.print_type(ea, PRTYPE_1LINE | PRTYPE_SEMI)`` into a named,
  semicolon-terminated C declaration that re-parses cleanly.
* **apply** — reuse the existing write paths (``ida_name.set_name`` with
  ``SN_CHECK``; ``ida_bytes.set_cmt`` / ``ida_funcs.set_func_cmt``;
  ``ida_typeinf.parse_decl`` + ``apply_tinfo`` under ``TINFO_DEFINITE``),
  best-effort per item, collecting each refusal into
  :attr:`AnnotationApplyReport.failures` instead of raising.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from idamesh.domain.entities.annotations import AnnotationApplyReport
from idamesh.domain.services.reconciliation import AnnotationRecord, Provenance


class IdaAnnotationGateway:
    """:class:`~idamesh.domain.ports.annotations.AnnotationGateway` over the IDA SDK."""

    # -- export ------------------------------------------------------------- #

    def export(
        self,
        *,
        funcs: Optional[Sequence[int]] = None,
        include_types: bool = True,
    ) -> AnnotationRecord:
        """Read this copy's user annotations into an :class:`AnnotationRecord`.

        ``funcs`` restricts the export to the given function start addresses (each
        item head is read); ``None`` walks every head in the database plus every
        function's comment. Only *user* annotations are captured — renamed names
        (``has_user_name``), authored comments, and user-set prototypes
        (``AFL_USERTI``) — so a later baseline subtraction has little to prune.
        """
        # Lazy SDK imports keep this module importable without IDA present.
        import ida_funcs
        import idautils

        names: Dict[int, str] = {}
        comments: Dict[Tuple[int, str], Tuple[str, str]] = {}
        prototypes: Dict[int, str] = {}

        if funcs is None:
            import ida_ida

            min_ea = ida_ida.inf_get_min_ea()
            max_ea = ida_ida.inf_get_max_ea()
            for head in idautils.Heads(min_ea, max_ea):
                _read_item(int(head), names, comments, prototypes, include_types)
            for func_ea in idautils.Functions():
                _read_func_comment(int(func_ea), comments)
        else:
            for target in funcs:
                func = ida_funcs.get_func(int(target))
                if func is None:
                    continue
                start = int(func.start_ea)
                for head in idautils.FuncItems(start):
                    _read_item(int(head), names, comments, prototypes, include_types)
                _read_func_comment(start, comments)

        return AnnotationRecord(
            provenance=_provenance(),
            names=names,
            comments=comments,
            prototypes=prototypes,
        )

    # -- apply -------------------------------------------------------------- #

    def apply(self, record: AnnotationRecord) -> AnnotationApplyReport:
        """Write ``record``'s annotations into this copy, best-effort per item.

        Each name/comment/prototype is installed independently; a single item the
        database refuses is collected into
        :attr:`AnnotationApplyReport.failures` (never aborting the whole write),
        and the per-field applied counts tally what landed. The record's
        provenance is not consulted — identity gating is the caller's job.
        """
        names_applied = 0
        comments_applied = 0
        types_applied = 0
        failures: List[str] = []

        for key, name in record.names.items():
            ea = _key_ea(key)
            try:
                if _apply_name(ea, str(name)):
                    names_applied += 1
                else:
                    failures.append(f"name at {_hex(ea)}: refused {str(name)!r}")
            except Exception as exc:  # noqa: BLE001 — collected, never fatal
                failures.append(f"name at {_hex(ea)}: {exc}")

        for key, signature in record.comments.items():
            ea, scope = _split_comment_key(key)
            regular, repeatable = _split_signature(signature)
            try:
                if _apply_comment(ea, scope, regular, repeatable):
                    comments_applied += 1
                else:
                    failures.append(f"comment at {_hex(ea)} ({scope}): empty, skipped")
            except Exception as exc:  # noqa: BLE001 — collected, never fatal
                failures.append(f"comment at {_hex(ea)} ({scope}): {exc}")

        for key, decl in record.prototypes.items():
            ea = _key_ea(key)
            try:
                if _apply_prototype(ea, str(decl)):
                    types_applied += 1
                else:
                    failures.append(f"type at {_hex(ea)}: refused {str(decl)!r}")
            except Exception as exc:  # noqa: BLE001 — collected, never fatal
                failures.append(f"type at {_hex(ea)}: {exc}")

        return AnnotationApplyReport(
            names=names_applied,
            comments=comments_applied,
            types=types_applied,
            failures=tuple(failures),
        )


# -- export readers (lazy SDK) --------------------------------------------- #


def _read_item(
    ea: int,
    names: Dict[int, str],
    comments: Dict[Tuple[int, str], Tuple[str, str]],
    prototypes: Dict[int, str],
    include_types: bool,
) -> None:
    """Read the user name, line comments, and user prototype of one item head."""
    import ida_bytes
    import ida_name

    flags = ida_bytes.get_full_flags(ea)
    if ida_bytes.has_user_name(flags):
        name = ida_name.get_name(ea)
        if name:
            names[ea] = name

    regular = ida_bytes.get_cmt(ea, False)
    repeatable = ida_bytes.get_cmt(ea, True)
    if regular or repeatable:
        comments[(ea, "line")] = (regular or "", repeatable or "")

    if include_types and _has_user_type(ea):
        decl = _render_prototype(ea)
        if decl:
            prototypes[ea] = decl


def _read_func_comment(
    func_ea: int, comments: Dict[Tuple[int, str], Tuple[str, str]]
) -> None:
    """Read the enclosing-function's regular/repeatable comment, keyed ``(ea, "func")``."""
    import ida_funcs

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return
    regular = ida_funcs.get_func_cmt(func, False)
    repeatable = ida_funcs.get_func_cmt(func, True)
    if regular or repeatable:
        comments[(int(func.start_ea), "func")] = (regular or "", repeatable or "")


def _has_user_type(ea: int) -> bool:
    """True when the item carries a *user-supplied* type (``AFL_USERTI``)."""
    import ida_nalt

    try:
        return bool(ida_nalt.get_aflags(ea) & ida_nalt.AFL_USERTI)
    except Exception:  # noqa: BLE001 — defensive across SDK builds
        return False


def _render_prototype(ea: int) -> Optional[str]:
    """Render the item's type as a named, semicolon-terminated C declaration.

    ``print_type`` with ``PRTYPE_1LINE | PRTYPE_SEMI`` yields e.g.
    ``int main(int a, int b);`` — a full declaration ``parse_decl`` re-parses and
    ``apply_tinfo`` re-applies (the embedded name is cosmetic; apply keys off the
    target ea). Falls back to the type-only ``idc.get_type`` string if
    ``print_type`` yields nothing.
    """
    import ida_typeinf

    flags = getattr(ida_typeinf, "PRTYPE_1LINE", 0) | getattr(
        ida_typeinf, "PRTYPE_SEMI", 0
    )
    try:
        decl = ida_typeinf.print_type(ea, flags)
    except Exception:  # noqa: BLE001 — defensive
        decl = None
    if decl:
        return str(decl)
    try:
        import idc

        fallback = idc.get_type(ea)
        return str(fallback) if fallback else None
    except Exception:  # noqa: BLE001 — defensive
        return None


def _provenance() -> Provenance:
    """Identify the binary this copy was made from (the merge safety gate)."""
    import ida_nalt

    input_path = ida_nalt.get_input_file_path() or ""
    return Provenance(
        input_path=input_path,
        input_sha256=_sha256(),
        imagebase=_imagebase(),
        ida_version=_ida_version(),
    )


def _sha256() -> Optional[str]:
    try:
        import ida_nalt

        digest = ida_nalt.retrieve_input_file_sha256()
        if not digest:
            return None
        if isinstance(digest, (bytes, bytearray)):
            return bytes(digest).hex()
        return str(digest)
    except Exception:  # noqa: BLE001 — defensive
        return None


def _imagebase() -> Optional[int]:
    try:
        import idaapi

        base = idaapi.get_imagebase()
        return int(base) if base is not None else None
    except Exception:  # noqa: BLE001 — defensive
        return None


def _ida_version() -> Optional[str]:
    try:
        import idaapi

        version = idaapi.get_kernel_version()
        return str(version) if version else None
    except Exception:  # noqa: BLE001 — defensive
        return None


# -- apply writers (lazy SDK) ---------------------------------------------- #


def _apply_name(ea: int, name: str) -> bool:
    """Install a user name with the check flag (refuse invalid/colliding names)."""
    import ida_name

    flags = getattr(ida_name, "SN_CHECK", 0) | getattr(ida_name, "SN_NOWARN", 0)
    return bool(ida_name.set_name(ea, name, flags))


def _apply_comment(ea: int, scope: str, regular: str, repeatable: str) -> bool:
    """Write the regular/repeatable comment for a ``line`` or ``func`` scope.

    Returns ``True`` when at least one non-empty slot was written; raises when the
    database refuses a write or a ``func`` comment is requested off any function.
    Empty slots are skipped so a merge never clears an existing comment.
    """
    wrote_any = False
    if scope == "func":
        import ida_funcs

        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"no function contains {_hex(ea)}")
        if regular:
            if not ida_funcs.set_func_cmt(func, regular, False):
                raise ValueError("set_func_cmt(regular) refused")
            wrote_any = True
        if repeatable:
            if not ida_funcs.set_func_cmt(func, repeatable, True):
                raise ValueError("set_func_cmt(repeatable) refused")
            wrote_any = True
    else:
        import ida_bytes

        if regular:
            if not ida_bytes.set_cmt(ea, regular, False):
                raise ValueError("set_cmt(regular) refused")
            wrote_any = True
        if repeatable:
            if not ida_bytes.set_cmt(ea, repeatable, True):
                raise ValueError("set_cmt(repeatable) refused")
            wrote_any = True
    return wrote_any


def _apply_prototype(ea: int, decl: str) -> bool:
    """Parse a C declaration and apply the resulting type at ``ea`` (definite)."""
    import ida_typeinf

    til = ida_typeinf.get_idati()
    if til is None:
        raise ValueError("the local type library is unavailable")

    tif = ida_typeinf.tinfo_t()
    pt_flags = getattr(ida_typeinf, "PT_SIL", 0)
    text = decl if decl.rstrip().endswith(";") else decl + ";"
    parsed = ida_typeinf.parse_decl(tif, til, text, pt_flags)
    if parsed is None:
        raise ValueError(f"cannot parse type declaration: {decl!r}")
    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
        raise ValueError(f"cannot apply type {decl!r} at {_hex(ea)}")
    return True


# -- key/signature decomposition (SDK-free) -------------------------------- #


def _key_ea(key: Any) -> int:
    """The effective address a names/prototypes key encodes."""
    if isinstance(key, (tuple, list)) and key:
        return int(key[0])
    return int(key)


def _split_comment_key(key: Any) -> Tuple[int, str]:
    """Decompose a comment key into ``(ea, scope)`` (tolerates a bare ea → line)."""
    if isinstance(key, (tuple, list)) and len(key) >= 2:
        return int(key[0]), str(key[1])
    return int(key), "line"


def _split_signature(signature: Any) -> Tuple[str, str]:
    """Decompose a comment signature into ``(regular, repeatable)`` strings."""
    if isinstance(signature, (tuple, list)):
        regular = signature[0] if len(signature) > 0 else ""
        repeatable = signature[1] if len(signature) > 1 else ""
    else:
        regular, repeatable = signature, ""
    return ("" if regular is None else str(regular)), (
        "" if repeatable is None else str(repeatable)
    )


def _hex(ea: int) -> str:
    try:
        return hex(int(ea))
    except (TypeError, ValueError):
        return repr(ea)
