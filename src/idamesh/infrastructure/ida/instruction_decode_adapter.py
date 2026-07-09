"""IDA adapter implementing :class:`InstructionDecodeGateway`.

Walks the instructions of the function containing an address and lowers each into
the pure
:class:`~idamesh.domain.entities.decoded_instruction.DecodedInstruction` model the
dataflow / taint / stack-string services consume. Per instruction it records the
mnemonic and, for every non-void operand, the operand kind, its rendered text, the
register / immediate / address / displacement it carries, the access width, and
whether the instruction reads and/or writes it (from the instruction's canonical
feature flags). Base/index registers of a memory phrase are recovered from the
operand's rendered text, which is processor-agnostic and sufficient for the
stack-slot detection the services need.

All ``ida_*``/``idc`` imports are performed lazily inside the method so this module
loads without IDA present; this is the *one* new SDK-touching adapter this batch
introduces.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from idamesh.domain.entities.decoded_instruction import (
    DecodedInstruction,
    Operand,
    OPERAND_KIND_IMM,
    OPERAND_KIND_MEM,
    OPERAND_KIND_PHRASE,
    OPERAND_KIND_REG,
)
from idamesh.domain.values.address import Address

#: Recovers ``base(+index)(*scale)(±disp)`` from a rendered memory operand such as
#: ``[rsp+20h]`` / ``[rbp-8]`` / ``[rax+rcx*4+10h]``. Authored parse, used only as a
#: robust, processor-agnostic fallback for the base/index/disp of a phrase.
_MEM_RE = re.compile(
    r"\[\s*(?P<base>[a-zA-Z_][a-zA-Z0-9_]*)?"
    r"(?:\s*\+\s*(?P<index>[a-zA-Z_][a-zA-Z0-9_]*)(?:\s*\*\s*(?P<scale>\d+))?)?"
    r"(?P<disp>\s*[+\-]\s*[0-9a-fA-Fx]+h?)?\s*\]"
)


class IdaInstructionDecodeGateway:
    """:class:`InstructionDecodeGateway` over the IDA SDK (single decode adapter)."""

    def decode_function(self, ea: Address) -> List[DecodedInstruction]:
        """Decode the instructions of the function containing ``ea``.

        Raises :class:`ValueError` when ``ea`` is inside no function. Returns the
        function's instructions in ascending address order, each lowered into the
        pure decoded model; an instruction that fails to decode is skipped while the
        walk still advances by the item size, so a data island cannot stall it.
        """
        import ida_bytes
        import ida_funcs
        import ida_idp
        import ida_lines
        import ida_ua

        try:
            import ida_ida

            self._addr_bytes = 8 if ida_ida.inf_is_64bit() else 4
        except Exception:  # noqa: BLE001 — default to 64-bit addressing
            self._addr_bytes = 8

        start = int(ea)
        func = ida_funcs.get_func(start)
        if func is None:
            raise ValueError(f"no function contains address {Address(start).hex()}")

        func_start = int(func.start_ea)
        func_end = int(func.end_ea)

        out: List[DecodedInstruction] = []
        cur = func_start
        insn = ida_ua.insn_t()
        while cur < func_end:
            decoded = ida_ua.decode_insn(insn, cur)
            if decoded <= 0:
                size = int(ida_bytes.get_item_size(cur))
                cur += size if size > 0 else 1
                continue
            size = int(decoded)

            mnem = ida_ua.print_insn_mnem(cur) or ""
            feature = insn.get_canon_feature()
            operands = self._operands(
                cur, insn, feature, ida_ua, ida_idp, ida_lines
            )

            try:
                anchor = Address(cur)
            except ValueError:
                break
            out.append(
                DecodedInstruction(
                    ea=anchor,
                    mnemonic=mnem.strip(),
                    operands=tuple(operands),
                )
            )
            cur += size
        return out

    # -- internals ---------------------------------------------------------

    def _operands(
        self, ea: int, insn, feature: int, ida_ua, ida_idp, ida_lines
    ) -> List[Operand]:
        """Lower every non-void operand of one decoded instruction."""
        result: List[Operand] = []
        for index in range(8):
            op = insn.ops[index]
            op_type = int(op.type)
            if op_type == ida_ua.o_void:
                break
            rendered = ida_ua.print_operand(ea, index) or ""
            text = ida_lines.tag_remove(rendered) if rendered else ""
            is_read, is_write = self._access(feature, index, ida_idp)
            size = self._dtype_size(op, ida_ua)
            result.append(
                self._operand(
                    index, op, op_type, text, size, is_read, is_write, ida_ua, ida_idp
                )
            )
        return result

    def _operand(
        self,
        index: int,
        op,
        op_type: int,
        text: str,
        size: Optional[int],
        is_read: bool,
        is_write: bool,
        ida_ua,
        ida_idp,
    ) -> Operand:
        """Build one :class:`Operand` from an ``op_t`` and its rendered text."""
        if op_type == ida_ua.o_reg:
            reg = self._reg_name(op, size, ida_idp) or (text.strip() or None)
            return Operand(
                index=index,
                kind=OPERAND_KIND_REG,
                text=text,
                reg=reg,
                size=size,
                is_read=is_read,
                is_write=is_write,
            )
        if op_type == ida_ua.o_imm:
            return Operand(
                index=index,
                kind=OPERAND_KIND_IMM,
                text=text,
                value=int(op.value),
                size=size,
                is_read=is_read,
                is_write=is_write,
            )
        if op_type in (ida_ua.o_mem, getattr(ida_ua, "o_near", 7), getattr(ida_ua, "o_far", 6)):
            return Operand(
                index=index,
                kind=OPERAND_KIND_MEM,
                text=text,
                value=int(op.addr),
                size=size,
                is_read=is_read,
                is_write=is_write,
            )
        if op_type in (ida_ua.o_phrase, ida_ua.o_displ):
            base_reg, index_reg, disp = self._parse_mem(text)
            if base_reg is None:
                # IDA renders a frame slot as ``[rsp+58h+var_18]``; the trailing
                # variable name defeats the text parse, so recover the base
                # register straight from the SDK operand (its ``reg`` field holds
                # the base of a displacement/phrase). This keeps stack-slot
                # detection working on real listings, not just synthetic ones.
                base_reg = self._base_register(op, ida_idp)
            if op_type == ida_ua.o_displ:
                # The SDK carries the displacement precisely; prefer it. Sign it at
                # the ADDRESS width (pointer width), not the operand's access width:
                # a stack displacement larger than the access-width mask (common:
                # ``[rsp+58h+var_18]`` with a byte/dword access) would otherwise be
                # truncated or mis-signed.
                disp = self._signed(int(op.addr), getattr(self, "_addr_bytes", 8))
            return Operand(
                index=index,
                kind=OPERAND_KIND_PHRASE,
                text=text,
                base_reg=base_reg,
                index_reg=index_reg,
                disp=disp if disp is not None else 0,
                size=size,
                is_read=is_read,
                is_write=is_write,
            )
        # Any other operand kind (register list, condition, …): keep the text only.
        return Operand(
            index=index,
            kind=OPERAND_KIND_MEM if op_type == ida_ua.o_mem else "other",
            text=text,
            size=size,
            is_read=is_read,
            is_write=is_write,
        )

    @staticmethod
    def _access(feature: int, index: int, ida_idp) -> Tuple[bool, bool]:
        """Read/write flags for operand ``index`` from the canonical feature bits."""
        use = getattr(ida_idp, f"CF_USE{index + 1}", 0)
        chg = getattr(ida_idp, f"CF_CHG{index + 1}", 0)
        is_read = bool(feature & use) if use else False
        is_write = bool(feature & chg) if chg else False
        # A memory/reg operand with neither flag is conservatively a read.
        if not is_read and not is_write:
            is_read = True
        return is_read, is_write

    @staticmethod
    def _dtype_size(op, ida_ua) -> Optional[int]:
        """Access width of an operand in bytes, or ``None`` if unavailable."""
        try:
            size = int(ida_ua.get_dtype_size(op.dtype))
        except Exception:  # noqa: BLE001 — width is best-effort
            return None
        return size if size > 0 else None

    @staticmethod
    def _base_register(op, ida_idp) -> Optional[str]:
        """Base register of a displacement/phrase operand, from the SDK.

        Named at pointer width (8 bytes) so a stack/frame base normalizes to its
        64-bit spelling (``rsp`` / ``rbp``). Used only as the fallback when the
        rendered text — IDA's ``[rsp+58h+var_18]`` frame-slot form — carries no
        parseable base.
        """
        try:
            name = ida_idp.get_reg_name(int(op.reg), 8)
        except Exception:  # noqa: BLE001 — base recovery is best-effort
            return None
        return name or None

    @staticmethod
    def _reg_name(op, size: Optional[int], ida_idp) -> Optional[str]:
        """Register name for an ``o_reg`` operand, sized to the operand width."""
        width = size if size and size > 0 else 8
        try:
            name = ida_idp.get_reg_name(int(op.reg), width)
        except Exception:  # noqa: BLE001 — fall back to the rendered text
            return None
        return name or None

    @staticmethod
    def _signed(value: int, size: Optional[int]) -> int:
        """Interpret ``value`` as a signed displacement of ``size`` bytes."""
        width = size if size and size > 0 else 8
        bits = 8 * width
        mask = (1 << bits) - 1
        v = value & mask
        if v >= (1 << (bits - 1)):
            v -= 1 << bits
        return v

    @staticmethod
    def _parse_mem(
        text: str,
    ) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Recover ``(base_reg, index_reg, disp)`` from a rendered memory operand."""
        match = _MEM_RE.search(text)
        if match is None:
            return None, None, None
        base = match.group("base")
        index = match.group("index")
        disp_text = match.group("disp")
        disp: Optional[int] = None
        if disp_text:
            cleaned = disp_text.replace(" ", "")
            sign = -1 if cleaned[0] == "-" else 1
            body = cleaned.lstrip("+-")
            try:
                if body.endswith("h"):
                    disp = sign * int(body[:-1], 16)
                elif body.lower().startswith("0x"):
                    disp = sign * int(body, 16)
                else:
                    disp = sign * int(body, 16)
            except ValueError:
                disp = None
        return (base or None), (index or None), disp
