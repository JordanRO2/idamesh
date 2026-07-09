"""IDA adapter implementing :class:`~idamesh.domain.ports.patch.PatchGateway`.

Backs the ``patch`` and ``patch_asm`` tools. :meth:`patch_bytes` overwrites the
raw bytes at an address with ``ida_bytes.patch_bytes`` and reports the count
landed; :meth:`assemble` encodes a single instruction through IDA's own assembler
(the ``idautils.Assemble`` path, which wraps ``ida_idp``'s ``AssembleLine``) and
returns the machine bytes *without* writing them, so the caller can patch and echo
the encoding. Text the architecture's assembler cannot encode raises a
:class:`ValueError` — surfaced by the application as an ``isError`` result — and
assembly is never delegated to an external engine. All ``ida_*`` / ``idautils``
imports are performed lazily inside the methods so this module loads without IDA
present.
"""

from __future__ import annotations

from idamesh.domain.values.address import Address


class IdaPatchGateway:
    """:class:`~idamesh.domain.ports.patch.PatchGateway` over the IDA SDK."""

    def patch_bytes(self, ea: Address, data: bytes) -> int:
        """Overwrite the bytes at ``ea`` with ``data``; return the count written.

        ``ida_bytes.patch_bytes`` writes the whole buffer into the database's
        patched-bytes store starting at ``ea``; it reports nothing, so the number of
        bytes patched is the buffer length. A region the SDK refuses to write raises,
        which the application renders as an ``isError`` result.
        """
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_bytes

        payload = bytes(data)
        ida_bytes.patch_bytes(int(ea), payload)
        return len(payload)

    def assemble(self, ea: Address, text: str) -> bytes:
        """Assemble the single instruction ``text`` at ``ea`` and return its bytes.

        ``idautils.Assemble`` drives the target architecture's own assembler
        (``ida_idp.AssembleLine``), encoding ``text`` as if placed at ``ea`` so
        ``ea``-relative operands resolve, and hands back the encoded bytes *without*
        patching them. It reports ``(True, encoding)`` on success and
        ``(False, message)`` when the architecture cannot encode ``text`` (or there
        is no segment at ``ea``); the failure is raised as a :class:`ValueError`,
        which the application renders as an ``isError`` result. Assembly is never
        delegated to an external engine.
        """
        # Lazy SDK import keeps this module importable without IDA present.
        import idautils

        ok, result = idautils.Assemble(int(ea), text)
        if not ok:
            raise ValueError(
                f"cannot assemble {text!r} at {ea.hex()}: {result}"
            )
        return _as_bytes(result, text, ea)


def _as_bytes(result: object, text: str, ea: Address) -> bytes:
    """Coerce the assembler's success payload into a ``bytes`` encoding.

    A single instruction encodes to one buffer; ``idautils.Assemble`` returns it
    directly as ``bytes`` on IDA 9's Python 3 SWIG bindings. A ``bytearray`` is
    normalised, a legacy ``str`` payload is read as raw octets (Latin-1, one byte
    per code point), and a list (the shape used for multi-line input) is joined
    defensively. Anything else is an encoding the adapter cannot interpret and
    raises rather than guess.
    """
    if isinstance(result, (bytes, bytearray)):
        return bytes(result)
    if isinstance(result, str):
        return result.encode("latin-1")
    if isinstance(result, (list, tuple)):
        return b"".join(_as_bytes(part, text, ea) for part in result)
    raise ValueError(
        f"assembler returned an unreadable encoding for {text!r} at {ea.hex()}"
    )
