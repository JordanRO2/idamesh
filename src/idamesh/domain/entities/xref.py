"""The :class:`Xref` value object — one cross-reference edge.

A cross-reference is a directed edge from a *source* address (the instruction or
data item that refers) to a *target* address (the thing referred to), classified
on two independent axes: its :class:`XrefKind` (whether the edge is a code or a
data reference) and its :class:`XrefType` (the finer flavour — a call, a jump, a
read, a write, …). This single value object backs both the ``xrefs_to`` tool
(which reports edges *into* a target, carrying the enclosing function of each
source) and the ``callees`` tool (which reports the call edges *out of* a
function, carrying the name at each target). The two axes and the field set are
our modelling; the code/data and call/jump/read/write distinctions are facts of
how the SDK classifies references.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from idamesh.domain.values.address import Address


class XrefKind(Enum):
    """The coarse axis of a reference: to code, or to data."""

    CODE = "code"
    DATA = "data"


class XrefType(Enum):
    """The fine axis of a reference — the flavour of the edge."""

    CALL = "call"
    JUMP = "jump"
    READ = "read"
    WRITE = "write"
    OFFSET = "offset"
    ORDINARY = "ordinary"


@dataclass(frozen=True)
class Xref:
    """A single classified cross-reference edge, ``source`` -> ``target``."""

    source: Address
    target: Address
    kind: XrefKind
    ref_type: XrefType
    source_func: str | None = None
    target_name: str | None = None
