"""Unit tests for the merge-back worker tools ``export_annotations`` /
``apply_annotations`` (no IDA).

A fake :class:`AnnotationGateway` and a resolver-backed fake database replace the
IDA adapter, so three layers are exercised without a database:

* the two use-cases — the export selector resolution + record hand-off, and the
  apply record hand-off / report wrap;
* the frozen wire projection — ``export_annotations`` returns the
  :class:`AnnotationRecordWire` shape (deterministic ``(ea, scope)`` ordering) and
  ``apply_annotations`` parses that same shape back into the exact domain
  key/signature conventions ``reconcile`` expects (int ``ea`` name/prototype keys,
  ``(ea, scope)`` comment keys, ``(regular, repeatable)`` comment signatures);
* the catalog registration — ``export_annotations`` is read-only, ``apply_annotations``
  is mutating and marshalled with write affinity, applied-counts/ok/failures are
  projected, and an adapter failure surfaces as a ``ToolError`` (``isError``).

The record the fake gateway records on apply lets a test assert the boundary
parse landed the frozen shape, and a wire round-trip (project the export, parse it
back through the apply boundary) proves the two tools compose across the process
hop the supervisor's merge fan-out relies on.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Sequence, Tuple, TypeVar

import pytest

from idamesh.application.annotation_wire import (
    annotation_record_from_wire,
    annotation_record_to_wire,
)
from idamesh.application.contexts.annotations import (
    ApplyAnnotationsUseCase,
    ExportAnnotationsUseCase,
)
from idamesh.application.dto.annotations import (
    ApplyAnnotationsCommand,
    ExportAnnotationsCommand,
)
from idamesh.domain.entities.annotations import AnnotationApplyReport
from idamesh.domain.services.reconciliation import AnnotationRecord, Provenance
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.annotations import (
    apply_view,
    register_apply_annotations,
    register_export_annotations,
)
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- fakes ------------------------------------------------------------------


class _FakeDatabase:
    """A resolver-backed database gateway over a fixed symbol table."""

    def __init__(self, symbols: Optional[Dict[str, int]] = None) -> None:
        self._symbols = symbols or {}

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        # Mirror the real gateway: numeric kinds parse directly, symbols look up.
        return selector.resolve(self)


class _FakeAnnotationGateway:
    """An in-memory ``AnnotationGateway`` recording every export/apply call.

    ``export`` returns the preset ``record`` and remembers the ``funcs`` /
    ``include_types`` it was asked for. ``apply`` remembers the domain record it
    received (so a test can assert the wire parse) and returns a preset report, or
    — by default — a clean report whose per-field counts equal the record's map
    sizes (modelling a fully-applied merge). ``raise_on_apply`` makes ``apply``
    raise, mirroring an adapter that blew up rather than collecting a per-item
    failure.
    """

    def __init__(
        self,
        *,
        record: Optional[AnnotationRecord] = None,
        report: Optional[AnnotationApplyReport] = None,
        raise_on_apply: Optional[Exception] = None,
    ) -> None:
        self._record = record if record is not None else _record()
        self._report = report
        self._raise_on_apply = raise_on_apply
        self.export_calls: List[Tuple[Optional[Sequence[int]], bool]] = []
        self.applied: List[AnnotationRecord] = []

    def export(
        self,
        *,
        funcs: Optional[Sequence[int]] = None,
        include_types: bool = True,
    ) -> AnnotationRecord:
        self.export_calls.append(
            (list(funcs) if funcs is not None else None, include_types)
        )
        return self._record

    def apply(self, record: AnnotationRecord) -> AnnotationApplyReport:
        self.applied.append(record)
        if self._raise_on_apply is not None:
            raise self._raise_on_apply
        if self._report is not None:
            return self._report
        return AnnotationApplyReport(
            names=len(record.names),
            comments=len(record.comments),
            types=len(record.prototypes),
        )


class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording write affinity."""

    def __init__(self) -> None:
        self.write_flags: List[bool] = []

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# -- fixtures ---------------------------------------------------------------


def _provenance() -> Provenance:
    return Provenance(
        input_path="C:/tmp/target.exe",
        input_sha256="ab" * 32,
        imagebase=0x140000000,
        ida_version="9.0",
    )


def _record(
    *,
    names: Optional[Dict[int, str]] = None,
    comments: Optional[Dict[Tuple[int, str], Tuple[str, str]]] = None,
    prototypes: Optional[Dict[int, str]] = None,
    provenance: Optional[Provenance] = None,
) -> AnnotationRecord:
    """A representative record touching every field, keyed the frozen way."""
    return AnnotationRecord(
        provenance=provenance if provenance is not None else _provenance(),
        names={0x2000: "handler", 0x1000: "parse_header"}
        if names is None
        else names,
        comments={
            (0x1000, "func"): ("does the parse", ""),
            (0x1000, "line"): ("prologue", "rpt note"),
            (0x2000, "line"): ("", "only repeatable"),
        }
        if comments is None
        else comments,
        prototypes={0x2000: "int handler(int a);", 0x1000: "void parse_header(void);"}
        if prototypes is None
        else prototypes,
    )


def _register(
    gateway: _FakeAnnotationGateway,
    database: _FakeDatabase,
    executor: _InlineExecutor,
) -> Registry:
    registry = Registry()
    register_export_annotations(
        registry,
        export_annotations_use_case=ExportAnnotationsUseCase(gateway, database),
        executor=executor,
    )
    register_apply_annotations(
        registry,
        apply_annotations_use_case=ApplyAnnotationsUseCase(gateway),
        executor=executor,
    )
    return registry


# -- export use-case: selector resolution -----------------------------------


def test_export_forwards_none_funcs_and_default_include_types():
    gateway = _FakeAnnotationGateway()
    use_case = ExportAnnotationsUseCase(gateway, _FakeDatabase())

    result = use_case.execute(ExportAnnotationsCommand())

    assert result.record is gateway._record
    assert gateway.export_calls == [(None, True)]


def test_export_resolves_hex_decimal_and_symbol_selectors():
    gateway = _FakeAnnotationGateway()
    database = _FakeDatabase(symbols={"handler": 0x406060})
    use_case = ExportAnnotationsUseCase(gateway, database)

    use_case.execute(
        ExportAnnotationsCommand(funcs=("0x401000", "4198400", "handler"))
    )

    # Each selector is resolved to an int ea before the gateway is asked to read.
    assert gateway.export_calls == [([0x401000, 4198400, 0x406060], True)]


def test_export_include_types_false_is_forwarded():
    gateway = _FakeAnnotationGateway()
    use_case = ExportAnnotationsUseCase(gateway, _FakeDatabase())

    use_case.execute(ExportAnnotationsCommand(funcs=None, include_types=False))

    assert gateway.export_calls == [(None, False)]


def test_export_unresolvable_selector_raises_before_reading():
    gateway = _FakeAnnotationGateway()
    use_case = ExportAnnotationsUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(ExportAnnotationsCommand(funcs=("ghost",)))
    # Resolution fails first: the gateway was never asked to read.
    assert gateway.export_calls == []


# -- apply use-case ---------------------------------------------------------


def test_apply_forwards_record_and_wraps_report():
    record = _record()
    report = AnnotationApplyReport(names=2, comments=3, types=2)
    gateway = _FakeAnnotationGateway(report=report)
    use_case = ApplyAnnotationsUseCase(gateway)

    result = use_case.execute(ApplyAnnotationsCommand(record=record))

    assert gateway.applied == [record]
    assert result.report is report


# -- export tool: wire projection -------------------------------------------


def test_export_tool_projects_record_to_the_frozen_wire_shape():
    gateway = _FakeAnnotationGateway(record=_record())
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())

    wire = registry.get_tool("export_annotations").invoke()

    # provenance block
    assert wire["provenance"] == {
        "input_path": "C:/tmp/target.exe",
        "input_sha256": "ab" * 32,
        "imagebase": 0x140000000,
        "ida_version": "9.0",
    }
    # names — ascending ea order, one {ea, name} per entry.
    assert wire["names"] == [
        {"ea": 0x1000, "name": "parse_header"},
        {"ea": 0x2000, "name": "handler"},
    ]
    # comments — ascending (ea, scope) order; "func" sorts before "line".
    assert wire["comments"] == [
        {"ea": 0x1000, "scope": "func", "regular": "does the parse", "repeatable": ""},
        {"ea": 0x1000, "scope": "line", "regular": "prologue", "repeatable": "rpt note"},
        {"ea": 0x2000, "scope": "line", "regular": "", "repeatable": "only repeatable"},
    ]
    # prototypes — ascending ea order, one {ea, type} per entry.
    assert wire["prototypes"] == [
        {"ea": 0x1000, "type": "void parse_header(void);"},
        {"ea": 0x2000, "type": "int handler(int a);"},
    ]


def test_export_tool_is_read_only():
    registry = _register(_FakeAnnotationGateway(), _FakeDatabase(), _InlineExecutor())

    spec = registry.get_tool("export_annotations")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is True


def test_export_tool_forwards_funcs_and_include_types():
    gateway = _FakeAnnotationGateway()
    database = _FakeDatabase(symbols={"handler": 0x406060})
    registry = _register(gateway, database, _InlineExecutor())

    registry.get_tool("export_annotations").invoke(
        funcs=["0x401000", "handler"], include_types=False
    )

    assert gateway.export_calls == [([0x401000, 0x406060], False)]


def test_export_tool_marshals_through_the_executor():
    executor = _InlineExecutor()
    registry = _register(_FakeAnnotationGateway(), _FakeDatabase(), executor)

    registry.get_tool("export_annotations").invoke()

    # The read is marshalled onto the kernel thread exactly once (reads are run
    # under the shipped write affinity; the read/write split is the readOnlyHint).
    assert executor.write_flags == [True]


def test_export_tool_unresolvable_selector_is_toolerror():
    registry = _register(_FakeAnnotationGateway(), _FakeDatabase(), _InlineExecutor())

    with pytest.raises(ToolError):
        registry.get_tool("export_annotations").invoke(funcs=["ghost"])


# -- apply tool: boundary parse + counts ------------------------------------


def test_apply_tool_is_mutating_with_write_affinity():
    gateway = _FakeAnnotationGateway()
    executor = _InlineExecutor()
    registry = _register(gateway, _FakeDatabase(), executor)

    spec = registry.get_tool("apply_annotations")
    assert spec.annotations["readOnlyHint"] is False
    # Applying a merged record is not a destructive data loss — no destructiveHint.
    assert "destructiveHint" not in spec.annotations

    spec.invoke(record=annotation_record_to_wire(_record()))
    assert executor.write_flags == [True]


def test_apply_tool_parses_wire_into_the_frozen_domain_shape():
    gateway = _FakeAnnotationGateway()
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())
    wire = annotation_record_to_wire(_record())

    registry.get_tool("apply_annotations").invoke(record=wire)

    assert len(gateway.applied) == 1
    parsed = gateway.applied[0]
    # names/prototypes keyed by int ea; comments keyed by (ea, scope); comment
    # signatures are (regular, repeatable) pairs — exactly what reconcile expects.
    assert parsed.names == {0x1000: "parse_header", 0x2000: "handler"}
    assert parsed.prototypes == {
        0x1000: "void parse_header(void);",
        0x2000: "int handler(int a);",
    }
    assert parsed.comments == {
        (0x1000, "func"): ("does the parse", ""),
        (0x1000, "line"): ("prologue", "rpt note"),
        (0x2000, "line"): ("", "only repeatable"),
    }


def test_apply_tool_projects_applied_counts_and_ok():
    gateway = _FakeAnnotationGateway()  # clean report: counts == record sizes
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())
    wire = annotation_record_to_wire(_record())

    view = registry.get_tool("apply_annotations").invoke(record=wire)

    assert view == {
        "applied": {"names": 2, "comments": 3, "types": 2},
        "ok": True,
        "failures": [],
    }


def test_apply_tool_reports_failures_and_ok_false():
    report = AnnotationApplyReport(
        names=1,
        comments=0,
        types=1,
        failures=("name at 0x2000: refused 'handler'", "comment at 0x1000 (func): no function"),
    )
    gateway = _FakeAnnotationGateway(report=report)
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())
    wire = annotation_record_to_wire(_record())

    view = registry.get_tool("apply_annotations").invoke(record=wire)

    assert view["applied"] == {"names": 1, "comments": 0, "types": 1}
    assert view["ok"] is False
    assert view["failures"] == [
        "name at 0x2000: refused 'handler'",
        "comment at 0x1000 (func): no function",
    ]


def test_apply_tool_gateway_exception_is_toolerror():
    gateway = _FakeAnnotationGateway(raise_on_apply=RuntimeError("db closed"))
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())
    wire = annotation_record_to_wire(_record())

    with pytest.raises(ToolError):
        registry.get_tool("apply_annotations").invoke(record=wire)


def test_apply_tool_tolerates_malformed_entries():
    # A row missing its ``ea`` is skipped at the parse boundary, never fatal.
    wire = {
        "provenance": {"input_path": "x", "input_sha256": None, "imagebase": None, "ida_version": None},
        "names": [{"name": "no_ea"}, {"ea": 0x3000, "name": "kept"}],
        "comments": [],
        "prototypes": [],
    }
    gateway = _FakeAnnotationGateway()
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())

    view = registry.get_tool("apply_annotations").invoke(record=wire)

    assert gateway.applied[0].names == {0x3000: "kept"}
    assert view["applied"]["names"] == 1


# -- view -------------------------------------------------------------------


def test_apply_view_projects_report_to_flat_shape():
    report = AnnotationApplyReport(names=5, comments=7, types=3, failures=("boom",))

    view = apply_view(report)

    assert view == {
        "applied": {"names": 5, "comments": 7, "types": 3},
        "ok": False,
        "failures": ["boom"],
    }


def test_apply_view_ok_true_when_no_failures():
    view = apply_view(AnnotationApplyReport(names=1, comments=0, types=0))

    assert view["ok"] is True
    assert view["failures"] == []


# -- wire round-trip: the two tools compose across the process hop -----------


def test_record_round_trips_export_wire_to_apply_boundary():
    original = _record()

    # export projects the domain record to the wire; apply parses it straight back.
    wire = annotation_record_to_wire(original)
    parsed = annotation_record_from_wire(wire)

    assert parsed.names == original.names
    assert parsed.comments == original.comments
    assert parsed.prototypes == original.prototypes
    # provenance identity fields (the merge safety gate) survive the hop.
    assert parsed.provenance.input_sha256 == original.provenance.input_sha256
    assert parsed.provenance.imagebase == original.provenance.imagebase


def test_export_then_apply_tools_roundtrip_applied_counts():
    # The supervisor's fan-out is export-on-worker → reconcile → apply-on-worker.
    # Here the same wire the export tool emits drives the apply tool; a clean
    # apply lands every field, so the applied counts equal the record's sizes.
    source = _record()
    export_gateway = _FakeAnnotationGateway(record=source)
    export_registry = _register(export_gateway, _FakeDatabase(), _InlineExecutor())
    wire = export_registry.get_tool("export_annotations").invoke()

    apply_gateway = _FakeAnnotationGateway()
    apply_registry = _register(apply_gateway, _FakeDatabase(), _InlineExecutor())
    view = apply_registry.get_tool("apply_annotations").invoke(record=wire)

    assert view["applied"] == {
        "names": len(source.names),
        "comments": len(source.comments),
        "types": len(source.prototypes),
    }
    assert view["ok"] is True
