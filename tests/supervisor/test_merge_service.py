"""Unit tests for the pure annotation merge-back reconciliation service.

These exercise :func:`idamesh.domain.services.reconciliation.reconcile` and its
helpers with no IDA and no processes — the whole point of keeping the merge in the
domain. Coverage: baseline subtraction, the no-op merge of agreeing/identical
records, a genuine same-EA conflict under each :class:`ConflictPolicy`, the
``dry_run`` report shape, the provenance safety gate, field selection, empty-
signature handling, comment/prototype fields, and ``plan_to_record`` round-trip.
"""

from __future__ import annotations

import pytest

from idamesh.domain.services.reconciliation import (
    AnnotationRecord,
    Conflict,
    ConflictPolicy,
    MergePlan,
    Provenance,
    ProvenanceMismatch,
    dry_run_report,
    plan_to_record,
    reconcile,
)

SHA = "a" * 64


# -- fixtures / builders ---------------------------------------------------- #


def _prov(**overrides):
    base = dict(input_path="/scratch/copy/target.exe", input_sha256=SHA, imagebase=0x400000)
    base.update(overrides)
    return Provenance(**base)


def _record(*, names=None, comments=None, prototypes=None, prov=None):
    return AnnotationRecord(
        provenance=prov if prov is not None else _prov(),
        names=dict(names or {}),
        comments=dict(comments or {}),
        prototypes=dict(prototypes or {}),
    )


# -- baseline subtraction --------------------------------------------------- #


def test_baseline_subtraction_drops_unedited_autoanalysis_names():
    # Both copies still report the loader/auto-analysis name at 0x401000, which is
    # identical to the pristine baseline: it must NOT be treated as a user edit.
    baseline = _record(names={0x401000: "sub_401000", 0x402000: "start"})
    a = _record(names={0x401000: "sub_401000", 0x402000: "start", 0x403000: "parse_hdr"})
    b = _record(names={0x401000: "sub_401000", 0x402000: "start"})

    plan = reconcile([("A", a), ("B", b)], baseline=baseline)

    # Only the genuinely new name survives; agreeing baseline names are subtracted.
    assert plan.names == {0x403000: "parse_hdr"}
    assert plan.conflicts == ()


def test_baseline_subtraction_keeps_names_that_diverge_from_baseline():
    baseline = _record(names={0x401000: "sub_401000"})
    a = _record(names={0x401000: "decode_frame"})  # user renamed away from baseline

    plan = reconcile([("A", a)], baseline=baseline)

    assert plan.names == {0x401000: "decode_frame"}
    assert plan.conflicts == ()


def test_records_identical_to_baseline_merge_to_empty_plan():
    baseline = _record(
        names={0x401000: "sub_401000"},
        comments={(0x401010, "line"): ("auto", "")},
    )
    a = _record(
        names={0x401000: "sub_401000"},
        comments={(0x401010, "line"): ("auto", "")},
    )
    b = _record(names={0x401000: "sub_401000"})

    plan = reconcile([("A", a), ("B", b)], baseline=baseline)

    assert plan.names == {}
    assert plan.comments == {}
    assert plan.prototypes == {}
    assert plan.conflicts == ()
    assert plan.counts == {"names": 0, "comments": 0, "prototypes": 0, "conflicts": 0}


# -- no-op / agreement merges ----------------------------------------------- #


def test_identical_records_agree_without_conflict():
    a = _record(names={0x401000: "parse_header"})
    b = _record(names={0x401000: "parse_header"})

    plan = reconcile([("A", a), ("B", b)])

    assert plan.names == {0x401000: "parse_header"}
    assert plan.conflicts == ()
    assert plan.counts["names"] == 1
    assert plan.counts["conflicts"] == 0


def test_singleton_annotation_auto_resolves():
    # Only one session names the EA — a lone contributor is not a conflict.
    a = _record(names={0x401000: "only_a"})
    b = _record(names={})

    plan = reconcile([("A", a), ("B", b)])

    assert plan.names == {0x401000: "only_a"}
    assert plan.conflicts == ()


def test_disjoint_edits_are_unioned():
    a = _record(names={0x401000: "fn_a"})
    b = _record(names={0x402000: "fn_b"})

    plan = reconcile([("A", a), ("B", b)])

    assert plan.names == {0x401000: "fn_a", 0x402000: "fn_b"}
    assert plan.conflicts == ()


# -- genuine same-EA conflict under each policy ----------------------------- #


def _conflicting_pair():
    a = _record(names={0x401000: "from_a"})
    b = _record(names={0x401000: "from_b"})
    return [("A", a), ("B", b)]


def test_conflict_manual_leaves_unresolved_and_unwritten():
    plan = reconcile(_conflicting_pair(), policy=ConflictPolicy.MANUAL)

    assert plan.names == {}  # nothing written under manual
    assert len(plan.conflicts) == 1
    conflict = plan.conflicts[0]
    assert isinstance(conflict, Conflict)
    assert conflict.field == "names"
    assert conflict.key == 0x401000
    assert conflict.candidates == {"A": "from_a", "B": "from_b"}
    assert conflict.resolved is None


def test_conflict_first_takes_earliest_contributor():
    plan = reconcile(_conflicting_pair(), policy=ConflictPolicy.FIRST)

    assert plan.names == {0x401000: "from_a"}
    assert plan.conflicts[0].resolved == "from_a"
    assert plan.conflicts[0].candidates == {"A": "from_a", "B": "from_b"}


def test_conflict_last_takes_latest_contributor():
    plan = reconcile(_conflicting_pair(), policy=ConflictPolicy.LAST)

    assert plan.names == {0x401000: "from_b"}
    assert plan.conflicts[0].resolved == "from_b"


def test_conflict_first_last_follow_sequence_order_not_key_order():
    # Reverse the input order: FIRST/LAST track the given sequence, not the sid.
    a = _record(names={0x401000: "from_a"})
    b = _record(names={0x401000: "from_b"})

    first = reconcile([("B", b), ("A", a)], policy=ConflictPolicy.FIRST)
    last = reconcile([("B", b), ("A", a)], policy=ConflictPolicy.LAST)

    assert first.names == {0x401000: "from_b"}
    assert last.names == {0x401000: "from_a"}


def test_conflict_prefer_takes_preferred_sessions_value():
    plan = reconcile(_conflicting_pair(), policy=ConflictPolicy.PREFER, prefer="B")

    assert plan.names == {0x401000: "from_b"}
    assert plan.conflicts[0].resolved == "from_b"


def test_conflict_prefer_without_contribution_stays_unresolved():
    # 'C' never contributed a value at the divergent key → unresolved.
    plan = reconcile(_conflicting_pair(), policy=ConflictPolicy.PREFER, prefer="C")

    assert plan.names == {}
    assert plan.conflicts[0].resolved is None


def test_three_way_agreement_of_edits_is_not_a_conflict():
    a = _record(names={0x401000: "same"})
    b = _record(names={0x401000: "same"})
    c = _record(names={0x401000: "same"})

    plan = reconcile([("A", a), ("B", b), ("C", c)], policy=ConflictPolicy.MANUAL)

    assert plan.names == {0x401000: "same"}
    assert plan.conflicts == ()


# -- comments (regular/repeatable tuple signature) -------------------------- #


def test_comment_tuple_agreement_and_conflict():
    a = _record(comments={(0x401000, "func"): ("does X", "")})
    b = _record(comments={(0x401000, "func"): ("does Y", "")})

    agree = reconcile(
        [("A", a), ("A2", _record(comments={(0x401000, "func"): ("does X", "")}))]
    )
    assert agree.comments == {(0x401000, "func"): ("does X", "")}
    assert agree.conflicts == ()

    clash = reconcile([("A", a), ("B", b)], policy=ConflictPolicy.LAST)
    assert clash.comments == {(0x401000, "func"): ("does Y", "")}
    assert clash.conflicts[0].field == "comments"
    assert clash.conflicts[0].key == (0x401000, "func")
    assert clash.conflicts[0].resolved == ("does Y", "")


def test_repeatable_comment_difference_is_a_conflict():
    # Same regular comment, different repeatable half → the whole tuple diverges.
    a = _record(comments={(0x401000, "line"): ("note", "rep-a")})
    b = _record(comments={(0x401000, "line"): ("note", "rep-b")})

    plan = reconcile([("A", a), ("B", b)], policy=ConflictPolicy.MANUAL)

    assert plan.comments == {}
    assert plan.conflicts[0].candidates == {
        "A": ("note", "rep-a"),
        "B": ("note", "rep-b"),
    }


# -- prototypes ------------------------------------------------------------- #


def test_prototype_conflict_resolution():
    a = _record(prototypes={0x401000: "int f(int)"})
    b = _record(prototypes={0x401000: "int f(char *)"})

    plan = reconcile([("A", a), ("B", b)], policy=ConflictPolicy.FIRST)

    assert plan.prototypes == {0x401000: "int f(int)"}
    assert plan.conflicts[0].field == "prototypes"


# -- empty signatures ------------------------------------------------------- #


def test_empty_signatures_are_ignored():
    a = _record(
        names={0x401000: "", 0x402000: "real"},
        comments={(0x401000, "line"): ("", ""), (0x402000, "line"): (None, None)},
    )
    b = _record(names={0x401000: None})

    plan = reconcile([("A", a), ("B", b)])

    assert plan.names == {0x402000: "real"}
    assert plan.comments == {}
    assert plan.conflicts == ()


# -- field selection -------------------------------------------------------- #


def test_fields_subset_restricts_reconciliation():
    a = _record(names={0x401000: "n"}, comments={(0x401000, "line"): ("c", "")})

    only_names = reconcile([("A", a)], fields=["names"])
    assert only_names.names == {0x401000: "n"}
    assert only_names.comments == {}

    nothing = reconcile([("A", a)], fields=[])
    assert nothing.names == {} and nothing.comments == {} and nothing.prototypes == {}


def test_unknown_field_raises_value_error():
    a = _record(names={0x401000: "n"})
    with pytest.raises(ValueError):
        reconcile([("A", a)], fields=["names", "bogus"])


# -- provenance gate -------------------------------------------------------- #


def test_provenance_mismatch_on_sha256_is_refused():
    a = _record(names={0x401000: "a"}, prov=_prov(input_sha256="a" * 64))
    b = _record(names={0x401000: "b"}, prov=_prov(input_sha256="b" * 64))

    with pytest.raises(ProvenanceMismatch):
        reconcile([("A", a), ("B", b)])


def test_provenance_mismatch_on_imagebase_is_refused():
    a = _record(names={0x401000: "a"}, prov=_prov(imagebase=0x400000))
    b = _record(names={0x401000: "b"}, prov=_prov(imagebase=0x140000000))

    with pytest.raises(ProvenanceMismatch):
        reconcile([("A", a), ("B", b)])


def test_provenance_none_values_do_not_trip_the_gate():
    a = _record(names={0x401000: "a"}, prov=_prov(input_sha256=None, imagebase=None))
    b = _record(names={0x402000: "b"}, prov=_prov(input_sha256=SHA, imagebase=0x400000))

    plan = reconcile([("A", a), ("B", b)])  # must not raise
    assert plan.names == {0x401000: "a", 0x402000: "b"}


def test_baseline_provenance_is_gated_too():
    baseline = _record(names={}, prov=_prov(input_sha256="c" * 64))
    a = _record(names={0x401000: "a"})

    with pytest.raises(ProvenanceMismatch):
        reconcile([("A", a)], baseline=baseline)


# -- dry_run report shape --------------------------------------------------- #


def test_dry_run_report_shape():
    a = _record(
        names={0x401000: "from_a", 0x402000: "shared"},
        comments={(0x403000, "func"): ("ca", "")},
    )
    b = _record(
        names={0x401000: "from_b", 0x402000: "shared"},
        comments={(0x403000, "func"): ("cb", "")},
    )

    plan = reconcile([("A", a), ("B", b)], policy=ConflictPolicy.MANUAL)
    report = dry_run_report(plan)

    assert set(report) == {"merged_counts", "conflicts"}
    assert report["merged_counts"] == {
        "names": 1,  # the agreeing "shared" name
        "comments": 0,
        "prototypes": 0,
        "conflicts": 2,
    }

    # Deterministic ordering: names conflict before the comments conflict.
    fields = [c["field"] for c in report["conflicts"]]
    assert fields == ["names", "comments"]

    name_conflict = report["conflicts"][0]
    assert set(name_conflict) == {"field", "key", "ea", "candidates", "resolved"}
    assert name_conflict["key"] == 0x401000
    assert name_conflict["ea"] == 0x401000
    assert name_conflict["candidates"] == {"A": "from_a", "B": "from_b"}
    assert name_conflict["resolved"] is None

    comment_conflict = report["conflicts"][1]
    assert comment_conflict["key"] == (0x403000, "func")
    assert comment_conflict["ea"] == 0x403000  # ea derived from a tuple key's head


def test_dry_run_report_resolved_value_reflects_policy():
    plan = reconcile(_conflicting_pair(), policy=ConflictPolicy.LAST)
    report = dry_run_report(plan)

    assert report["merged_counts"]["conflicts"] == 1
    assert report["conflicts"][0]["resolved"] == "from_b"


# -- plan_to_record --------------------------------------------------------- #


def test_plan_to_record_round_trip():
    a = _record(
        names={0x401000: "fn"},
        comments={(0x402000, "line"): ("c", "")},
        prototypes={0x401000: "void fn(void)"},
    )
    b = _record(names={0x403000: "other"})

    plan = reconcile([("A", a), ("B", b)])
    target_prov = _prov(input_path="/merge/target.i64")
    merged = plan_to_record(plan, target_prov)

    assert isinstance(merged, AnnotationRecord)
    assert merged.provenance is target_prov
    assert merged.names == {0x401000: "fn", 0x403000: "other"}
    assert merged.comments == {(0x402000, "line"): ("c", "")}
    assert merged.prototypes == {0x401000: "void fn(void)"}


def test_plan_to_record_default_provenance_is_placeholder():
    merged = plan_to_record(MergePlan(names={0x401000: "fn"}))

    assert merged.provenance.input_path == ""
    assert merged.names == {0x401000: "fn"}


def test_plan_to_record_omits_unresolved_conflicts():
    plan = reconcile(_conflicting_pair(), policy=ConflictPolicy.MANUAL)
    merged = plan_to_record(plan)

    assert merged.names == {}  # the unresolved divergence is not applyable


# -- determinism ------------------------------------------------------------ #


def test_reconcile_is_order_independent_for_the_plan_maps():
    a = _record(names={0x402000: "b", 0x401000: "a"})
    b = _record(names={0x403000: "c"})

    left = reconcile([("A", a), ("B", b)])
    right = reconcile([("B", b), ("A", a)])

    assert list(left.names.items()) == [(0x401000, "a"), (0x402000, "b"), (0x403000, "c")]
    assert list(left.names.items()) == list(right.names.items())


def test_empty_input_yields_empty_plan():
    plan = reconcile([])

    assert plan.names == {} and plan.comments == {} and plan.prototypes == {}
    assert plan.conflicts == ()
