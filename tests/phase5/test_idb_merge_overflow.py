"""Regression tests: a merge must never consume a truncated export.

The worker's output guard spills any structured result over its char budget to an
overflow store and returns a **ten-item preview** plus an ``mcpref://overflow/<sha>``
reference under ``_meta``. A whole-database ``export_annotations`` exceeds that
budget by orders of magnitude on any real binary, so an orchestrator that consumes
``structuredContent`` verbatim merges ten annotations and reports success — the
worst possible outcome for a consolidation step, and invisible because the guard
does not set ``isError``.

Observed on a real 96k-function database before the fix::

    "names":    [ ...10 entries..., {"_more": 23318} ]
    "comments": [ ...10 entries..., {"_more": 148156} ]

and a merge of 50 genuine renames reported ``{"names": 0, "conflicts": 0}`` —
zero, because the baseline export was truncated to the *same* ten entries and
subtracting a set from itself yields nothing.

Locked in here:

* an overflowed export is fetched back in full via ``resources/read`` and every
  annotation survives the merge;
* an overflow reference that cannot be read refuses the merge instead of
  proceeding on the preview;
* the merged record is applied in batches small enough for the transport's body
  cap, with the per-batch counts summed;
* an unknown source id (an adopted/GUI instance among them) is rejected rather
  than silently dropped from the merge.

The existing fakes are reused from :mod:`tests.phase5.test_idb_merge`; only the
overflow behaviour is new.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional

from idamesh.interface.mcp.middleware import OVERFLOW_META_KEY
from idamesh.interface.mcp.overflow import OVERFLOW_URI_PREFIX

from tests.phase5.test_idb_merge import (
    APPLY,
    EXPORT,
    SNAPSHOT,
    Env,
    FakeEndpoint,
    _wire,
)

PREVIEW_ITEMS = 10


def _truncated(payload: Mapping[str, Any], uri: str) -> Dict[str, Any]:
    """The shrunk preview the output guard substitutes for an oversized result."""
    preview: Dict[str, Any] = {"provenance": payload.get("provenance")}
    for field in ("names", "comments", "prototypes"):
        items = list(payload.get(field) or [])
        if len(items) > PREVIEW_ITEMS:
            head = items[:PREVIEW_ITEMS]
            head.append({"_more": len(items) - PREVIEW_ITEMS})
            preview[field] = head
        else:
            preview[field] = items
    return preview


class OverflowEndpoint(FakeEndpoint):
    """A worker whose ``export_annotations`` overflows the output guard.

    ``tools/call`` returns the preview plus the ``_meta`` overflow marker (never
    ``isError`` — that is precisely what made the truncation silent), and
    ``resources/read`` hands the parked payload back in full.
    """

    def __init__(self, *, full_export: Mapping[str, Any], readable: bool = True, **kw: Any) -> None:
        super().__init__(export=full_export, **kw)
        self.full_export = dict(full_export)
        self.readable = readable
        self.uri = f"{OVERFLOW_URI_PREFIX}{'d' * 64}"
        self.resource_reads: List[str] = []

    def handle(self, frame: Mapping[str, Any]) -> Dict[str, Any]:
        if frame.get("method") == "resources/read":
            uri = (frame.get("params") or {}).get("uri")
            self.resource_reads.append(uri)
            if not self.readable:
                return {
                    "jsonrpc": "2.0",
                    "id": frame.get("id"),
                    "error": {"code": -32002, "message": "Overflow payload expired"},
                }
            return {
                "jsonrpc": "2.0",
                "id": frame.get("id"),
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(self.full_export),
                        }
                    ]
                },
            }
        params = frame.get("params") or {}
        if params.get("name") == EXPORT:
            self.calls.append(
                {"name": EXPORT, "arguments": dict(params.get("arguments") or {}),
                 "frame": dict(frame)}
            )
            return {
                "jsonrpc": "2.0",
                "id": frame.get("id"),
                "result": {
                    "content": [{"type": "text", "text": "preview"}],
                    "structuredContent": _truncated(self.full_export, self.uri),
                    "isError": False,
                    "_meta": {
                        OVERFLOW_META_KEY: {
                            "truncated": True,
                            "totalChars": 7_000_000,
                            "ref": self.uri,
                        }
                    },
                },
            }
        return super().handle(frame)


def _many_names(count: int, *, start: int = 0x401000) -> Dict[int, str]:
    return {start + 0x10 * i: "user_name_%04d" % i for i in range(count)}


# --------------------------------------------------------------------------- #
# The regression: an overflowed export must be recovered in full
# --------------------------------------------------------------------------- #


def test_overflowed_export_is_read_back_in_full_and_every_edit_survives():
    names = _many_names(40)
    env = Env()
    env.baseline(_wire(names={0x400500: "sub_400500"}))
    endpoint = OverflowEndpoint(
        full_export=_wire(names={0x400500: "sub_400500", **names})
    )
    env.add_source("sess-1", endpoint)

    report = env.orch.merge({"sources": ["sess-1"], "dry_run": True})

    assert "error" not in report, report
    # Without the fix this is PREVIEW_ITEMS-ish (or 0 once the baseline is also
    # truncated); with it, every genuine edit is present.
    assert report["merged_counts"]["names"] == len(names), report["merged_counts"]
    assert endpoint.resource_reads == [endpoint.uri]


def test_overflowed_baseline_and_export_still_isolate_the_real_edits():
    """Both the baseline and the export overflow — the subtraction stays exact."""
    baseline_names = {0x400000 + 0x10 * i: "sub_%06X" % (0x400000 + 0x10 * i)
                      for i in range(30)}
    edits = {0x500000: "decode_frame", 0x500010: "parse_header"}
    env = Env()
    env.baseline(_wire(names=baseline_names))
    endpoint = OverflowEndpoint(full_export=_wire(names={**baseline_names, **edits}))
    env.add_source("sess-1", endpoint)

    report = env.orch.merge({"sources": ["sess-1"], "dry_run": True})

    assert report["merged_counts"]["names"] == len(edits), report["merged_counts"]


def test_unreadable_overflow_refuses_the_merge_instead_of_using_the_preview():
    names = _many_names(40)
    env = Env()
    env.baseline(_wire(names={0x400500: "sub_400500"}))
    env.add_source(
        "sess-1",
        OverflowEndpoint(
            full_export=_wire(names={0x400500: "sub_400500", **names}),
            readable=False,
        ),
    )

    report = env.orch.merge({"sources": ["sess-1"], "dry_run": True})

    # An unrecoverable payload makes the source unreachable rather than silently
    # contributing its ten-item preview.
    assert report.get("unreachable") == ["sess-1"], report
    assert report["merged_counts"]["names"] == 0, report


# --------------------------------------------------------------------------- #
# Apply must be batched to fit the transport's body cap
# --------------------------------------------------------------------------- #


def test_large_record_is_applied_in_batches_and_counts_are_summed():
    from idamesh.interface.router import merge as merge_module

    batch = merge_module._APPLY_BATCH_ITEMS
    total = batch * 2 + 25
    names = _many_names(total)

    env = Env()
    env.baseline(_wire())
    endpoint = FakeEndpoint(
        export=_wire(names=names),
        apply_result={"applied": {"names": 1, "comments": 0, "types": 0},
                      "ok": True, "failures": []},
    )
    env.add_source("sess-1", endpoint)

    report = env.orch.merge({"sources": ["sess-1"]})

    assert "error" not in report, report
    applies = endpoint.calls_named(APPLY)
    assert len(applies) == 3, len(applies)
    for call in applies:
        record = call["arguments"]["record"]
        items = sum(len(record.get(f) or []) for f in ("names", "comments", "prototypes"))
        assert items <= batch, items
        assert record.get("provenance"), "every chunk must carry provenance"
    # Every chunk's worker-reported count is accumulated, not overwritten.
    assert report["applied"]["names"] == len(applies)
    # And the whole record actually went out.
    sent = sum(len(c["arguments"]["record"].get("names") or []) for c in applies)
    assert sent == total, sent


def test_empty_record_still_round_trips_as_a_single_apply():
    env = Env()
    env.baseline(_wire(names={0x401000: "sub_401000"}))
    endpoint = FakeEndpoint(export=_wire(names={0x401000: "sub_401000"}))
    env.add_source("sess-1", endpoint)

    report = env.orch.merge({"sources": ["sess-1"]})

    assert "error" not in report, report
    assert len(endpoint.calls_named(APPLY)) == 1
    assert len(endpoint.calls_named(SNAPSHOT)) == 1


# --------------------------------------------------------------------------- #
# A source that is not a pool worker must be rejected, not dropped
# --------------------------------------------------------------------------- #


def test_unknown_source_id_is_rejected_rather_than_silently_dropped():
    """An adopted/GUI session id lands here: it is not a pool worker.

    Dropping it and merging the remaining sources reports success for a merge that
    silently excluded a contributor.
    """
    env = Env()
    env.baseline(_wire())
    env.add_source("sess-1", FakeEndpoint(export=_wire(names={0x401000: "a"})))

    report = env.orch.merge({"sources": ["sess-1", "gui-idb-d80db6"], "dry_run": True})

    assert "error" in report, report
    assert "gui-idb-d80db6" in report["error"]
    assert "idb_open" in report["error"]
