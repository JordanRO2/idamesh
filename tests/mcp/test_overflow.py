"""Unit tests for the content-addressed overflow store and its preview shrinker."""

from __future__ import annotations

from idamesh.interface.mcp.overflow import OVERFLOW_URI_PREFIX, OverflowStore


def test_put_get_roundtrip_and_content_dedup():
    store = OverflowStore()
    ref1 = store.put({"a": 1, "b": [1, 2, 3]})
    # Same content, different key order -> same content hash (canonical JSON).
    ref2 = store.put({"b": [1, 2, 3], "a": 1})
    assert ref1.sha == ref2.sha
    assert ref1.uri == OVERFLOW_URI_PREFIX + ref1.sha
    assert store.get(ref1.sha) == {"a": 1, "b": [1, 2, 3]}
    assert store.resolve_uri(ref1.uri) == {"a": 1, "b": [1, 2, 3]}


def test_lru_evicts_oldest():
    store = OverflowStore(max_entries=2)
    r1 = store.put({"n": 1})
    r2 = store.put({"n": 2})
    r3 = store.put({"n": 3})
    assert store.get(r1.sha) is None  # evicted
    assert store.get(r2.sha) == {"n": 2}
    assert store.get(r3.sha) == {"n": 3}


def test_get_refreshes_lru_recency():
    store = OverflowStore(max_entries=2)
    r1 = store.put({"n": 1})
    r2 = store.put({"n": 2})
    store.get(r1.sha)  # touch r1 so r2 becomes least-recent
    r3 = store.put({"n": 3})
    assert store.get(r2.sha) is None
    assert store.get(r1.sha) == {"n": 1}
    assert store.get(r3.sha) == {"n": 3}


def test_make_preview_clips_strings_and_lists():
    store = OverflowStore()
    payload = {"s": "x" * 5000, "items": list(range(50))}
    preview = store.make_preview(payload, max_string=100, max_items=5)
    assert preview["s"].endswith("(5000 chars)")
    assert preview["s"].startswith("x" * 100)
    assert len(preview["items"]) == 6
    assert preview["items"][-1] == {"_more": 45}


def test_resolve_uri_unknown_and_foreign_scheme():
    store = OverflowStore()
    assert store.resolve_uri(OVERFLOW_URI_PREFIX + "0" * 64) is None
    assert store.resolve_uri("https://example/whatever") is None
