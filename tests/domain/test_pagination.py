"""Unit tests for the pagination value objects.

Covers ``PageRequest`` construction/normalization/clamping, the opaque
tamper-evident ``Cursor`` (encode/decode round-trip plus corruption and
args-hash mismatch handling), and the passive ``Page`` record.
"""

from __future__ import annotations

import base64

import pytest

from idamesh.domain.values.pagination import (
    DEFAULT_COUNT,
    MAX_COUNT,
    Cursor,
    Page,
    PageRequest,
)


# -- PageRequest.of ---------------------------------------------------------- #


def test_of_applies_defaults_for_none():
    req = PageRequest.of(None, None)
    assert req.offset == 0
    assert req.count == DEFAULT_COUNT


def test_of_keeps_explicit_values():
    req = PageRequest.of(5, 20)
    assert req == PageRequest(offset=5, count=20)


def test_of_clamps_negative_offset_to_zero():
    assert PageRequest.of(-3, 10).offset == 0


def test_of_resets_negative_count_to_default():
    # A negative count is not clamped to zero here — it resets to the default.
    assert PageRequest.of(10, -5).count == DEFAULT_COUNT


def test_default_pagerequest_fields():
    req = PageRequest()
    assert req.offset == 0
    assert req.count == DEFAULT_COUNT


# -- PageRequest.clamp ------------------------------------------------------- #


def test_clamp_bounds_count_to_max():
    clamped = PageRequest(offset=0, count=5000).clamp()
    assert clamped.count == MAX_COUNT
    assert clamped.offset == 0


def test_clamp_is_identity_when_already_within_bounds():
    req = PageRequest(offset=0, count=100)
    assert req.clamp() is req


def test_clamp_honors_custom_maximum():
    assert PageRequest(offset=0, count=100).clamp(50).count == 50


def test_clamp_floors_negative_count_and_offset():
    clamped = PageRequest(offset=-4, count=-3).clamp()
    assert clamped.offset == 0
    assert clamped.count == 0


# -- Cursor round-trip ------------------------------------------------------- #


def test_cursor_encode_decode_round_trip():
    cursor = Cursor(offset=50, args_hash="abc123")
    token = cursor.encode()
    assert isinstance(token, str)
    assert Cursor.decode(token) == cursor


def test_cursor_token_is_opaque_base64():
    token = Cursor(offset=7, args_hash="deadbeef").encode()
    # Round-trips through the urlsafe-base64 alphabet the client treats verbatim.
    assert base64.urlsafe_b64decode(token.encode("ascii"))


def test_cursor_matches_is_hash_equality():
    cursor = Cursor(offset=0, args_hash="h1")
    assert cursor.matches("h1") is True
    assert cursor.matches("h2") is False


def test_cursor_decode_rejects_non_json_payload():
    token = base64.urlsafe_b64encode(b"not-json").decode("ascii")
    with pytest.raises(ValueError):
        Cursor.decode(token)


def test_cursor_decode_rejects_missing_keys():
    token = base64.urlsafe_b64encode(b'{"o":1}').decode("ascii")
    with pytest.raises(ValueError):
        Cursor.decode(token)


def test_cursor_decode_rejects_corrupt_token():
    with pytest.raises(ValueError):
        Cursor.decode("%%%not-base64%%%")


# -- PageRequest.from_cursor ------------------------------------------------- #


def test_from_cursor_round_trips_offset_and_verifies_hash():
    token = Cursor(offset=50, args_hash="args-abc").encode()
    req = PageRequest.from_cursor(token, args_hash="args-abc")
    assert req.offset == 50
    assert req.count == DEFAULT_COUNT


def test_from_cursor_rejects_tampered_args_hash():
    token = Cursor(offset=50, args_hash="args-abc").encode()
    with pytest.raises(ValueError):
        PageRequest.from_cursor(token, args_hash="different-args")


def test_from_cursor_rejects_malformed_token():
    with pytest.raises(ValueError):
        PageRequest.from_cursor("%%%bad%%%", args_hash="whatever")


# -- Page -------------------------------------------------------------------- #


def test_page_defaults():
    page = Page(items=[1, 2, 3], offset=0, count=3)
    assert list(page.items) == [1, 2, 3]
    assert page.offset == 0
    assert page.count == 3
    assert page.total is None
    assert page.truncated is False
    assert page.next_cursor is None


def test_page_carries_truncation_and_continuation_metadata():
    cursor = Cursor(offset=10, args_hash="h").encode()
    page = Page(
        items=("a", "b"),
        offset=0,
        count=2,
        total=42,
        truncated=True,
        next_cursor=cursor,
    )
    assert page.total == 42
    assert page.truncated is True
    assert page.next_cursor == cursor
