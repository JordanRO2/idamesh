"""Unit tests for ``Registry`` registration invariants."""

from __future__ import annotations

import pytest

from idamesh.interface.mcp.registry import Registry


def test_tool_name_charset_accepts_valid_names():
    reg = Registry()

    @reg.tool(name="get_metadata")
    def a() -> dict:
        """ok"""
        return {}

    @reg.tool(name="ida.func-list_2")
    def b() -> dict:
        """ok"""
        return {}

    assert {"get_metadata", "ida.func-list_2"} <= set(reg.tools())


def test_tool_name_defaults_to_function_name():
    reg = Registry()

    @reg.tool
    def list_funcs() -> dict:
        """ok"""
        return {}

    assert "list_funcs" in reg.tools()


@pytest.mark.parametrize(
    "bad",
    [
        "bad name",  # space
        "a,b",  # comma
        "has/slash",  # slash
        "spür",  # non-ASCII
        "x" * 129,  # too long
    ],
)
def test_tool_name_charset_rejects_invalid_names(bad):
    reg = Registry()
    with pytest.raises(ValueError):
        reg.tool(name=bad)(lambda: {})
