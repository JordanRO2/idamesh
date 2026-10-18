"""idb_open spawns a worker and a private copy, so it is not advertised read-only."""

from __future__ import annotations

from idamesh.interface.router.management import management_tool_objects


def test_idb_open_is_not_read_only():
    tools = {t["name"]: t for t in management_tool_objects()}
    assert tools["idb_open"]["annotations"]["readOnlyHint"] is False
    assert tools["idb_list"]["annotations"]["readOnlyHint"] is True
