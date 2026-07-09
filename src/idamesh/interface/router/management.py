"""Management-tool contracts and worker-schema shaping for the supervisor.

The supervisor handles four *management* tools itself instead of routing them:
``idb_open`` (open a database, N-copies), ``idb_list`` (enumerate sessions),
``idb_close`` (release a session + reap its worker), and ``idb_merge`` (reconcile
parallel edits). This module owns their frozen
JSON-Schema contracts and the transform that turns a worker's
tool schema into the supervisor's proxied version (an optional ``database``
routing key injected). It is pure data + dict-shaping — no pool, no network — so
it is trivially unit-testable.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Mapping

#: The injected routing key every proxied worker tool gains.
DATABASE_ARG = "database"
_DATABASE_PROPERTY: Dict[str, Any] = {
    "type": "string",
    "description": (
        "Session id from idb_open identifying which open database to act on; "
        "list them with idb_list. Optional — with exactly one database open it "
        "defaults to that one."
    ),
}

#: Names the supervisor answers locally and filters out of the worker catalog.
IDB_OPEN = "idb_open"
IDB_LIST = "idb_list"
IDB_CLOSE = "idb_close"
IDB_MERGE = "idb_merge"
MANAGEMENT_TOOL_NAMES = frozenset({IDB_OPEN, IDB_LIST, IDB_CLOSE, IDB_MERGE})

#: Result-shape descriptor for one session, shared by idb_open/idb_list schemas.
_SESSION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "session_id": {"type": "string"},
        "input_path": {"type": "string"},
        "filename": {"type": "string"},
        "private_copy_path": {"type": "string"},
        "backend": {"type": "string"},
        "host": {"type": "string"},
        "port": {"type": "integer"},
        "created_at": {"type": "string"},
        "last_accessed": {"type": "string"},
    },
    "required": ["session_id", "input_path", "filename"],
    "additionalProperties": True,
}


#: Management tools that mutate server state (not read-only): they open, close,
#: or reconcile databases rather than merely reporting on them.
_WRITE_TOOL_NAMES = frozenset({IDB_CLOSE, IDB_MERGE})


def _tool(name: str, description: str, input_schema: Dict[str, Any],
          output_schema: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "outputSchema": output_schema,
        "annotations": {"readOnlyHint": name not in _WRITE_TOOL_NAMES},
    }


def management_tool_objects() -> List[Dict[str, Any]]:
    """The ``tools/list`` entries for the management tools (schemas + metadata)."""
    idb_open = _tool(
        IDB_OPEN,
        "Open a target binary or IDA database and return its session. Each open "
        "with no preferred_session_id mints a fresh worker over a private copy, so "
        "opening the same binary twice yields two independent sessions.",
        {
            "type": "object",
            "properties": {
                "input_path": {
                    "type": "string",
                    "description": "Filesystem path to the binary or IDA database to open.",
                },
                "preferred_session_id": {
                    "type": "string",
                    "description": (
                        "Attach to this existing session instead of opening a new "
                        "private copy; empty or absent always opens a fresh one."
                    ),
                },
            },
            "required": ["input_path"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                **_SESSION_SCHEMA["properties"],
                "shared": {
                    "type": "boolean",
                    "description": "True when an existing session was reused, not spawned.",
                },
            },
            "required": ["session_id", "input_path", "filename", "shared"],
            "additionalProperties": True,
        },
    )
    idb_list = _tool(
        IDB_LIST,
        "List the databases currently open behind this endpoint.",
        {"type": "object", "properties": {}, "additionalProperties": False},
        {
            "type": "object",
            "properties": {
                "sessions": {"type": "array", "items": _SESSION_SCHEMA},
                "count": {"type": "integer"},
            },
            "required": ["sessions", "count"],
            "additionalProperties": False,
        },
    )
    idb_close = _tool(
        IDB_CLOSE,
        "Close an open database and release its worker. Terminates the headless "
        "worker process backing the session and removes its private working copy, "
        "freeing a slot against the concurrency cap. Call this when done with a "
        "session opened by idb_open.",
        {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": (
                        "Session id from idb_open identifying the database to close; "
                        "list open ones with idb_list."
                    ),
                },
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "closed": {
                    "type": "boolean",
                    "description": (
                        "True when a live session was found and released; false "
                        "when no session matched the id (already closed/unknown)."
                    ),
                },
            },
            "required": ["session_id", "closed"],
            "additionalProperties": False,
        },
    )
    idb_merge = _tool(
        IDB_MERGE,
        "Reconcile the user annotations from parallel copies of one binary into a "
        "single canonical database. Exports each copy's names/comments/prototypes, "
        "subtracts each copy's own pristine baseline (captured in-process at "
        "idb_open, before any edit) so only genuine human edits remain, resolves "
        "same-address conflicts under the chosen policy, then "
        "(unless dry_run) applies the merged annotations into a target session and "
        "writes a compressed .i64 snapshot. Under the default 'manual' policy an "
        "unresolved conflict aborts the write with a report to review.",
        {
            "type": "object",
            "properties": {
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Explicit session ids to merge (from idb_open/idb_list). "
                        "When given, these win over 'path' enumeration."
                    ),
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Binary path whose every open copy is enumerated as a merge "
                        "source; used when 'sources' is omitted."
                    ),
                },
                "into": {
                    "type": "string",
                    "description": (
                        "Session id to apply the merged annotations into; defaults "
                        "to the first resolved source."
                    ),
                },
                "policy": {
                    "type": "string",
                    "enum": ["manual", "first", "last", "prefer"],
                    "description": (
                        "Same-address conflict policy: 'manual' leaves conflicts "
                        "unresolved (and refuses the write), 'first'/'last' take the "
                        "earliest/latest contributor, 'prefer' takes 'prefer''s value."
                    ),
                },
                "prefer": {
                    "type": "string",
                    "description": "Session id whose value wins under policy='prefer'.",
                },
                "fields": {
                    "type": "array",
                    "items": {"enum": ["names", "comments", "prototypes"]},
                    "description": (
                        "Restrict reconciliation to a subset of the annotation "
                        "fields; omit for all three."
                    ),
                },
                "dry_run": {
                    "type": "boolean",
                    "description": (
                        "Report the merge plan and conflicts without writing "
                        "anything (the review gate)."
                    ),
                },
                "use_baseline": {
                    "type": "boolean",
                    "description": (
                        "Subtract each source session's own pristine baseline "
                        "(captured in-process at idb_open, before any edit) so "
                        "unedited auto-analysis names are not treated as edits "
                        "(default true)."
                    ),
                },
            },
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"},
                "dry_run": {"type": "boolean"},
                "into": {"type": "string"},
                "sessions": {"type": "array", "items": {"type": "string"}},
                "reachable": {"type": "array", "items": {"type": "string"}},
                "unreachable": {"type": "array", "items": {"type": "string"}},
                "baseline_sessions": {"type": "array", "items": {"type": "string"}},
                "baseline_missing": {"type": "array", "items": {"type": "string"}},
                "merged_counts": {"type": "object", "additionalProperties": True},
                "conflicts": {"type": "array", "items": {"type": "object"}},
                "applied": {"type": "object", "additionalProperties": True},
                "snapshot": {"type": "object", "additionalProperties": True},
                "error": {"type": "string"},
            },
            "additionalProperties": True,
        },
    )
    return [idb_open, idb_list, idb_close, idb_merge]


def inject_database_arg(tool_object: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a copy of a worker tool object with the optional ``database`` routing
    key injected into its input schema.

    The key is added to ``properties`` (so the schema's ``additionalProperties:
    false`` still admits it) but deliberately **not** to ``required`` — a
    single-session client can omit it.
    """
    proxied = copy.deepcopy(dict(tool_object))
    schema = proxied.get("inputSchema")
    if not isinstance(schema, dict):
        schema = {"type": "object", "properties": {}, "additionalProperties": False}
    properties = dict(schema.get("properties") or {})
    properties.setdefault(DATABASE_ARG, dict(_DATABASE_PROPERTY))
    schema["properties"] = properties
    proxied["inputSchema"] = schema
    return proxied
