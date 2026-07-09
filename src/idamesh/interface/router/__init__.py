"""The supervisor router — the single public MCP endpoint's request dispatch.

Presents the worker MCP surface but routes each ``tools/call`` to the owning
worker by an injected ``database`` session id, handling the management tools
(``idb_open`` / ``idb_list`` / ``idb_merge``) locally. Imports no ``idapro`` and no
``infrastructure`` (it depends on the ports in :mod:`.ports`, wired by bootstrap).
"""

from __future__ import annotations

from idamesh.interface.router.management import (
    MANAGEMENT_TOOL_NAMES,
    inject_database_arg,
    management_tool_objects,
)
from idamesh.interface.router.merge import (
    MergeError,
    MergeOrchestrator,
    MergeRequest,
)
from idamesh.interface.router.ports import (
    SessionView,
    WorkerClientPort,
    WorkerPoolPort,
)
from idamesh.interface.router.supervisor import SupervisorRouter

__all__ = [
    "SupervisorRouter",
    "SessionView",
    "WorkerPoolPort",
    "WorkerClientPort",
    "MANAGEMENT_TOOL_NAMES",
    "management_tool_objects",
    "inject_database_arg",
    "MergeOrchestrator",
    "MergeRequest",
    "MergeError",
]
