"""The supervisor's MCP surface: management tools handled locally, everything
else routed to the owning worker (interface layer, idapro-free).

``SupervisorRouter`` presents the same MCP method set as a worker
(``initialize`` / ``ping`` / ``tools/list`` / ``tools/call`` / ``resources/*``),
but it executes nothing itself except the management tools. It:

* answers ``initialize`` / ``ping`` / ``notifications/*`` locally;
* builds ``tools/list`` from the management tools **plus** every worker tool with
  an optional ``database`` routing key injected — the worker schemas come from an
  in-process, idapro-free tool ``Registry`` handed in by the composition root, so
  no worker is spawned merely to list;
* dispatches ``tools/call``: a management name is handled locally against the
  injected :class:`WorkerPoolPort`; any other name has its ``database`` argument
  popped (defaulting to the sole open session) and the JSON-RPC frame forwarded
  verbatim — minus ``database`` — to that session's worker via the injected
  :class:`WorkerClientPort`, whose response is relayed back.

Like the worker's :class:`~idamesh.interface.mcp.engine.McpEngine`, it exposes its
handlers via :meth:`methods` for the composition root to register on an
``infrastructure.rpc`` ``Router``; it never imports the transport or the process
pool concretely (only their ports), so the layer rule and the idapro-free
guarantee hold structurally.
"""

from __future__ import annotations

import itertools
import threading
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from idamesh.interface.mcp.engine import (
    SUPPORTED_PROTOCOL_VERSIONS,
    ErrorCode,
    McpError,
    ServerInfo,
    ToolError,
)
from idamesh.interface.mcp.registry import Registry
from idamesh.interface.mcp.specs import RequestView, ToolResult, ToolSpec
from idamesh.interface.router.management import (
    IDB_CLOSE,
    IDB_LIST,
    IDB_MERGE,
    IDB_OPEN,
    MANAGEMENT_TOOL_NAMES,
    inject_database_arg,
    management_tool_objects,
)
from idamesh.interface.router.merge import MergeOrchestrator
from idamesh.interface.router.ports import (
    GuiDiscoveryPort,
    SessionView,
    WorkerClientPort,
    WorkerPoolPort,
)


def _text_block(message: str) -> Dict[str, Any]:
    return {"type": "text", "text": message}


def _ok_result(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """A successful management-tool result envelope."""
    import json

    text = json.dumps(dict(payload), ensure_ascii=False)
    return ToolResult(
        content=(_text_block(text),),
        structured_content=dict(payload),
        is_error=False,
    ).to_wire()


def _error_result(message: str) -> Dict[str, Any]:
    """A tool-level failure envelope (``isError: true``), not a protocol error."""
    return ToolResult(content=(_text_block(message),), is_error=True).to_wire()


def _structured_error_result(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """An ``isError`` envelope that still carries a structured report body.

    Used by a *refused* merge (provenance mismatch, or unresolved conflicts under
    ``manual``): the caller gets ``isError: true`` plus the full report — counts,
    conflicts, reachability — in ``structuredContent`` so it can review and rerun.
    """
    import json

    body = dict(payload)
    message = str(body.get("error", "merge refused"))
    return ToolResult(
        content=(_text_block(json.dumps(body, ensure_ascii=False)),),
        structured_content=body,
        is_error=True,
    ).to_wire()


class SupervisorRouter:
    """Routes the MCP surface across a pool of workers behind one endpoint."""

    def __init__(
        self,
        *,
        pool: WorkerPoolPort,
        client: WorkerClientPort,
        worker_registry: Registry,
        server_info: Optional[ServerInfo] = None,
        discovery: Optional[GuiDiscoveryPort] = None,
    ) -> None:
        self._pool = pool
        self._client = client
        self._worker_registry = worker_registry
        self._server_info = server_info or ServerInfo()
        #: Optional reader of instances the supervisor did not spawn (the live GUI
        #: plugin). When wired, its sessions are listed and routable alongside the
        #: owned workers; when ``None`` the supervisor exposes only its own pool.
        self._discovery = discovery
        self._ready_sessions: Set[Optional[str]] = set()
        self._ready_lock = threading.Lock()
        self._inner_ids = itertools.count(1)
        #: The merge-back pipeline; driven only for ``idb_merge``.
        self._merge = MergeOrchestrator(pool=pool, client=client)

    # -- wiring seam ---------------------------------------------------------

    def methods(self) -> Mapping[str, Any]:
        """Method-name -> handler map the composition root registers on a Router."""
        return {
            "initialize": self.initialize,
            "notifications/initialized": self.initialized,
            "ping": self.ping,
            "tools/list": self.tools_list,
            "tools/call": self.tools_call,
            "resources/list": self.resources_list,
            "resources/templates/list": self.resources_templates_list,
            "resources/read": self.resources_read,
        }

    def map_exception(self, exc: BaseException) -> Optional[Tuple[int, str, Any]]:
        """Map a router exception to ``(code, message, data)`` for the Router."""
        if isinstance(exc, McpError):
            return exc.code, exc.message, exc.data
        if isinstance(exc, ToolError):
            return ErrorCode.TOOL, exc.message, exc.data
        return None

    # -- lifecycle -----------------------------------------------------------

    def initialize(self, params: Optional[Mapping[str, Any]], ctx: RequestView) -> dict:
        params = params or {}
        requested = params.get("protocolVersion")
        negotiated = (
            requested
            if requested in SUPPORTED_PROTOCOL_VERSIONS
            else SUPPORTED_PROTOCOL_VERSIONS[0]
        )
        info: Dict[str, Any] = {
            "name": self._server_info.name,
            "version": self._server_info.version,
        }
        if self._server_info.title:
            info["title"] = self._server_info.title
        return {
            "protocolVersion": negotiated,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
            },
            "serverInfo": info,
        }

    def initialized(self, params: Optional[Mapping[str, Any]], ctx: RequestView) -> None:
        with self._ready_lock:
            self._ready_sessions.add(getattr(ctx, "session_id", None))
        return None

    def ping(self, params: Optional[Mapping[str, Any]], ctx: RequestView) -> dict:
        return {}

    def _require_initialized(self, ctx: RequestView) -> None:
        with self._ready_lock:
            ready = getattr(ctx, "session_id", None) in self._ready_sessions
        if not ready:
            raise McpError(
                ErrorCode.INVALID_PARAMS,
                "Session not initialized: complete 'initialize' and send "
                "'notifications/initialized' before other requests",
            )

    # -- tools ---------------------------------------------------------------

    def tools_list(self, params: Optional[Mapping[str, Any]], ctx: RequestView) -> dict:
        """Management tools + every worker tool with ``database`` injected."""
        self._require_initialized(ctx)
        features = getattr(ctx, "features", frozenset()) or frozenset()
        tools: List[Dict[str, Any]] = list(management_tool_objects())
        for spec in sorted(
            self._worker_registry.tools().values(), key=lambda s: s.name
        ):
            if spec.name in MANAGEMENT_TOOL_NAMES:
                continue
            if spec.feature is not None and spec.feature not in features:
                continue
            tools.append(inject_database_arg(self._worker_tool_object(spec)))
        return {"tools": tools}

    def tools_call(self, params: Mapping[str, Any], ctx: RequestView) -> dict:
        """Management → local; anything else → forwarded to the owning session."""
        self._require_initialized(ctx)
        if not isinstance(params, Mapping):
            raise McpError(ErrorCode.INVALID_PARAMS, "params must be an object")
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise McpError(
                ErrorCode.INVALID_PARAMS, "tools/call requires a string 'name'"
            )
        arguments = params.get("arguments")
        args: Dict[str, Any] = dict(arguments) if isinstance(arguments, Mapping) else {}

        if name == IDB_OPEN:
            return self._tool_idb_open(args)
        if name == IDB_LIST:
            return self._tool_idb_list(args)
        if name == IDB_CLOSE:
            return self._tool_idb_close(args)
        if name == IDB_MERGE:
            return self._tool_idb_merge(args)
        return self._forward_tool_call(name, args)

    # -- management handlers -------------------------------------------------

    def _tool_idb_open(self, args: Mapping[str, Any]) -> dict:
        input_path = args.get("input_path")
        if not isinstance(input_path, str) or not input_path:
            return _error_result("idb_open requires a non-empty 'input_path' string")
        preferred = args.get("preferred_session_id") or None
        if preferred is not None and not isinstance(preferred, str):
            return _error_result("'preferred_session_id' must be a string")

        before = {s.session_id for s in self._pool.list_sessions()}
        try:
            session = self._pool.open_session(
                input_path, preferred_session_id=preferred
            )
        except Exception as exc:  # noqa: BLE001 — pool errors are tool-level
            return _error_result(str(exc))
        shared = session.session_id in before
        if not shared:
            # A freshly spawned worker: its initial auto-analysis is complete but no
            # agent has edited yet. Capture its pristine annotation record now, in
            # the same in-process analysis, so idb_merge can subtract exactly this
            # session's own baseline later (deterministic, zero cross-copy variance).
            # A SHARED reuse keeps whatever baseline the original open captured.
            # Idapro-free: this drives the worker's export tool over the client.
            self._merge.capture_pristine_baseline(session)
        info = dict(session.to_info())
        info["shared"] = shared
        return _ok_result(info)

    def _tool_idb_list(self, args: Mapping[str, Any]) -> dict:
        sessions = [dict(s.to_info()) for s in self._all_sessions()]
        return _ok_result({"sessions": sessions, "count": len(sessions)})

    def _tool_idb_merge(self, args: Mapping[str, Any]) -> dict:
        """Reconcile parallel copies' annotations into one canonical database.

        Delegates the whole pipeline to the idapro-free
        :class:`~idamesh.interface.router.merge.MergeOrchestrator` and
        wraps its report payload: a payload carrying an ``error`` key is a *refused*
        or failed merge (``isError`` with the structured report attached), anything
        else is a dry-run or applied success.
        """
        payload = self._merge.merge(args)
        if payload.get("error"):
            return _structured_error_result(payload)
        return _ok_result(payload)

    def _tool_idb_close(self, args: Mapping[str, Any]) -> dict:
        session_id = args.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            return _error_result("idb_close requires a non-empty 'session_id' string")
        try:
            closed = bool(self._pool.close_session(session_id))
        except Exception as exc:  # noqa: BLE001 — pool errors are tool-level
            return _error_result(str(exc))
        return _ok_result({"session_id": session_id, "closed": closed})

    # -- forwarding ----------------------------------------------------------

    def _forward_tool_call(self, name: str, args: Dict[str, Any]) -> dict:
        database = args.pop("database", None)
        if database is not None and not isinstance(database, str):
            raise McpError(ErrorCode.INVALID_PARAMS, "'database' must be a string")
        session = self._resolve_session(database or None)
        session.touch()
        frame = {
            "jsonrpc": "2.0",
            "id": next(self._inner_ids),
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        }
        try:
            response = self._client.forward(
                host=session.host,
                port=session.port,
                frame=frame,
                token=session.token,
            )
        except Exception as exc:  # noqa: BLE001 — transport failure → protocol error
            raise McpError(
                ErrorCode.INTERNAL,
                f"failed forwarding '{name}' to session '{session.session_id}': {exc}",
            ) from exc
        if response is None:
            raise McpError(
                ErrorCode.INTERNAL,
                f"worker for session '{session.session_id}' returned no response",
            )
        error = response.get("error")
        if error is not None:
            raise McpError(
                int(error.get("code", ErrorCode.INTERNAL)),
                str(error.get("message", "worker error")),
                error.get("data"),
            )
        return response.get("result", {})

    def _resolve_session(self, database: Optional[str]) -> SessionView:
        if database:
            session = self._pool.get(database)
            if session is None and self._discovery is not None:
                # Not an owned worker — it may be an adopted GUI (or other
                # discovered instance) addressed by its session id.
                session = self._discovery.get(database)
            if session is None:
                raise McpError(
                    ErrorCode.INVALID_PARAMS,
                    f"unknown database session '{database}'; list open sessions "
                    "with idb_list",
                )
            return session
        sessions = self._all_sessions()
        if len(sessions) == 1:
            return sessions[0]
        if not sessions:
            raise McpError(
                ErrorCode.INVALID_PARAMS,
                "no database is open; call idb_open first",
            )
        raise McpError(
            ErrorCode.INVALID_PARAMS,
            "multiple databases are open; pass database=<session_id> "
            "(list them with idb_list)",
        )

    def _all_sessions(self) -> List[SessionView]:
        """Owned workers plus any adopted discovered instances (owned wins on id).

        The pool's own sessions come first; a discovered instance is appended only
        when its ``session_id`` is not already an owned one, so an instance the
        supervisor both spawned and that also self-registered is never counted
        twice.
        """
        sessions: List[SessionView] = list(self._pool.list_sessions())
        if self._discovery is None:
            return sessions
        seen = {s.session_id for s in sessions}
        for adopted in self._discovery.list_sessions():
            if adopted.session_id not in seen:
                sessions.append(adopted)
                seen.add(adopted.session_id)
        return sessions

    # -- resources -----------------------------------------------------------

    def resources_list(self, params: Optional[Mapping[str, Any]], ctx: RequestView) -> dict:
        """Local resources only. Worker resource proxying is a later phase."""
        self._require_initialized(ctx)
        return {"resources": []}

    def resources_templates_list(
        self, params: Optional[Mapping[str, Any]], ctx: RequestView
    ) -> dict:
        self._require_initialized(ctx)
        return {"resourceTemplates": []}

    def resources_read(self, params: Mapping[str, Any], ctx: RequestView) -> dict:
        """A bare resource read carries no session id, so it cannot be routed.

        Direct the caller to the tool form, which takes ``database=``.
        """
        self._require_initialized(ctx)
        raise McpError(
            ErrorCode.INVALID_PARAMS,
            "resource reads are not routable without a session; call the "
            "equivalent tool with database=<session_id> instead",
        )

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _worker_tool_object(spec: ToolSpec) -> Dict[str, Any]:
        """Render a worker ``ToolSpec`` into a ``tools/list`` entry (pre-injection)."""
        obj: Dict[str, Any] = {
            "name": spec.name,
            "description": spec.description,
            "inputSchema": dict(spec.input_schema),
        }
        if spec.output_schema is not None:
            obj["outputSchema"] = dict(spec.output_schema)
        if spec.annotations:
            obj["annotations"] = dict(spec.annotations)
        return obj
