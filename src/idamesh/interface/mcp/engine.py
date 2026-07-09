"""The MCP protocol engine: the MCP method handlers, minus JSON-RPC framing.

``McpEngine`` implements the *semantics* of every MCP method — ``initialize``
(version negotiation), ``ping``, ``notifications/initialized``, ``tools/list``,
``tools/call``, and the ``resources/*`` reads (including the overflow fetch). It
owns the :class:`~idamesh.interface.mcp.registry.Registry`, the middleware chain,
the overflow store, and the server identity.

Layering note (contract-freeze decision). The mechanical import contract forbids
``interface`` from importing ``infrastructure``. So the engine does **not** own
the JSON-RPC ``Router``, the ``RequestContext``, or the ``CancellationRegistry``
(those live in ``infrastructure/rpc`` per doc 02). Instead the engine exposes its
methods via :meth:`methods`, and the composition root registers them onto a
``Router``. Each handler receives the request context as a
:class:`~idamesh.interface.mcp.specs.RequestView` (which the concrete
``RequestContext`` satisfies structurally) and returns a plain result object; the
Router does framing, error mapping (through :meth:`map_exception`), and
cancellation-token lifecycle. This is the realization of doc 02's
``engine.handle(...) -> bytes | None`` seam, split to honor the layer rule.
"""

from __future__ import annotations

import base64
import collections.abc as cabc
import enum
import json
import re
import threading
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from idamesh.application.policies.limits import Limits
from idamesh.interface.mcp.middleware import (
    CallMiddleware,
    OutputGuardMiddleware,
    build_chain,
)
from idamesh.interface.mcp.overflow import (
    OVERFLOW_URI_PREFIX,
    OverflowStore,
    json_default,
)
from idamesh.interface.mcp.registry import Registry
from idamesh.interface.mcp.schema import CoercionError
from idamesh.interface.mcp.specs import (
    ParamSpec,
    RequestView,
    ResourceSpec,
    ToolResult,
    ToolSpec,
)

#: MCP protocol revisions we can negotiate, newest first.
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)

#: Default cosmetic server identity (distinct from the ``idamesh`` import package).
DEFAULT_SERVER_NAME: str = "idamesh"

#: Tools returned per ``tools/list`` page before an opaque cursor is issued.
TOOLS_PAGE_SIZE: int = 250


class ErrorCode:
    """JSON-RPC / MCP error-code constants (protocol facts) the engine raises with."""

    PARSE = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL = -32603
    RESOURCE_NOT_FOUND = -32002
    CANCELLED = -32800
    TOOL = -32000


class McpError(Exception):
    """A protocol-level failure the Router renders as a JSON-RPC ``error``."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class ToolError(Exception):
    """A tool-execution failure surfaced as an ``isError: true`` *result*."""

    def __init__(self, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.data = data


@dataclass(frozen=True)
class ServerInfo:
    """The ``serverInfo`` advertised at ``initialize``."""

    name: str = DEFAULT_SERVER_NAME
    version: str = "0.0.1"
    title: Optional[str] = None


#: An MCP method handler as registered onto the Router.
MethodHandler = Callable[[Any, RequestView], Any]


def _text_block(message: str) -> dict[str, Any]:
    return {"type": "text", "text": message}


def _jsonify(value: Any) -> Any:
    """Recursively convert a Python value into JSON-native structures."""
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonify(asdict(value))
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, cabc.Mapping):
        return {key: _jsonify(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonify(item) for item in value]
    return value


def _features_of(ctx: RequestView) -> frozenset:
    return getattr(ctx, "features", frozenset()) or frozenset()


def _cancelled(ctx: RequestView) -> bool:
    cancel = getattr(ctx, "cancel", None)
    return bool(cancel is not None and getattr(cancel, "cancelled", False))


class McpEngine:
    """Implements the MCP method set over a :class:`Registry`."""

    def __init__(
        self,
        registry: Registry,
        *,
        server_info: Optional[ServerInfo] = None,
        overflow: Optional[OverflowStore] = None,
        middlewares: Sequence[CallMiddleware] = (),
        limits: Optional[Limits] = None,
    ) -> None:
        self._registry = registry
        self._server_info = server_info or ServerInfo()
        self._overflow = overflow or OverflowStore()
        self._middlewares = tuple(middlewares)
        self._limits = limits or Limits()
        # Lifecycle gate: a session is "ready" only once its
        # ``notifications/initialized`` has been received. Until then every
        # method other than ``initialize`` and ``ping`` is rejected. Keyed by the
        # transport session id (fixed ``"stdio"`` for stdio, the assigned
        # ``Mcp-Session-Id`` for HTTP); guarded because HTTP dispatches on
        # background threads.
        self._ready_sessions: Set[Optional[str]] = set()
        self._ready_lock = threading.Lock()
        # The output guard is always the outermost stage; any injected
        # middlewares (rate-limit, feature-gate) sit inside it, around the
        # terminal invoker.
        output_guard = OutputGuardMiddleware(
            self._overflow, budget_chars=self._limits.output_budget_chars
        )
        self._chain = build_chain(
            [output_guard, *self._middlewares], self._invoke_terminal
        )

    # -- lifecycle -----------------------------------------------------------

    def initialize(self, params: Mapping[str, Any], ctx: RequestView) -> dict:
        """Negotiate the protocol version and advertise capabilities + serverInfo."""
        params = params or {}
        negotiated = self.negotiate_version(params.get("protocolVersion"))
        info: dict[str, Any] = {
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
        """Handle ``notifications/initialized``: open the session's gate (no response)."""
        with self._ready_lock:
            self._ready_sessions.add(self._session_key(ctx))
        return None

    def ping(self, params: Optional[Mapping[str, Any]], ctx: RequestView) -> dict:
        """Reply to ``ping`` with an empty object. Always allowed, even pre-init."""
        return {}

    @staticmethod
    def _session_key(ctx: RequestView) -> Optional[str]:
        return getattr(ctx, "session_id", None)

    def _require_initialized(self, ctx: RequestView) -> None:
        """Reject an operational method until the session has been initialized.

        Per the MCP lifecycle, a client MUST complete ``initialize`` and send
        ``notifications/initialized`` before issuing any other request. Before
        that we answer with an ``INVALID_PARAMS`` protocol error (``initialize``
        and ``ping`` bypass this gate).
        """
        with self._ready_lock:
            ready = self._session_key(ctx) in self._ready_sessions
        if not ready:
            raise McpError(
                ErrorCode.INVALID_PARAMS,
                "Session not initialized: complete 'initialize' and send "
                "'notifications/initialized' before other requests",
            )

    def negotiate_version(self, requested: Optional[str]) -> str:
        """Pick a mutually supported protocol version (keep the client's if we
        support it, else answer with our newest)."""
        if requested in SUPPORTED_PROTOCOL_VERSIONS:
            return requested  # type: ignore[return-value]
        return SUPPORTED_PROTOCOL_VERSIONS[0]

    # -- tools ---------------------------------------------------------------

    def tools_list(self, params: Optional[Mapping[str, Any]], ctx: RequestView) -> dict:
        """List tools visible for ``ctx`` (feature/profile filtered), with opaque
        cursor pagination; returns ``{tools, nextCursor?}``."""
        self._require_initialized(ctx)
        params = params or {}
        features = _features_of(ctx)
        visible = sorted(
            (
                spec
                for spec in self._registry.tools().values()
                if spec.feature is None or spec.feature in features
            ),
            key=lambda spec: spec.name,
        )
        offset = self._decode_cursor(params.get("cursor"))
        page = visible[offset : offset + TOOLS_PAGE_SIZE]
        result: dict[str, Any] = {"tools": [self._tool_object(spec) for spec in page]}
        next_offset = offset + TOOLS_PAGE_SIZE
        if next_offset < len(visible):
            result["nextCursor"] = self._encode_cursor(next_offset)
        return result

    def tools_call(self, params: Mapping[str, Any], ctx: RequestView) -> dict:
        """Resolve the tool, bind arguments, run the middleware chain, and return
        the ``{content, structuredContent, isError}`` envelope. Execution failures
        become ``isError: true`` results, not JSON-RPC errors."""
        self._require_initialized(ctx)
        if not isinstance(params, cabc.Mapping):
            raise McpError(ErrorCode.INVALID_PARAMS, "params must be an object")
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise McpError(
                ErrorCode.INVALID_PARAMS, "tools/call requires a string 'name'"
            )
        spec = self._registry.get_tool(name)
        if spec is None:
            # An unknown tool is a *protocol* error, per the MCP error model.
            raise McpError(ErrorCode.INVALID_PARAMS, f"Unknown tool: {name}")
        if self._is_gated(spec, ctx):
            gated = ToolResult(
                content=(_text_block(f"Tool '{name}' is not enabled for this session."),),
                is_error=True,
            )
            return gated.to_wire()
        result = self._chain(spec, params.get("arguments"), ctx)
        return result.to_wire()

    def bind_args(self, spec: ToolSpec, arguments: Optional[Mapping[str, Any]]) -> dict:
        """Validate/coerce raw arguments against ``spec`` into call kwargs.
        Raises :class:`McpError` (``INVALID_PARAMS``) on a bad argument object."""
        return self._bind(spec.params, spec.name, arguments)

    def shape_result(self, value: Any, *, is_error: bool = False) -> ToolResult:
        """Wrap a tool's Python return into the MCP result envelope."""
        if is_error:
            message = value if isinstance(value, str) else json.dumps(
                _jsonify(value), ensure_ascii=False
            )
            return ToolResult(content=(_text_block(message),), is_error=True)
        jsonable = _jsonify(value)
        structured = jsonable if isinstance(jsonable, dict) else {"result": jsonable}
        text = json.dumps(structured, ensure_ascii=False, default=json_default)
        return ToolResult(
            content=(_text_block(text),),
            structured_content=structured,
            is_error=False,
        )

    # -- resources -----------------------------------------------------------

    def resources_list(self, params: Optional[Mapping[str, Any]], ctx: RequestView) -> dict:
        """List literal resources: ``{resources, nextCursor?}``."""
        self._require_initialized(ctx)
        resources = [
            {
                "uri": spec.uri,
                "name": spec.name,
                "description": spec.description,
                "mimeType": spec.mime_type,
            }
            for spec in self._registry.resources().values()
            if not spec.is_template
        ]
        return {"resources": resources}

    def resources_templates_list(
        self, params: Optional[Mapping[str, Any]], ctx: RequestView
    ) -> dict:
        """List templated resources: ``{resourceTemplates}``."""
        self._require_initialized(ctx)
        templates = [
            {
                "uriTemplate": spec.uri,
                "name": spec.name,
                "description": spec.description,
                "mimeType": spec.mime_type,
            }
            for spec in self._registry.resources().values()
            if spec.is_template
        ]
        return {"resourceTemplates": templates}

    def resources_read(self, params: Mapping[str, Any], ctx: RequestView) -> dict:
        """Read a resource URI (including ``mcpref://overflow/<sha>``): ``{contents}``."""
        self._require_initialized(ctx)
        if not isinstance(params, cabc.Mapping):
            raise McpError(ErrorCode.INVALID_PARAMS, "params must be an object")
        uri = params.get("uri")
        if not isinstance(uri, str):
            raise McpError(
                ErrorCode.INVALID_PARAMS, "resources/read requires a string 'uri'"
            )

        if uri.startswith(OVERFLOW_URI_PREFIX):
            payload = self._overflow.resolve_uri(uri)
            if payload is None:
                raise McpError(
                    ErrorCode.RESOURCE_NOT_FOUND,
                    "Overflow payload expired or not found",
                    {"uri": uri},
                )
            return self._contents(uri, "application/json", payload)

        for spec in self._registry.resources().values():
            bound = _match_resource(spec, uri)
            if bound is None:
                continue
            kwargs = self._bind(spec.params, spec.uri, bound)
            # A resource handler surfaces a bad target (unresolvable address,
            # unknown type, unreadable region) as a ``ToolError`` — the same
            # convention the tool catalog uses. For a resource read there is no
            # ``isError`` envelope, so it is mapped to a ``resources/read``
            # protocol error (resource-not-found) rather than propagating as a
            # generic tool fault.
            try:
                value = spec.invoke(**kwargs)
            except ToolError as exc:
                raise McpError(
                    ErrorCode.RESOURCE_NOT_FOUND, exc.message, {"uri": uri}
                ) from exc
            return self._contents(uri, spec.mime_type, value)

        known = sorted(self._registry.resources())
        raise McpError(
            ErrorCode.RESOURCE_NOT_FOUND,
            "Resource not found",
            {"uri": uri, "known": known},
        )

    # -- wiring seam ---------------------------------------------------------

    def methods(self) -> Mapping[str, MethodHandler]:
        """Method-name -> handler map the composition root registers on the Router.

        Keys are the MCP method names (``"initialize"``, ``"ping"``,
        ``"notifications/initialized"``, ``"tools/list"``, ``"tools/call"``,
        ``"resources/list"``, ``"resources/templates/list"``, ``"resources/read"``).
        """
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
        """Map an engine exception to ``(code, message, data)`` for the Router,
        or ``None`` to defer to the Router's default internal-error mapping."""
        if isinstance(exc, McpError):
            return exc.code, exc.message, exc.data
        if isinstance(exc, ToolError):
            return ErrorCode.TOOL, exc.message, exc.data
        return None

    # -- internals -----------------------------------------------------------

    def _invoke_terminal(
        self, spec: ToolSpec, arguments: Any, ctx: RequestView
    ) -> ToolResult:
        """The innermost stage: bind arguments, call the tool, shape the result.

        Argument-binding failures raise :class:`McpError` (a protocol error). A
        ``ToolError`` — or a cooperative cancellation mid-call — becomes an
        ``isError`` result; anything else propagates for the Router to map.
        """
        kwargs = self.bind_args(spec, arguments)
        try:
            value = spec.invoke(**kwargs)
        except ToolError as exc:
            return self.shape_result(exc.message, is_error=True)
        except McpError:
            raise
        except Exception:
            if _cancelled(ctx):
                return self.shape_result("Request cancelled", is_error=True)
            raise
        return self.shape_result(value, is_error=False)

    def _is_gated(self, spec: ToolSpec, ctx: RequestView) -> bool:
        # Authoritative feature-group gate (mirrored by FeatureGateMiddleware,
        # which is only wired when profile filtering is also wanted).
        if spec.feature is None:
            return False
        return spec.feature not in _features_of(ctx)

    def _tool_object(self, spec: ToolSpec) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "name": spec.name,
            "description": spec.description,
            "inputSchema": dict(spec.input_schema),
        }
        if spec.output_schema is not None:
            obj["outputSchema"] = dict(spec.output_schema)
        if spec.annotations:
            obj["annotations"] = dict(spec.annotations)
        return obj

    def _bind(
        self,
        params: Sequence[ParamSpec],
        owner: str,
        arguments: Any,
    ) -> dict:
        if arguments is None:
            provided: Dict[str, Any] = {}
        elif isinstance(arguments, cabc.Mapping):
            provided = dict(arguments)
        elif isinstance(arguments, (list, tuple)):
            if len(arguments) > len(params):
                raise McpError(
                    ErrorCode.INVALID_PARAMS,
                    f"too many positional arguments for '{owner}'",
                )
            provided = {p.name: v for p, v in zip(params, arguments)}
        else:
            raise McpError(
                ErrorCode.INVALID_PARAMS, "arguments must be an object or array"
            )

        by_name = {p.name: p for p in params}
        unknown = set(provided) - set(by_name)
        if unknown:
            raise McpError(
                ErrorCode.INVALID_PARAMS,
                f"unknown arguments for '{owner}': {sorted(unknown)}",
            )
        missing = [p.name for p in params if p.required and p.name not in provided]
        if missing:
            raise McpError(
                ErrorCode.INVALID_PARAMS,
                f"missing required arguments for '{owner}': {missing}",
            )

        kwargs: Dict[str, Any] = {}
        for name, raw in provided.items():
            pspec = by_name[name]
            try:
                kwargs[name] = pspec.coerce(raw)
            except CoercionError as exc:
                raise McpError(
                    ErrorCode.INVALID_PARAMS,
                    f"invalid argument '{name}': {exc.message}",
                    {"param": name},
                )
            except (ValueError, TypeError) as exc:
                raise McpError(
                    ErrorCode.INVALID_PARAMS,
                    f"invalid argument '{name}': {exc}",
                    {"param": name},
                )
        return kwargs

    def _contents(self, uri: str, mime_type: str, value: Any) -> dict:
        text = json.dumps(_jsonify(value), ensure_ascii=False, default=json_default)
        return {"contents": [{"uri": uri, "mimeType": mime_type, "text": text}]}

    def _encode_cursor(self, offset: int) -> str:
        raw = json.dumps({"o": offset}).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    def _decode_cursor(self, cursor: Optional[str]) -> int:
        if cursor is None:
            return 0
        try:
            raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
            offset = int(json.loads(raw)["o"])
        except Exception:
            raise McpError(ErrorCode.INVALID_PARAMS, "Invalid cursor")
        if offset < 0:
            raise McpError(ErrorCode.INVALID_PARAMS, "Invalid cursor")
        return offset


def _match_resource(spec: ResourceSpec, uri: str) -> Optional[Dict[str, str]]:
    """Match ``uri`` against a resource spec; return bound params or ``None``."""
    if not spec.is_template:
        return {} if spec.uri == uri else None
    match = _template_regex(spec.uri).match(uri)
    if match is None:
        return None
    return dict(match.groupdict())


_TEMPLATE_TOKEN = re.compile(r"\{([^/{}]+)\}")


def _template_regex(template: str) -> "re.Pattern[str]":
    parts: List[str] = []
    cursor = 0
    for token in _TEMPLATE_TOKEN.finditer(template):
        parts.append(re.escape(template[cursor : token.start()]))
        parts.append(f"(?P<{token.group(1)}>[^/]+)")
        cursor = token.end()
    parts.append(re.escape(template[cursor:]))
    return re.compile("^" + "".join(parts) + "$")
