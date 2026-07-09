"""The JSON-RPC 2.0 router: decode, validate, dispatch, serialize.

The ``Router`` is a generic mechanism: it maps a method name to a handler
registered by the composition root (typically the engine's MCP methods). It owns
the JSON-RPC error model, batch handling, the notification-has-no-``id`` rule,
and the per-request context + cancellation lifecycle (it opens a token for each
call, trips it on a built-in ``notifications/cancelled`` handler, and closes it
when the call completes). It imports no ``interface`` code; handlers are injected
and exceptions are mapped through an injected :data:`ExceptionMapper`, so the
layer boundary stays clean. This is the ``dispatch`` entry point a transport
drives.
"""

from __future__ import annotations

import json
import traceback
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from idamesh.infrastructure.rpc.context import (
    Cancelled,
    CancellationRegistry,
    CancellationToken,
    RequestContext,
    RpcId,
    bind,
)


class RpcErrorCode(IntEnum):
    """Standard JSON-RPC codes plus the two we use from the MCP/LSP ranges."""

    PARSE = -32700
    INVALID_REQUEST = -32600
    METHOD_MISSING = -32601
    BAD_PARAMS = -32602
    INTERNAL = -32603
    CANCELLED = -32800
    TOOL = -32000


class RpcError(Exception):
    """A JSON-RPC error carrying a code, message, and optional data."""

    def __init__(
        self,
        code: Union[RpcErrorCode, int],
        message: str,
        data: Any = None,
    ) -> None:
        super().__init__(message)
        self.code = int(code)
        self.message = message
        self.data = data

    def as_payload(self) -> dict:
        """Render to the ``{"code", "message"[, "data"]}`` error object."""
        payload: Dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            payload["data"] = self.data
        return payload


@dataclass(frozen=True)
class RpcRequest:
    """A parsed JSON-RPC request or notification.

    ``has_id`` distinguishes a notification (id key absent) from a call with a
    literal ``null`` id, per the JSON-RPC spec.
    """

    method: str
    params: Any
    id: RpcId
    has_id: bool

    @classmethod
    def from_wire(cls, obj: Mapping[str, Any]) -> "RpcRequest":
        """Parse one request object. Raises :class:`RpcError` on an invalid envelope."""
        if not isinstance(obj, Mapping):
            raise RpcError(
                RpcErrorCode.INVALID_REQUEST, "request must be a JSON object"
            )
        if obj.get("jsonrpc") != "2.0":
            raise RpcError(
                RpcErrorCode.INVALID_REQUEST,
                "missing or invalid 'jsonrpc' version (must be '2.0')",
            )
        method = obj.get("method")
        if not isinstance(method, str):
            raise RpcError(
                RpcErrorCode.INVALID_REQUEST, "missing or non-string 'method'"
            )
        has_id = "id" in obj
        rid = obj.get("id") if has_id else None
        # JSON-RPC ids are string, integer, or null. ``bool`` is an ``int``
        # subclass in Python but is not a valid id, and a fractional number
        # (parsed as ``float``) is rejected too.
        if has_id and rid is not None:
            if isinstance(rid, bool) or not isinstance(rid, (str, int)):
                raise RpcError(
                    RpcErrorCode.INVALID_REQUEST,
                    "'id' must be a string, integer, or null",
                )
        return cls(method=method, params=obj.get("params"), id=rid, has_id=has_id)


@dataclass(frozen=True)
class RpcResponse:
    """A JSON-RPC response; ``result`` and ``error`` are mutually exclusive."""

    id: RpcId
    result: Any = None
    error: Optional[Mapping[str, Any]] = None

    def to_wire(self) -> dict:
        """Render to the ``{"jsonrpc": "2.0", "id", "result"|"error"}`` object."""
        wire: Dict[str, Any] = {"jsonrpc": "2.0", "id": self.id}
        if self.error is not None:
            wire["error"] = dict(self.error)
        else:
            wire["result"] = self.result
        return wire


#: A registered method handler: ``(params, ctx) -> result``.
Handler = Callable[[Any, RequestContext], Any]
#: Maps an escaped exception to ``(code, message, data)`` or ``None`` to default.
ExceptionMapper = Callable[[BaseException], Optional[Tuple[int, str, Any]]]

#: Sentinel distinguishing "JSON failed to parse" from a legitimate ``None``.
_PARSE_FAILURE = object()

#: The wire method name whose handler the Router owns internally.
_CANCELLED_METHOD = "notifications/cancelled"


class Router:
    """Generic JSON-RPC 2.0 dispatcher over a registered handler table."""

    def __init__(
        self,
        *,
        registry: Optional[CancellationRegistry] = None,
        map_exception: Optional[ExceptionMapper] = None,
        redact_internal_errors: bool = False,
    ) -> None:
        self._registry = registry or CancellationRegistry()
        #: Public so the composition root can wire ``engine.map_exception`` in.
        self.map_exception: Optional[ExceptionMapper] = map_exception
        self._redact = redact_internal_errors
        self._handlers: Dict[str, Tuple[Handler, bool]] = {}
        # The cancellation notification is a built-in: it trips the token the
        # registry holds for the referenced in-flight request.
        self.register(_CANCELLED_METHOD, self._on_cancelled, notification=True)

    def register(
        self,
        method: str,
        handler: Handler,
        *,
        notification: bool = False,
    ) -> None:
        """Bind ``method`` to ``handler``. ``notification`` handlers never yield a
        response even when called with an id."""
        self._handlers[method] = (handler, notification)

    def dispatch(
        self,
        raw: Union[bytes, str, Mapping[str, Any], list],
        *,
        session_id: Optional[str] = None,
        protocol_version: Optional[str] = None,
        features: frozenset = frozenset(),
        deadline: Optional[float] = None,
    ) -> Optional[bytes]:
        """Decode, dispatch (single or batch), and serialize a reply.

        Returns the encoded reply bytes, or ``None`` when the input was purely
        notifications/responses (the transport then emits its no-body signal).
        The transport supplies the raw context fields; the Router builds and
        binds the :class:`RequestContext` and manages the cancellation token.
        """
        fields = dict(
            session_id=session_id,
            protocol_version=protocol_version,
            features=features,
            deadline=deadline,
        )

        payload = self._decode(raw)
        if payload is _PARSE_FAILURE:
            return self._encode(
                RpcResponse(
                    None,
                    error=RpcError(RpcErrorCode.PARSE, "parse error").as_payload(),
                ).to_wire()
            )

        if isinstance(payload, list):
            if not payload:
                # An empty batch has no valid element; JSON-RPC treats it as a
                # single Invalid Request.
                return self._encode(
                    RpcResponse(
                        None,
                        error=RpcError(
                            RpcErrorCode.INVALID_REQUEST, "empty batch"
                        ).as_payload(),
                    ).to_wire()
                )
            responses: List[dict] = []
            for element in payload:
                one = self.dispatch_one(element, **fields)
                if one is not None:
                    responses.append(one)
            if not responses:
                return None
            return self._encode(responses)

        one = self.dispatch_one(payload, **fields)
        if one is None:
            return None
        return self._encode(one)

    def dispatch_one(
        self,
        obj: Mapping[str, Any],
        *,
        session_id: Optional[str] = None,
        protocol_version: Optional[str] = None,
        features: frozenset = frozenset(),
        deadline: Optional[float] = None,
    ) -> Optional[dict]:
        """Dispatch a single request object; ``None`` for a notification."""
        rid = self._safe_id(obj)
        if not isinstance(obj, Mapping):
            return RpcResponse(
                rid,
                error=RpcError(
                    RpcErrorCode.INVALID_REQUEST, "request must be a JSON object"
                ).as_payload(),
            ).to_wire()

        try:
            req = RpcRequest.from_wire(obj)
        except RpcError as err:
            return RpcResponse(rid, error=err.as_payload()).to_wire()

        entry = self._handlers.get(req.method)
        if entry is None:
            if not req.has_id:
                # Unknown notification: silently ignored, per JSON-RPC.
                return None
            return RpcResponse(
                req.id,
                error=RpcError(
                    RpcErrorCode.METHOD_MISSING,
                    f"method not found: {req.method}",
                ).as_payload(),
            ).to_wire()

        handler, is_notification_handler = entry
        suppress = (not req.has_id) or is_notification_handler

        # A token is registered (and thus cancellable via the registry) only for
        # an id-bearing, response-yielding call; notifications get an unregistered
        # token so leaf code can still read ``ctx.cancel`` uniformly. ``initialize``
        # is defined as non-cancellable by the MCP spec, so it never gets a
        # registered token — a stray cancel for it is a harmless no-op.
        registered = (
            req.has_id
            and not is_notification_handler
            and req.method != "initialize"
        )
        token = self._registry.open(req.id) if registered else CancellationToken()
        ctx = RequestContext(
            request_id=req.id if req.has_id else None,
            session_id=session_id,
            protocol_version=protocol_version or "",
            features=features,
            cancel=token,
            deadline=deadline,
        )

        error_payload: Optional[dict] = None
        result: Any = None
        try:
            with bind(ctx):
                result = handler(req.params, ctx)
        except RpcError as err:
            error_payload = err.as_payload()
        except Cancelled:
            error_payload = RpcError(
                RpcErrorCode.CANCELLED, "request cancelled"
            ).as_payload()
        except Exception as exc:  # noqa: BLE001 — mapped to a JSON-RPC error
            error_payload = self._error_payload(exc)
        finally:
            if registered:
                self._registry.close(req.id)

        if suppress:
            return None
        if error_payload is not None:
            return RpcResponse(req.id, error=error_payload).to_wire()
        return RpcResponse(req.id, result=result).to_wire()

    # -- internals ---------------------------------------------------------

    def _on_cancelled(self, params: Any, ctx: RequestContext) -> None:
        """Built-in ``notifications/cancelled`` handler: trip the target token."""
        if isinstance(params, Mapping):
            target = params.get("requestId")
            if target is not None:
                self._registry.trip(target)
        return None

    def _error_payload(self, exc: BaseException) -> dict:
        """Map an unhandled exception to a JSON-RPC error payload."""
        mapper = self.map_exception
        if mapper is not None:
            mapped = mapper(exc)
            if mapped is not None:
                code, message, data = mapped
                return RpcError(code, message, data).as_payload()
        if self._redact:
            return RpcError(RpcErrorCode.INTERNAL, "internal error").as_payload()
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        return RpcError(
            RpcErrorCode.INTERNAL, f"internal error: {exc}", {"traceback": tb}
        ).as_payload()

    @staticmethod
    def _safe_id(obj: Any) -> RpcId:
        """Best-effort id extraction for error responses to malformed frames."""
        if isinstance(obj, Mapping):
            rid = obj.get("id")
            if isinstance(rid, bool):
                return None
            if isinstance(rid, (str, int)):
                return rid
        return None

    @classmethod
    def _decode(cls, raw: Any) -> Any:
        """Turn transport bytes/str into a parsed JSON value (or the sentinel)."""
        if isinstance(raw, (bytes, bytearray)):
            try:
                text = bytes(raw).decode("utf-8")
            except UnicodeDecodeError:
                return _PARSE_FAILURE
            return cls._parse(text)
        if isinstance(raw, str):
            return cls._parse(raw)
        # Already a decoded structure (dict/list/scalar) from the transport.
        return raw

    @staticmethod
    def _parse(text: str) -> Any:
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            return _PARSE_FAILURE

    @staticmethod
    def _encode(obj: Any) -> bytes:
        """Serialize a wire object/array to newline-free UTF-8 bytes."""
        return json.dumps(obj, ensure_ascii=False).encode("utf-8")
