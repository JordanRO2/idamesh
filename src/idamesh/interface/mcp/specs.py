"""Compiled tool/resource/prompt descriptors and the per-request read surface.

A :class:`ToolSpec` is reflected once at registration and thereafter drives both
``tools/list`` (its precomputed schema) and ``tools/call`` (its per-parameter
coercers), so the advertised schema and the enforced validation can never drift.

:class:`RequestView` and :class:`CancelSignal` are the *read* surface the engine
needs from the per-request context. They are declared here, in the interface
layer, so the engine never imports the transport; the concrete
``infrastructure.rpc.context.RequestContext`` / ``CancellationToken`` satisfy
them structurally, and the composition root passes the concrete objects in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol, runtime_checkable


@runtime_checkable
class CancelSignal(Protocol):
    """Cooperative cancellation flag a running tool polls."""

    @property
    def cancelled(self) -> bool:
        """``True`` once the request has been cancelled."""
        ...

    def check(self) -> None:
        """Raise if the request has been cancelled; otherwise return."""
        ...


@runtime_checkable
class RequestView(Protocol):
    """Read-only view of the per-request context consumed by the engine.

    Structurally satisfied by ``infrastructure.rpc.context.RequestContext``.
    """

    @property
    def request_id(self) -> str | int | None: ...
    @property
    def session_id(self) -> str | None: ...
    @property
    def protocol_version(self) -> str: ...
    @property
    def features(self) -> frozenset[str]: ...
    @property
    def deadline(self) -> float | None: ...
    @property
    def cancel(self) -> CancelSignal: ...


#: A per-parameter coercer: raw JSON value -> validated Python value.
Coercer = Callable[[Any], Any]


@dataclass(frozen=True)
class ParamSpec:
    """One reflected parameter: its schema fragment and its coercer."""

    name: str
    py_type: Any
    schema: Mapping[str, Any]
    required: bool
    coerce: Coercer


@dataclass(frozen=True)
class ToolSpec:
    """A fully compiled tool descriptor."""

    name: str
    description: str
    params: tuple[ParamSpec, ...]
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any] | None
    invoke: Callable[..., Any]
    feature: str | None = None
    annotations: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResourceSpec:
    """A registered MCP resource, literal or templated."""

    uri: str
    name: str
    description: str
    invoke: Callable[..., Any]
    mime_type: str = "application/json"
    is_template: bool = False
    params: tuple[ParamSpec, ...] = ()


@dataclass(frozen=True)
class PromptSpec:
    """A registered MCP prompt."""

    name: str
    description: str
    arguments: tuple[ParamSpec, ...]
    invoke: Callable[..., Any]


@dataclass(frozen=True)
class ToolResult:
    """The MCP ``tools/call`` result envelope in structured form."""

    content: tuple[Mapping[str, Any], ...]
    structured_content: Mapping[str, Any] | None = None
    is_error: bool = False
    meta: Mapping[str, Any] | None = None

    def to_wire(self) -> dict[str, Any]:
        """Render to the JSON object shape MCP clients expect
        (``content`` + ``structuredContent`` + ``isError`` [+ ``_meta``])."""
        wire: dict[str, Any] = {
            "content": [dict(block) for block in self.content],
            "isError": self.is_error,
        }
        if self.structured_content is not None:
            wire["structuredContent"] = dict(self.structured_content)
        if self.meta is not None:
            wire["_meta"] = dict(self.meta)
        return wire
