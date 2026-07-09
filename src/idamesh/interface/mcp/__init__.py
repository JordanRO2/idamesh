"""Our own MCP protocol engine (JSON-RPC framing lives in ``infrastructure/rpc``).

Public surface: the :class:`~idamesh.interface.mcp.engine.McpEngine`, the
:class:`~idamesh.interface.mcp.registry.Registry` decorators, the compiled
descriptors in :mod:`specs`, the schema compiler in :mod:`schema`, the
:mod:`middleware` chain, and the :mod:`overflow` store.
"""

from __future__ import annotations

from idamesh.interface.mcp.engine import (
    DEFAULT_SERVER_NAME,
    SUPPORTED_PROTOCOL_VERSIONS,
    ErrorCode,
    McpEngine,
    McpError,
    ServerInfo,
    ToolError,
)
from idamesh.interface.mcp.overflow import OVERFLOW_URI_PREFIX, OverflowRef, OverflowStore
from idamesh.interface.mcp.registry import Registry
from idamesh.interface.mcp.schema import Compiled, SchemaContext, TypeAdapter, compile_signature
from idamesh.interface.mcp.specs import (
    CancelSignal,
    ParamSpec,
    PromptSpec,
    RequestView,
    ResourceSpec,
    ToolResult,
    ToolSpec,
)

__all__ = [
    "DEFAULT_SERVER_NAME",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "ErrorCode",
    "McpEngine",
    "McpError",
    "ServerInfo",
    "ToolError",
    "OVERFLOW_URI_PREFIX",
    "OverflowRef",
    "OverflowStore",
    "Registry",
    "Compiled",
    "SchemaContext",
    "TypeAdapter",
    "compile_signature",
    "CancelSignal",
    "ParamSpec",
    "PromptSpec",
    "RequestView",
    "ResourceSpec",
    "ToolResult",
    "ToolSpec",
]
