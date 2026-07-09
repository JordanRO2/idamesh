"""JSON-RPC dispatch and per-request context (IDA-free).

The :class:`~idamesh.infrastructure.rpc.router.Router` (dispatch mechanism) and
the :class:`~idamesh.infrastructure.rpc.context.RequestContext` +
cancellation registry. Reused unchanged by the supervisor process.
"""

from __future__ import annotations

from idamesh.infrastructure.rpc.context import (
    Cancelled,
    CancellationRegistry,
    CancellationToken,
    RequestContext,
    RpcId,
    bind,
    current,
)
from idamesh.infrastructure.rpc.router import (
    ExceptionMapper,
    Handler,
    Router,
    RpcError,
    RpcErrorCode,
    RpcRequest,
    RpcResponse,
)

__all__ = [
    "Cancelled",
    "CancellationRegistry",
    "CancellationToken",
    "RequestContext",
    "RpcId",
    "bind",
    "current",
    "ExceptionMapper",
    "Handler",
    "Router",
    "RpcError",
    "RpcErrorCode",
    "RpcRequest",
    "RpcResponse",
]
