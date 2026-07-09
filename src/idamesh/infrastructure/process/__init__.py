"""Headless-worker process management for the supervisor (idapro-free).

The N-copies core's OS-facing half: minting per-session private copies of a target
binary, spawning windowless ``idalib`` workers, learning their bound port from the
readiness handshake, tracking them in an in-process session map, and reaping them.
Nothing here imports ``idapro`` — it runs in the router process.
"""

from __future__ import annotations

from idamesh.infrastructure.process.handshake import (
    HandshakeError,
    parse_handshake_line,
)
from idamesh.infrastructure.process.session import Backend, WorkerSession
from idamesh.infrastructure.process.worker_pool import (
    ConcurrencyLimitError,
    SessionSpawnError,
    WorkerPool,
    WorkerPoolError,
)

__all__ = [
    "Backend",
    "WorkerSession",
    "WorkerPool",
    "WorkerPoolError",
    "ConcurrencyLimitError",
    "SessionSpawnError",
    "HandshakeError",
    "parse_handshake_line",
]
