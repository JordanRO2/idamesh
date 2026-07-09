"""Supervisor entry point (composition root) — the single public MCP endpoint.

Builds the idapro-free N-copies core and serves it over streamable HTTP:

* a :class:`~idamesh.infrastructure.process.worker_pool.WorkerPool` that spawns and
  reaps the headless workers;
* a :class:`~idamesh.infrastructure.rpc.worker_client.WorkerClient` that forwards
  frames to them;
* a :class:`~idamesh.interface.router.supervisor.SupervisorRouter` wired with the
  in-process, idapro-free worker tool ``Registry`` (obtained from
  :func:`~idamesh.bootstrap.container.build_worker_container`, whose IDA adapters
  import lazily, so no ``idapro`` loads just to read tool schemas).

This module — and everything it imports at load time — must never ``import
idapro``; the router process stays a neutral fan-out point. The
``build_worker_container`` import is done inside :func:`build_supervisor_container`
so merely importing this module is light and unambiguously idapro-free. Verified
by ``tests/architecture`` (``test_orchestrator_graph_is_idapro_free``).
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
from dataclasses import dataclass, field
from typing import Optional, Sequence, Tuple

from idamesh.infrastructure.process.worker_pool import WorkerPool
from idamesh.infrastructure.rpc.router import Router
from idamesh.infrastructure.rpc.worker_client import WorkerClient
from idamesh.infrastructure.transport.http import HttpTransport
from idamesh.interface.mcp.engine import SUPPORTED_PROTOCOL_VERSIONS, ServerInfo
from idamesh.interface.router.supervisor import SupervisorRouter

#: Default front endpoint (env ``IDA_MCP_SUPERVISOR_HOST`` / ``_PORT`` override).
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8745


@dataclass
class SupervisorContainer:
    """The wired supervisor object graph for one process."""

    pool: WorkerPool
    client: WorkerClient
    router_impl: SupervisorRouter
    rpc_router: Router
    protocol_versions: Tuple[str, ...] = field(
        default=tuple(SUPPORTED_PROTOCOL_VERSIONS)
    )


def build_supervisor_container(
    *,
    server_version: str = "0.0.1",
    max_workers: Optional[int] = None,
    host: str = DEFAULT_HOST,
    adopt_gui: bool = True,
) -> SupervisorContainer:
    """Build the supervisor graph (pool + client + router), idapro-free.

    ``adopt_gui`` (default on) wires the filesystem-discovery reader so a running
    idamesh GUI plugin is surfaced by ``idb_list`` and routable by its session id.
    The reader is pure stdlib (no ``idapro``); with no registry present it simply
    yields nothing, so enabling it is harmless on a host with no live GUI.
    """
    # Imported here (not at module load) so importing this module never triggers
    # the worker container's adapter graph — keeps the module trivially
    # idapro-free and cheap to import.
    from idamesh.bootstrap.container import build_worker_container

    worker_registry = build_worker_container(server_version=server_version).registry

    discovery = None
    if adopt_gui:
        from idamesh.infrastructure.discovery import GuiDiscoveryReader

        discovery = GuiDiscoveryReader()

    pool = WorkerPool(max_workers=max_workers, host=host)
    client = WorkerClient()
    router_impl = SupervisorRouter(
        pool=pool,
        client=client,
        worker_registry=worker_registry,
        server_info=ServerInfo(version=server_version),
        discovery=discovery,
    )
    rpc_router = Router(map_exception=router_impl.map_exception)
    for method, handler in router_impl.methods().items():
        rpc_router.register(
            method, handler, notification=method.startswith("notifications/")
        )
    return SupervisorContainer(
        pool=pool,
        client=client,
        router_impl=router_impl,
        rpc_router=rpc_router,
        protocol_versions=tuple(SUPPORTED_PROTOCOL_VERSIONS),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="idamesh-supervisor",
        description="Routing supervisor / N-copies orchestrator (single MCP endpoint).",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("IDA_MCP_SUPERVISOR_HOST", DEFAULT_HOST),
        help="front endpoint bind host",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("IDA_MCP_SUPERVISOR_PORT", DEFAULT_PORT)),
        help="front endpoint bind port (0 = ephemeral)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="cap on concurrently-owned workers (env IDA_MCP_MAX_WORKERS; 0 = unlimited)",
    )
    parser.add_argument("--server-version", default="0.0.1", help="advertised server version")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Serve the supervisor over HTTP until interrupted. Reaps workers on exit."""
    args = _build_parser().parse_args(list(argv) if argv is not None else None)

    container = build_supervisor_container(
        server_version=args.server_version,
        max_workers=args.max_workers,
        host=args.host,
    )
    transport = HttpTransport(
        container.rpc_router,
        host=args.host,
        port=args.port,
        supported_protocol_versions=container.protocol_versions,
    )
    try:
        transport.serve(block=False)
        sys.stderr.write(
            f"idamesh supervisor listening on http://{args.host}:{transport.bound_port}/mcp\n"
        )
        sys.stderr.flush()
        # The HTTP server runs on its own daemon thread; park the main thread
        # until Ctrl-C so the finally-block can reap the workers.
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        transport.stop()
        container.pool.close_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
