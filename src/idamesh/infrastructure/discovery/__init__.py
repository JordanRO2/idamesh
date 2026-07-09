"""Filesystem instance discovery (idapro-free).

The coupling between the resident GUI plugin (which *writes* its endpoint here) and
the supervisor (which *reads* it to adopt live instances). Pure stdlib, so both the
IDA-hosted plugin and the idapro-free supervisor share it. See
:mod:`idamesh.infrastructure.discovery.registry` for the on-disk contract and
:mod:`idamesh.infrastructure.discovery.adoption` for the routing-record view.
"""

from __future__ import annotations

from idamesh.infrastructure.discovery.adoption import (
    DiscoveredSession,
    GuiDiscoveryReader,
)
from idamesh.infrastructure.discovery.registry import (
    BACKEND_GUI,
    BACKEND_WORKER,
    DiscoveryEntry,
    DiscoveryRegistry,
    ida_user_dir,
    registry_dir,
    tcp_port_open,
)

__all__ = [
    "BACKEND_GUI",
    "BACKEND_WORKER",
    "DiscoveryEntry",
    "DiscoveryRegistry",
    "DiscoveredSession",
    "GuiDiscoveryReader",
    "ida_user_dir",
    "registry_dir",
    "tcp_port_open",
]
