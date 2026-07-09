"""The ``idb_snapshot`` use-case: save a compressed database copy.

A thin orchestration over the :class:`~idamesh.domain.ports.snapshot.SnapshotGateway`:
validate that a non-empty destination path was given (a pure guard, so an obviously
bad request fails without touching the database), then ask the gateway to save the
compressed snapshot and wrap the result. Everything that touches the SDK lives in
the adapter.
"""

from __future__ import annotations

from idamesh.application.dto.snapshot import SnapshotCommand, SnapshotResult
from idamesh.domain.ports.snapshot import SnapshotGateway


def _require_path(path: str) -> str:
    """Return ``path`` if it is a non-empty, non-blank string, else raise."""
    if not isinstance(path, str):
        raise ValueError(f"path must be a string, got {type(path).__name__}")
    stripped = path.strip()
    if not stripped:
        raise ValueError("path must not be empty")
    return stripped


class SnapshotUseCase:
    """Validate the destination and save a compressed snapshot there."""

    def __init__(self, snapshot: SnapshotGateway) -> None:
        self._snapshot = snapshot

    def execute(self, command: SnapshotCommand) -> SnapshotResult:
        """Save a compressed snapshot to ``command.path`` and wrap it.

        The path is validated (non-empty) before the gateway writes; a refused
        save surfaces as an error the interface layer renders as an ``isError``
        result.
        """
        path = _require_path(command.path)
        snapshot = self._snapshot.save(path)
        return SnapshotResult(snapshot=snapshot)
