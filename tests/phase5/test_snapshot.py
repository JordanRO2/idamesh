"""Unit tests for the ``idb_snapshot`` worker tool (no IDA).

A fake :class:`SnapshotGateway` stands in for the IDA adapter so the use-case's
path guard, the wire projection, and the catalog registration (mutating
annotation, write marshalling, error surfacing) are exercised without a database.
The fake records every destination it is asked to write and can *refuse* a save —
mirroring the real adapter raising when ``ida_loader.save_database`` is refused or
the destination cannot be written.
"""

from __future__ import annotations

from typing import Callable, TypeVar

import pytest

from idamesh.application.contexts.snapshot import SnapshotUseCase
from idamesh.application.dto.snapshot import SnapshotCommand, SnapshotResult
from idamesh.domain.entities.snapshot import Snapshot
from idamesh.interface.catalog.snapshot import register_idb_snapshot, snapshot_view
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- fakes ------------------------------------------------------------------


class _FakeSnapshotGateway:
    """An in-memory ``SnapshotGateway`` that records writes and can refuse them.

    ``unwritable`` paths raise on ``save`` exactly as the IDA adapter does when the
    kernel refuses the save or the destination file cannot be stat'd afterward.
    Every accepted destination is recorded (with the stripped path the use-case
    forwards) and answered with a :class:`Snapshot` of ``size`` bytes.
    """

    def __init__(
        self, *, size: int = 4096, unwritable: set[str] | None = None
    ) -> None:
        self._size = size
        self._unwritable = unwritable or set()
        self.saved: list[str] = []

    def save(self, path: str) -> Snapshot:
        if path in self._unwritable:
            raise RuntimeError(f"IDA refused to save the database snapshot to {path!r}")
        self.saved.append(path)
        return Snapshot(path=path, size=self._size)


class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording write affinity."""

    def __init__(self) -> None:
        self.write_flags: list[bool] = []

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# -- use-case: path guard & pass-through ------------------------------------


def test_saves_to_given_path_and_wraps_snapshot():
    gateway = _FakeSnapshotGateway(size=8192)
    use_case = SnapshotUseCase(gateway)

    result = use_case.execute(SnapshotCommand(path="C:/out/sample.merged.i64"))

    assert isinstance(result, SnapshotResult)
    assert gateway.saved == ["C:/out/sample.merged.i64"]
    assert result.snapshot == Snapshot(path="C:/out/sample.merged.i64", size=8192)


def test_path_is_stripped_before_the_gateway_writes():
    gateway = _FakeSnapshotGateway()
    use_case = SnapshotUseCase(gateway)

    result = use_case.execute(SnapshotCommand(path="   /tmp/snap.i64  "))

    assert gateway.saved == ["/tmp/snap.i64"]
    assert result.snapshot.path == "/tmp/snap.i64"


def test_empty_path_raises_without_touching_the_gateway():
    gateway = _FakeSnapshotGateway()
    use_case = SnapshotUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(SnapshotCommand(path=""))
    assert gateway.saved == []  # nothing written on a rejected request


def test_blank_path_raises_without_touching_the_gateway():
    gateway = _FakeSnapshotGateway()
    use_case = SnapshotUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(SnapshotCommand(path="   "))
    assert gateway.saved == []


def test_non_string_path_raises():
    use_case = SnapshotUseCase(_FakeSnapshotGateway())

    with pytest.raises(ValueError):
        use_case.execute(SnapshotCommand(path=1234))  # type: ignore[arg-type]


def test_refused_save_propagates_from_the_use_case():
    target = "Z:/read-only/snap.i64"
    gateway = _FakeSnapshotGateway(unwritable={target})
    use_case = SnapshotUseCase(gateway)

    with pytest.raises(RuntimeError):
        use_case.execute(SnapshotCommand(path=target))
    assert gateway.saved == []


# -- view -------------------------------------------------------------------


def test_view_projects_snapshot_to_flat_shape():
    view = snapshot_view(Snapshot(path="/tmp/out.i64", size=2048))

    assert view == {"path": "/tmp/out.i64", "ok": True, "size": 2048}


def test_view_reports_ok_true_for_zero_byte_snapshot():
    view = snapshot_view(Snapshot(path="/tmp/empty.i64", size=0))

    assert view["ok"] is True
    assert view["size"] == 0
    assert view["path"] == "/tmp/empty.i64"


# -- catalog registration ---------------------------------------------------


def _register(gateway: _FakeSnapshotGateway, executor) -> Registry:
    registry = Registry()
    register_idb_snapshot(
        registry,
        snapshot_use_case=SnapshotUseCase(gateway),
        executor=executor,
    )
    return registry


def test_tool_is_registered_as_mutating():
    registry = _register(_FakeSnapshotGateway(), _InlineExecutor())

    spec = registry.get_tool("idb_snapshot")
    assert spec is not None
    # It writes a file, so it takes the write slot on the kernel thread.
    assert spec.annotations["readOnlyHint"] is False
    # Writing a *copy* never disturbs the live database — not a destructive edit.
    assert "destructiveHint" not in spec.annotations


def test_tool_invocation_writes_through_gateway_with_write_affinity():
    gateway = _FakeSnapshotGateway(size=1024)
    executor = _InlineExecutor()
    registry = _register(gateway, executor)

    invoke = registry.get_tool("idb_snapshot").invoke
    view = invoke(path="C:/out/canonical.merged.i64")

    assert view == {
        "path": "C:/out/canonical.merged.i64",
        "ok": True,
        "size": 1024,
    }
    assert gateway.saved == ["C:/out/canonical.merged.i64"]
    # The snapshot write was marshalled with explicit write affinity.
    assert executor.write_flags == [True]


def test_tool_invocation_surfaces_refused_save_as_toolerror():
    target = "Z:/read-only/snap.i64"
    gateway = _FakeSnapshotGateway(unwritable={target})
    registry = _register(gateway, _InlineExecutor())

    invoke = registry.get_tool("idb_snapshot").invoke
    with pytest.raises(ToolError):
        invoke(path=target)


def test_tool_invocation_surfaces_empty_path_as_toolerror():
    registry = _register(_FakeSnapshotGateway(), _InlineExecutor())

    invoke = registry.get_tool("idb_snapshot").invoke
    with pytest.raises(ToolError):
        invoke(path="")
