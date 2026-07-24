"""Catalog registration and wire-shape projection for ``exec_python`` (mutating).

The ``ExecPythonView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`exec_python_view` renders the run result into that flat
shape (captured ``stdout``, the ``result`` repr, ``ok`` always true on success).
The tool is marked ``@registry.mutating`` because a script may write the database.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.exec_script import ExecScriptUseCase
from idamesh.application.dto.script import ExecScriptCommand, ExecScriptResult
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class ExecPythonView(TypedDict):
    """The outcome of one ``exec_python`` call."""

    stdout: str
    result: str
    ok: bool


def exec_python_view(result: ExecScriptResult) -> ExecPythonView:
    """Project an :class:`ExecScriptResult` into its wire shape."""
    return ExecPythonView(
        stdout=result.outcome.stdout,
        result=result.outcome.result,
        ok=True,
    )


def register_exec_python(
    registry: Registry,
    *,
    exec_script_use_case: ExecScriptUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``exec_python`` against the exec-script use-case (mutating)."""

    @registry.tool(name="exec_python")
    @registry.mutating
    def exec_python(code: str) -> ExecPythonView:
        """Execute an IDAPython script against the current database and return what
        it produced. ``code`` is Python source run on the database-owning thread
        with the IDA SDK in scope (``idaapi`` / ``idc`` / ``idautils`` and the
        ``ida_*`` modules pre-imported), so it may both read and mutate the
        database — use it for bulk work the structured tools do not cover (e.g.
        rename every function matching a pattern in one pass). Whatever the script
        ``print``s is returned as ``stdout``; if it binds a top-level ``result``
        variable, its ``repr`` is returned as ``result``. A syntax error or an
        exception raised by the script comes back as an error result carrying the
        captured output and traceback rather than failing the protocol request.
        Powerful and unsandboxed: the script has full in-process access to IDA."""
        command = ExecScriptCommand(code=code)
        result = run_mutation(
            executor, lambda: exec_script_use_case.execute(command)
        )
        return exec_python_view(result)
