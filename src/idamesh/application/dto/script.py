"""DTOs for the ``exec_python`` tool: the source command and the run result."""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.ports.script import ScriptOutcome


@dataclass(frozen=True)
class ExecScriptCommand:
    """A request to execute one IDAPython script."""

    code: str


@dataclass(frozen=True)
class ExecScriptResult:
    """The outcome of one ``exec_python`` call."""

    outcome: ScriptOutcome
