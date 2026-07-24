"""The ``exec_python`` use-case: run an IDAPython script via the script runner.

Validates the source is a non-empty string, then routes it through the
:class:`~idamesh.domain.ports.script.ScriptRunner` port. The runner captures the
script's stdout and the ``repr`` of a ``result`` name it binds; a syntax error or
an exception the script raises surfaces as an error the interface layer renders as
an ``isError`` result.
"""

from __future__ import annotations

from idamesh.application.dto.script import ExecScriptCommand, ExecScriptResult
from idamesh.domain.ports.script import ScriptRunner


class ExecScriptUseCase:
    """Run an IDAPython script against the current database."""

    def __init__(self, script: ScriptRunner) -> None:
        self._script = script

    def execute(self, command: ExecScriptCommand) -> ExecScriptResult:
        """Validate ``command.code`` and execute it through the script runner.

        The source must be a non-empty string. The runner performs the execution on
        the database-owning thread (the interface marshals it through
        ``run_mutation``), captures whatever the script prints, and repr's any
        ``result`` binding. The completed outcome is wrapped as an
        :class:`~idamesh.application.dto.script.ExecScriptResult`.
        """
        if not isinstance(command.code, str):
            raise ValueError(
                f"code must be a string, got {type(command.code).__name__}"
            )
        if not command.code.strip():
            raise ValueError("code must not be empty")
        outcome = self._script.run(command.code)
        return ExecScriptResult(outcome=outcome)
