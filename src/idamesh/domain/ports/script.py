"""Port for executing an IDAPython script against the current database.

The ``exec_python`` tool runs arbitrary IDAPython, whose surface is the IDA SDK,
so the only implementation lives under ``infrastructure/ida/`` — this port keeps
the application and interface layers free of ``idaapi`` while still driving the
capability. The runner returns a :class:`ScriptOutcome` capturing whatever the
script printed plus the ``repr`` of an optional ``result`` value it left behind.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ScriptOutcome:
    """The captured effect of one script run."""

    stdout: str
    result: str


class ScriptRunner(Protocol):
    """Execute IDAPython source against the current database."""

    def run(self, code: str) -> ScriptOutcome:
        """Execute ``code`` and return its captured stdout + ``result`` repr."""
        ...
