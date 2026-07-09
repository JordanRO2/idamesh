"""The dangerous-API service — a pure, IDA-free classification table.

:class:`DangerousApiService` classifies imported C-runtime and OS functions that
are historically implicated in memory-safety and injection bugs: the unbounded
string copies (``strcpy`` / ``strcat`` / ``gets`` / ``sprintf`` …), the raw
memory moves (``memcpy`` / ``memmove``), the format-string sinks (``printf`` /
``syslog`` …), the input parsers (``scanf`` family), and the command launchers
(``system`` / ``exec*`` / ``popen`` / ``WinExec`` …). Each entry carries a coarse
``category`` and a ``severity`` band.

The *list of names* is a published fact (these are the functions every secure-C
guideline flags); the *categorization*, the severity bands, and the name
normalization policy are our authored design. Keeping the table as a stateless
domain service makes it fully unit-testable with no IDA present; the application
layer matches it against the import table and collects each dangerous import's
call sites.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

#: Severity bands, most-to-least severe. Used as authored labels on findings.
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

#: Coarse categories grouping the danger by the class of bug it invites.
CATEGORY_BUFFER_COPY = "buffer_copy"
CATEGORY_MEMORY_MOVE = "memory_move"
CATEGORY_FORMAT_STRING = "format_string"
CATEGORY_INPUT_PARSE = "input_parse"
CATEGORY_COMMAND_EXEC = "command_exec"


@dataclass(frozen=True)
class DangerousApi:
    """A dangerous imported API and its authored classification."""

    name: str
    category: str
    severity: str


def _entries(
    names: Tuple[str, ...], category: str, severity: str
) -> Tuple[DangerousApi, ...]:
    """Build classified entries for a group of names sharing category/severity."""
    return tuple(DangerousApi(name, category, severity) for name in names)


#: The authored classification table. Grouped by the bug class each API invites;
#: the names are facts, the grouping and severities are ours.
_TABLE: Dict[str, DangerousApi] = {
    api.name: api
    for api in (
        # Unbounded string copies — the classic stack/heap overflow sinks.
        *_entries(
            ("gets", "_gets"),
            CATEGORY_BUFFER_COPY,
            SEVERITY_CRITICAL,
        ),
        *_entries(
            (
                "strcpy", "strcat", "stpcpy", "wcscpy", "wcscat",
                "lstrcpy", "lstrcat", "sprintf", "vsprintf",
            ),
            CATEGORY_BUFFER_COPY,
            SEVERITY_HIGH,
        ),
        # Bounded variants that still truncate/overflow when misused.
        *_entries(
            ("strncpy", "strncat", "snprintf", "vsnprintf", "strtok"),
            CATEGORY_BUFFER_COPY,
            SEVERITY_MEDIUM,
        ),
        # Raw memory moves — overflow when the size is attacker-influenced.
        *_entries(
            ("memcpy", "memmove", "bcopy", "wmemcpy"),
            CATEGORY_MEMORY_MOVE,
            SEVERITY_MEDIUM,
        ),
        # Format-string sinks — dangerous when the format is not a literal.
        *_entries(
            ("printf", "fprintf", "vprintf", "vfprintf", "syslog"),
            CATEGORY_FORMAT_STRING,
            SEVERITY_HIGH,
        ),
        # Input parsers — the ``%s`` conversions overflow fixed buffers.
        *_entries(
            ("scanf", "sscanf", "fscanf", "vscanf", "vsscanf"),
            CATEGORY_INPUT_PARSE,
            SEVERITY_MEDIUM,
        ),
        # Command / process launchers — command-injection sinks.
        *_entries(
            (
                "system", "popen", "execl", "execlp", "execle",
                "execv", "execvp", "execvpe", "WinExec", "ShellExecute",
                "CreateProcess",
            ),
            CATEGORY_COMMAND_EXEC,
            SEVERITY_HIGH,
        ),
    )
}


class DangerousApiService:
    """Classify imported symbol names as dangerous APIs by category/severity."""

    def classify(self, name: str) -> Optional[DangerousApi]:
        """Return the :class:`DangerousApi` for ``name``, or ``None`` if benign.

        The lookup is tolerant of the decoration real import tables carry: an
        exact hit wins first, otherwise a single leading underscore is stripped
        (``_strcpy``), otherwise a trailing Win32 ``A``/``W`` charset suffix is
        stripped (``lstrcpyA``). The returned entry names the *canonical* API and
        its authored category/severity; the classification is deterministic and
        IDA-free.
        """
        if not name:
            return None
        exact = _TABLE.get(name)
        if exact is not None:
            return exact
        stripped = name.lstrip("_")
        if stripped != name:
            hit = _TABLE.get(stripped)
            if hit is not None:
                return hit
        if len(stripped) > 1 and stripped[-1] in ("A", "W"):
            hit = _TABLE.get(stripped[:-1])
            if hit is not None:
                return hit
        return None

    def is_dangerous(self, name: str) -> bool:
        """``True`` when ``name`` classifies as a dangerous API."""
        return self.classify(name) is not None
