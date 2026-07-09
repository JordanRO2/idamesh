"""The vulnerability-heuristics service — pure, IDA-free, explainable rules.

:class:`VulnHeuristicsService` reads a function's decompiled pseudocode as text
and applies a small set of *authored* pattern rules, each of which, when it
fires, produces a :class:`~idamesh.domain.entities.vuln_finding.VulnFinding` whose
``description`` names the rule so the result is explainable. The rules approximate
well-known weakness classes from static shape alone:

* **R1 — unbounded copy.** A call to an unbounded string-copy sink
  (``strcpy`` / ``strcat`` / ``gets`` / ``sprintf`` …) has no length argument to
  bound it; ``gets`` is uniquely dangerous (no bound is even possible).
* **R2 — format string.** A ``printf``-family call whose format argument is not a
  string literal lets an attacker control the format specifiers.
* **R3 — command injection.** A ``system`` / ``exec*`` / ``popen`` / ``WinExec``
  call whose command argument is not a string literal launches an
  attacker-influenced command.
* **R4 — unchecked memory move.** A ``memcpy`` / ``memmove`` whose size argument
  is not a compile-time constant may copy an attacker-controlled length.
* **R5 — dangerous API reachable.** A dangerous imported API is called but did
  not trip a more specific rule — a low-severity signpost worth review.

The rules, thresholds, severities, and messages are ours; the weakness-class
*names* are shared vocabulary. Operating purely on text keeps the service fully
unit-testable with no IDA present; the application layer supplies the pseudocode
(via the decompiler) and the dangerous-API classification.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from idamesh.domain.entities.vuln_finding import VulnFinding
from idamesh.domain.services.dangerous_apis import DangerousApiService
from idamesh.domain.values.address import Address

# -- Finding vocabulary --------------------------------------------------------

KIND_BUFFER_OVERFLOW = "buffer_overflow"
KIND_FORMAT_STRING = "format_string"
KIND_COMMAND_INJECTION = "command_injection"
KIND_DANGEROUS_CALL = "dangerous_call"

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# -- Authored rule tables (base API names, undecorated) ------------------------

#: R1: unbounded string-copy sinks (no length argument bounds them).
_UNBOUNDED_COPY: Tuple[str, ...] = (
    "strcpy", "strcat", "gets", "sprintf", "vsprintf",
    "stpcpy", "lstrcpy", "lstrcat", "wcscpy", "wcscat",
)
#: R2: format-string sinks mapped to the argument index of their format string.
_FORMAT_ARG_INDEX: Dict[str, int] = {
    "printf": 0,
    "vprintf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "syslog": 1,
}
#: R3: command launchers mapped to the argument index of their command string.
_COMMAND_ARG_INDEX: Dict[str, int] = {
    "system": 0,
    "popen": 0,
    "execl": 0,
    "execlp": 0,
    "execv": 0,
    "execvp": 0,
    "WinExec": 0,
}
#: R4: raw memory moves whose last argument is the copy length.
_MEMORY_MOVE: Tuple[str, ...] = ("memcpy", "memmove", "bcopy", "wmemcpy")

#: Matches an identifier immediately followed by an opening parenthesis — a call.
_CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
#: A compile-time-constant size expression (decimal, hex, or ``sizeof``).
_CONST_SIZE_RE = re.compile(r"\A(0[xX][0-9a-fA-F]+|[0-9]+[uUlL]*|sizeof\b)")


class VulnHeuristicsService:
    """Apply authored, explainable vulnerability rules to pseudocode text."""

    def analyze(
        self,
        *,
        address: Address,
        function: Optional[str],
        pseudocode: str,
        danger: DangerousApiService,
    ) -> List[VulnFinding]:
        """Run every rule over ``pseudocode`` and return the findings it raises.

        Each rule inspects the call sites in the decompiled text; when a rule
        fires it produces one :class:`VulnFinding` anchored at ``address`` (the
        function entry) naming its ``kind``, ``severity``, and the rule in its
        ``description``. Findings are de-duplicated per ``(kind, sink)`` so a sink
        called several times in one function reports once. The ``danger`` service
        supplies the classification behind the R5 fallback and normalizes the
        decorated names real binaries carry.
        """
        findings: List[VulnFinding] = []
        seen: Set[Tuple[str, str]] = set()

        def emit(kind: str, severity: str, sink: str, description: str) -> None:
            key = (kind, sink)
            if key in seen:
                return
            seen.add(key)
            findings.append(
                VulnFinding(
                    address=address,
                    function=function,
                    kind=kind,
                    severity=severity,
                    description=description,
                )
            )

        for match in _CALL_RE.finditer(pseudocode):
            raw_name = match.group(1)
            base = self._base_name(raw_name)
            args = self._call_args(pseudocode, match.end() - 1)

            if base in _UNBOUNDED_COPY:
                if base == "gets":
                    emit(
                        KIND_BUFFER_OVERFLOW,
                        SEVERITY_CRITICAL,
                        base,
                        "R1 unbounded copy: gets() cannot bound its read and "
                        "always risks a buffer overflow",
                    )
                else:
                    emit(
                        KIND_BUFFER_OVERFLOW,
                        SEVERITY_HIGH,
                        base,
                        f"R1 unbounded copy: {base}() has no length argument to "
                        "bound the write into its destination",
                    )
                continue

            if base in _FORMAT_ARG_INDEX:
                index = _FORMAT_ARG_INDEX[base]
                fmt = self._arg(args, index)
                if fmt is not None and not self._is_string_literal(fmt):
                    emit(
                        KIND_FORMAT_STRING,
                        SEVERITY_HIGH,
                        base,
                        f"R2 format string: the format argument of {base}() is "
                        "not a string literal and may be attacker-controlled",
                    )
                continue

            if base in _COMMAND_ARG_INDEX:
                index = _COMMAND_ARG_INDEX[base]
                cmd = self._arg(args, index)
                if cmd is not None and not self._is_string_literal(cmd):
                    emit(
                        KIND_COMMAND_INJECTION,
                        SEVERITY_HIGH,
                        base,
                        f"R3 command injection: the command argument of {base}() "
                        "is not a string literal and may be attacker-controlled",
                    )
                continue

            if base in _MEMORY_MOVE:
                size = self._arg(args, -1)
                if size is not None and not self._is_constant_size(size):
                    emit(
                        KIND_BUFFER_OVERFLOW,
                        SEVERITY_MEDIUM,
                        base,
                        f"R4 unchecked copy: the size argument of {base}() is not "
                        "a compile-time constant",
                    )
                continue

            classified = danger.classify(raw_name)
            if classified is not None:
                emit(
                    KIND_DANGEROUS_CALL,
                    SEVERITY_LOW,
                    classified.name,
                    f"R5 dangerous API reachable: {classified.name}() "
                    f"({classified.category}) is called in this function",
                )

        return findings

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _base_name(name: str) -> str:
        """Undecorate an identifier to its base API name.

        Strips leading underscores and a trailing Win32 ``A``/``W`` charset
        suffix so ``_strcpy`` and ``lstrcpyA`` normalize to the table's spelling.
        """
        stripped = name.lstrip("_")
        if len(stripped) > 1 and stripped[-1] in ("A", "W"):
            core = stripped[:-1]
            if (
                core in _UNBOUNDED_COPY
                or core in _FORMAT_ARG_INDEX
                or core in _COMMAND_ARG_INDEX
                or core in _MEMORY_MOVE
            ):
                return core
        return stripped

    @staticmethod
    def _call_args(text: str, open_paren: int) -> Optional[List[str]]:
        """Split the argument list of a call into top-level argument strings.

        ``open_paren`` indexes the call's opening parenthesis in ``text``. Parses
        forward with parenthesis-depth and string-literal awareness, splitting on
        the top-level commas only. Returns ``None`` when the parentheses do not
        balance before the text ends (a wrapped or truncated call), so a rule that
        needs an argument simply does not fire rather than guessing.
        """
        depth = 0
        in_str: Optional[str] = None
        escaped = False
        current: List[str] = []
        args: List[str] = []
        i = open_paren
        length = len(text)
        while i < length:
            char = text[i]
            if in_str is not None:
                current.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == in_str:
                    in_str = None
                i += 1
                continue
            if char in ('"', "'"):
                in_str = char
                current.append(char)
            elif char == "(":
                depth += 1
                if depth > 1:
                    current.append(char)
            elif char == ")":
                depth -= 1
                if depth == 0:
                    args.append("".join(current))
                    return args
                current.append(char)
            elif char == "," and depth == 1:
                args.append("".join(current))
                current = []
            else:
                current.append(char)
            i += 1
        return None

    @staticmethod
    def _arg(args: Optional[List[str]], index: int) -> Optional[str]:
        """Return the ``index``-th argument (negative indexes from the end)."""
        if args is None:
            return None
        # A lone empty string means a no-argument call — no argument to inspect.
        if len(args) == 1 and args[0].strip() == "":
            return None
        if index < 0:
            index += len(args)
        if 0 <= index < len(args):
            return args[index].strip()
        return None

    @staticmethod
    def _is_string_literal(arg: str) -> bool:
        """``True`` when an argument is a (possibly wide) string literal."""
        text = arg.strip()
        if text[:1] in ("L", "u", "U") and text[1:2] == '"':
            return True
        return text[:1] == '"'

    @staticmethod
    def _is_constant_size(arg: str) -> bool:
        """``True`` when a size argument is a compile-time constant expression."""
        return bool(_CONST_SIZE_RE.match(arg.strip()))
