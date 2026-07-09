"""The survey classification service — pure, IDA-free triage taxonomy.

:class:`SurveyService` holds the *authored* policy that turns raw records into the
survey's qualitative buckets: a function-role taxonomy (thunk / library /
small-leaf / leaf / hub / dispatcher / large / ordinary), a notable-import
categoriser (network / process / filesystem / registry / crypto / memory /
loader / anti-debug), and a coarse string categoriser (url / path / registry /
format / ip / command / other). Every threshold, keyword set, and bucket name is
our own design, kept here as a stateless service so the aggregation use-case stays
a thin orchestration over the read ports and the taxonomy is unit-testable with no
IDA present.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from idamesh.domain.entities.function import Function

# --------------------------------------------------------------------------- #
# Function-role taxonomy (our authored buckets)
# --------------------------------------------------------------------------- #

ROLE_THUNK = "thunk"
ROLE_LIBRARY = "library"
ROLE_SMALL_LEAF = "small-leaf"
ROLE_LEAF = "leaf"
ROLE_HUB = "hub"
ROLE_DISPATCHER = "dispatcher"
ROLE_LARGE = "large"
ROLE_ORDINARY = "ordinary"

# --------------------------------------------------------------------------- #
# Notable-import categories (our authored keyword taxonomy)
# --------------------------------------------------------------------------- #

CATEGORY_NETWORK = "network"
CATEGORY_PROCESS = "process"
CATEGORY_FILESYSTEM = "filesystem"
CATEGORY_REGISTRY = "registry"
CATEGORY_CRYPTO = "crypto"
CATEGORY_MEMORY = "memory"
CATEGORY_LOADER = "loader"
CATEGORY_ANTIDBG = "anti-debug"

# Ordered so an earlier category wins when a name matches more than one bucket.
_IMPORT_KEYWORDS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        CATEGORY_ANTIDBG,
        (
            "isdebuggerpresent",
            "checkremotedebugger",
            "ntquery",
            "outputdebugstring",
            "debugactiveprocess",
        ),
    ),
    (
        CATEGORY_LOADER,
        (
            "loadlibrary",
            "getprocaddress",
            "ldrload",
            "dlopen",
            "dlsym",
            "getmodulehandle",
        ),
    ),
    (
        CATEGORY_CRYPTO,
        (
            "crypt",
            "bcrypt",
            "encrypt",
            "decrypt",
            "aes",
            "des",
            "rc4",
            "md5",
            "sha",
            "rsa",
            "hash",
        ),
    ),
    (
        CATEGORY_NETWORK,
        (
            "socket",
            "connect",
            "wsastartup",
            "wsasocket",
            "send",
            "recv",
            "inet",
            "gethostby",
            "getaddrinfo",
            "bind",
            "listen",
            "accept",
            "winhttp",
            "internetopen",
            "urldownload",
            "http",
            "dnsquery",
        ),
    ),
    (
        CATEGORY_PROCESS,
        (
            "createprocess",
            "shellexecute",
            "winexec",
            "openprocess",
            "terminateprocess",
            "createthread",
            "createremotethread",
            "system",
            "popen",
            "execv",
            "execl",
            "fork",
        ),
    ),
    (
        CATEGORY_FILESYSTEM,
        (
            "createfile",
            "readfile",
            "writefile",
            "deletefile",
            "movefile",
            "copyfile",
            "findfirstfile",
            "findnextfile",
            "getmodulefilename",
            "fopen",
            "fread",
            "fwrite",
            "unlink",
            "remove",
        ),
    ),
    (
        CATEGORY_REGISTRY,
        (
            "regopen",
            "regquery",
            "regset",
            "regcreate",
            "regdelete",
            "regenum",
        ),
    ),
    (
        CATEGORY_MEMORY,
        (
            "virtualalloc",
            "virtualprotect",
            "heapalloc",
            "heapcreate",
            "memcpy",
            "memmove",
            "malloc",
            "calloc",
            "realloc",
            "mmap",
            "mprotect",
            "writeprocessmemory",
            "readprocessmemory",
        ),
    ),
)

# --------------------------------------------------------------------------- #
# String categories (our authored coarse taxonomy)
# --------------------------------------------------------------------------- #

STRING_URL = "url"
STRING_PATH = "path"
STRING_REGISTRY = "registry"
STRING_FORMAT = "format"
STRING_IP = "ip"
STRING_COMMAND = "command"
STRING_OTHER = "other"

_URL_MARKERS: Tuple[str, ...] = ("http://", "https://", "ftp://", "ws://", "://")
_PATH_SUFFIXES: Tuple[str, ...] = (".dll", ".exe", ".sys", ".so", ".dylib", ".bat")
_FORMAT_MARKERS: Tuple[str, ...] = ("%s", "%d", "%x", "%p", "%u", "%c", "%02x", "{0}")
_COMMAND_MARKERS: Tuple[str, ...] = ("cmd.exe", "powershell", "/bin/sh", "/bin/bash", "cmd /c")


class SurveyService:
    """Authored, stateless triage classification for :class:`~idamesh.domain.entities.survey.BinarySurvey`."""

    #: A body no larger than this (bytes) reads as a trivial leaf/stub.
    small_size: int = 0x20
    #: A body at least this large (bytes) reads as a heavyweight function.
    large_size: int = 0x400
    #: Called from at least this many sites reads as a shared hub/utility.
    hub_callers: int = 16
    #: Fanning out to at least this many callees reads as a dispatcher.
    dispatcher_callees: int = 12

    def classify_function(
        self,
        func: Function,
        *,
        caller_count: int,
        callee_count: int,
    ) -> str:
        """Assign ``func`` a role using its flags, size, and call degree.

        Structural flags win first (a thunk or library routine is labelled as
        such regardless of shape); otherwise the call degree and body size decide
        between a leaf, a shared hub, a dispatcher, a heavyweight, or an ordinary
        function. Every threshold is our own.
        """
        if func.is_thunk:
            return ROLE_THUNK
        if func.is_library:
            return ROLE_LIBRARY
        if callee_count == 0:
            return ROLE_SMALL_LEAF if func.size <= self.small_size else ROLE_LEAF
        if caller_count >= self.hub_callers:
            return ROLE_HUB
        if callee_count >= self.dispatcher_callees:
            return ROLE_DISPATCHER
        if func.size >= self.large_size:
            return ROLE_LARGE
        return ROLE_ORDINARY

    def classify_cheap(self, func: Function) -> str:
        """Assign ``func`` a role from flags and size alone (no xref scan).

        The ``minimal`` detail level uses this so a huge database can be surveyed
        without an inbound/outbound reference query per function.
        """
        if func.is_thunk:
            return ROLE_THUNK
        if func.is_library:
            return ROLE_LIBRARY
        if func.size <= self.small_size:
            return ROLE_SMALL_LEAF
        if func.size >= self.large_size:
            return ROLE_LARGE
        return ROLE_ORDINARY

    def categorize_import(self, name: str, module: str) -> Optional[str]:
        """Return the authored category of an import, or ``None`` if unremarkable.

        Matching is case-insensitive and substring-based over the symbol name;
        the first category (in fixed priority order) whose keyword the name
        contains wins.
        """
        lowered = name.lower()
        for category, keywords in _IMPORT_KEYWORDS:
            for keyword in keywords:
                if keyword in lowered:
                    return category
        return None

    def categorize_string(self, value: str) -> str:
        """Bucket one extracted string into a coarse authored category."""
        lowered = value.lower()
        if any(marker in lowered for marker in _URL_MARKERS):
            return STRING_URL
        if any(marker in lowered for marker in _COMMAND_MARKERS):
            return STRING_COMMAND
        if lowered.startswith("hkey") or "\\currentversion\\" in lowered or lowered.startswith("software\\"):
            return STRING_REGISTRY
        if any(marker in value for marker in _FORMAT_MARKERS):
            return STRING_FORMAT
        if self._looks_like_ipv4(value):
            return STRING_IP
        if self._looks_like_path(value, lowered):
            return STRING_PATH
        return STRING_OTHER

    @staticmethod
    def _looks_like_ipv4(value: str) -> bool:
        text = value.strip()
        parts = text.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            if not 0 <= int(part) <= 255:
                return False
        return True

    @staticmethod
    def _looks_like_path(value: str, lowered: str) -> bool:
        if any(lowered.endswith(suffix) for suffix in _PATH_SUFFIXES):
            return True
        if len(value) >= 3 and value[1] == ":" and value[2] in ("\\", "/"):
            return True  # drive-letter path (C:\ …)
        if "\\" in value and " " not in value.strip():
            return True
        if value.startswith("/") and len(value) > 1 and "/" in value[1:]:
            return True
        return False

    def role_histogram(self, roles: Dict[str, int]) -> Dict[str, int]:
        """Return ``roles`` unchanged — a hook kept for symmetry/extension."""
        return dict(roles)
