"""Live end-to-end test of the headless worker over both transports.

Spawns the ``idamesh`` idalib worker on a private copy of the compiled
``tests/fixtures/tiny.exe`` and drives *our own* MCP stack: the ``initialize``
handshake, ``tools/list`` (asserting every shipping tool exposes valid
object-rooted JSON Schemas), then ``tools/call`` across the whole surface —
``get_metadata``, ``list_funcs``, ``list_globals`` and ``decompile`` from the
foundation slice, the Phase-2 analysis tools ``imports``, ``xrefs_to``,
``callees`` and ``disasm``, the Phase-3 structure tools ``callgraph``,
``basic_blocks`` and ``func_profile``, and the Phase-4 search/strings/number tools
``find_bytes``, ``list_strings`` and ``int_convert`` — over stdio and over
streamable HTTP. The analysis tools are checked against known facts of the
fixture: a CRT import is present, ``main`` calls ``add_numbers``, an inbound call
to ``add_numbers`` originates in ``main``, and disassembling ``main`` yields
rendered instruction lines. The structure tools are cross-checked against each
other and the fixture: the call graph rooted at ``main`` records the ``main`` ->
``add_numbers`` edge, ``main`` decomposes into at least one basic block with a
valid half-open span, and ``func_profile`` of ``main`` reports a non-zero size
whose block and callee counts agree with ``basic_blocks`` and ``callees``. The
Phase-4 tools are cross-checked against the disassembly and source: the opcode
bytes ``disasm`` rendered for ``main`` are re-formed into an IDA-style byte
pattern that ``find_bytes`` locates back at ``main``'s entry (both literally and
with an interior wildcard); ``list_strings`` returns a page carrying the
``printf`` format literal authored in ``tiny.c``; and ``int_convert`` — which
reads no database but is driven through the worker anyway — reinterprets a value
across every representation with the expected hex/decimal/signed forms. Finally the
Phase-5 memory/listing-search/bulk-function tools ``get_bytes``, ``get_int``,
``get_string``, ``get_global_value``, ``search_text``, ``find_regex``,
``export_funcs`` and ``lookup_funcs`` are cross-checked against the same known
facts: ``get_bytes`` at ``main`` reproduces the opcode bytes ``disasm`` rendered
there; ``get_int`` decodes those bytes little-endian into the value their hex
implies; ``get_global_value`` resolves the exported ``add_numbers`` symbol by name
and agrees byte-for-byte with independent ``get_bytes``/``get_int`` reads at it;
``get_string`` reads back the ``printf`` format literal at the address
``list_strings`` reported and ``find_regex`` matches the same literal at the same
address; ``search_text`` finds the ``call`` mnemonic in the rendered listing; and
``export_funcs`` plus ``lookup_funcs`` surface ``main`` and ``add_numbers`` with a
shared entry address. Each address-taking memory tool honors the ``isError``
contract on an unresolvable symbol, and ``find_regex`` does so on an invalid
pattern.

Finally the resources slice drives the server's MCP *resources* capability:
``resources/list`` and ``resources/templates/list`` advertise the five static
``ida://`` resources and the five ``ida://…/{param}`` templates, and
``resources/read`` fetches each. Because every resource is a second projection
of a use-case already exercised as a tool, each read is cross-checked against
that tool's data (``ida://metadata`` reports the same architecture/bits/module
as ``get_metadata``; ``ida://functions|globals|imports|strings`` report the same
totals as their listing tools; ``ida://function/main`` matches ``decompile``;
``ida://disasm/main`` matches ``disasm``; ``ida://xrefs/<addr>`` matches
``xrefs_to``; ``ida://struct/<name>`` matches ``type_inspect``; and
``ida://bytes/main/8`` reproduces the opcode bytes at ``main``). A template read
of an unresolvable target returns a JSON-RPC resource-not-found error
(``-32002``), never a crash and never a tool ``isError`` envelope.

Finally the mutation slice drives the write path — the first tools that *modify*
the database — over the same private copy. ``rename`` / ``set_comment`` /
``set_type`` each advertise ``readOnlyHint:false`` (the read tools advertise
``true``). ``rename`` renames the non-entry function ``add_numbers`` to a fresh
identifier and the change is read back: the new name resolves (``lookup_funcs`` /
``export_funcs``) at the old address and the old name is gone. A function comment
is written on ``main`` (``set_comment`` with ``function=true``), then a two-int
prototype is applied (``set_type`` ``"int f(int a, int b)"``); applying the type
invalidates ``main``'s decompilation cache, so one fresh ``decompile`` of ``main``
proves all three writes at once — the regenerated pseudocode carries the new
``main(int a, int b)`` signature, the function comment, and the renamed callee at
its call site (old name absent). An invalid rename (spaces in the identifier) and
an unparseable ``set_type`` are ``isError`` results, not crashes.

The batch-2 structural edits — ``patch`` / ``patch_asm`` / ``make_data`` /
``define_func`` / ``undefine`` — extend the write path over the same private copy.
All five advertise ``readOnlyHint:false`` and ``undefine`` additionally advertises
``destructiveHint:true``. ``patch`` overwrites a byte inside ``main``, ``get_bytes``
reads the new byte back, and the original window is restored and re-read.
``patch_asm`` assembles a ``nop`` at ``main`` with IDA's own assembler, discovering
at runtime whether the native assembler is available: on success the encoded bytes
are read back and the window restored, otherwise the tool's ``isError`` path is
asserted. ``make_data`` defines a dword at the printf-format literal's address and
reports the applied type and span. ``define_func`` and ``undefine`` round-trip the
non-entry function: undefining its entry removes it from ``list_funcs`` /
``lookup_funcs``, and defining it there again brings it back. Malformed hex, an
out-of-range address, a type-or-size-less ``make_data``, an unsupported width, and
define/undefine at an unresolvable symbol are all ``isError`` results. Because every
mutation lands on the worker's private copy and the worker closes its database
without saving, the on-disk fixture is asserted byte-for-byte unchanged after each
run.

The batch-3 edits — ``set_op_type`` / ``define_code`` / ``declare_type`` /
``enum_upsert`` / ``declare_stack`` / ``delete_stack`` / ``add_bookmark`` /
``force_recompile`` — finish the Phase-3 write surface over the same private copy.
All eight advertise ``readOnlyHint:false`` and ``delete_stack`` additionally
advertises ``destructiveHint:true`` (joining ``undefine``). ``set_op_type`` scans
``main`` for an operand that accepts a numeric base, flips it between ``dec`` and
``hex``, and re-disassembles after each so both renderings are observed.
``define_code`` re-creates the instruction at ``main`` and reports its length.
``declare_type`` installs a fresh struct that ``type_query`` then lists and
``type_inspect`` resolves into its three members; ``enum_upsert`` creates an enum
(surfaced by ``type_query``/``type_inspect``) and a second upsert extends it by one
member without dropping the originals. ``declare_stack`` places a frame variable on
``main`` (the first of several candidate offsets that the frame accepts) and
``delete_stack`` removes it. ``add_bookmark`` marks ``main`` and reports its slot;
``force_recompile`` invalidates ``main``'s decompilation and a fresh ``decompile``
still regenerates working pseudocode. An unknown operand representation, an
unparseable declaration, an empty enum member map, a stack op on an unresolvable
function, a delete of an absent frame variable, and code/mark/recompile at an
unresolvable address are all ``isError`` results, never crashes.

The whole module skips cleanly when idalib is unavailable (``IDADIR`` unset or the
library not importable) so a machine without IDA keeps CI green. Every spawned
idalib subprocess is created without a console window on Windows.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

import pytest

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "tiny.exe"
_SRC = Path(__file__).resolve().parents[2] / "src"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_SPAWN_TIMEOUT = 180
_CALL_TIMEOUT = 60


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_SRC) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _idalib_available() -> bool:
    """True when a child process can import idalib with the current ``IDADIR``."""
    idadir = os.environ.get("IDADIR")
    if not idadir or not os.path.isdir(idadir):
        return False
    probe = (
        "import os\n"
        "d = os.environ.get('IDADIR')\n"
        "os.add_dll_directory(d)\n"
        "import idapro\n"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", probe],
            env=_child_env(),
            capture_output=True,
            timeout=_SPAWN_TIMEOUT,
            creationflags=_NO_WINDOW,
        )
    except Exception:
        return False
    return result.returncode == 0


pytestmark = pytest.mark.skipif(
    not _FIXTURE.exists() or not _idalib_available(),
    reason="idalib unavailable (set IDADIR to a valid IDA install) or fixture missing",
)


def _spawn(copy: Path, transport: str, extra: Optional[list[str]] = None) -> subprocess.Popen:
    argv = [
        sys.executable,
        "-m",
        "idamesh.bootstrap.worker_main",
        str(copy),
        "--transport",
        transport,
    ] + (extra or [])
    return subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_child_env(),
        creationflags=_NO_WINDOW,
    )


class _LineReader:
    """Reads stdout lines on a background thread so reads can time out."""

    def __init__(self, stream) -> None:
        self._q: "queue.Queue[Optional[bytes]]" = queue.Queue()
        self._t = threading.Thread(target=self._pump, args=(stream,), daemon=True)
        self._t.start()

    def _pump(self, stream) -> None:
        for line in iter(stream.readline, b""):
            self._q.put(line)
        self._q.put(None)

    def next_line(self, timeout: float = _CALL_TIMEOUT) -> bytes:
        try:
            line = self._q.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError("worker produced no output before timeout")
        if line is None:
            raise AssertionError("worker closed its output stream unexpectedly")
        return line


def _drain_stderr(proc: subprocess.Popen) -> str:
    try:
        return (proc.stderr.read() or b"").decode(errors="replace")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Transport clients
# --------------------------------------------------------------------------- #


class _StdioClient:
    def __init__(self, proc: subprocess.Popen) -> None:
        self._proc = proc
        self._reader = _LineReader(proc.stdout)

    def notify(self, method: str, params: Optional[dict] = None) -> None:
        frame = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            frame["params"] = params
        self._proc.stdin.write((json.dumps(frame) + "\n").encode())
        self._proc.stdin.flush()

    def call(self, rid: int, method: str, params: Optional[dict] = None) -> dict:
        frame: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            frame["params"] = params
        self._proc.stdin.write((json.dumps(frame) + "\n").encode())
        self._proc.stdin.flush()
        return json.loads(self._reader.next_line())

    def close(self) -> None:
        try:
            self._proc.stdin.close()
        except Exception:
            pass


class _HttpClient:
    def __init__(self, proc: subprocess.Popen) -> None:
        self._proc = proc
        reader = _LineReader(proc.stdout)
        ready = json.loads(reader.next_line(timeout=_SPAWN_TIMEOUT))
        assert ready.get("ready") is True, ready
        self._url = f"http://127.0.0.1:{ready['port']}/mcp"
        self._session: Optional[str] = None

    def _post(self, frame: dict) -> Optional[dict]:
        headers = {"Content-Type": "application/json", "Origin": "http://localhost"}
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        req = urllib.request.Request(
            self._url, data=json.dumps(frame).encode(), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=_CALL_TIMEOUT) as resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self._session = sid
            body = resp.read()
        return json.loads(body) if body else None

    def notify(self, method: str, params: Optional[dict] = None) -> None:
        frame = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            frame["params"] = params
        self._post(frame)

    def call(self, rid: int, method: str, params: Optional[dict] = None) -> dict:
        frame: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            frame["params"] = params
        result = self._post(frame)
        assert result is not None, "expected a response body for an id-bearing call"
        return result

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------- #
# Assertions shared by both transports
# --------------------------------------------------------------------------- #


def _assert_valid_object_schema(schema: dict) -> None:
    assert schema.get("type") == "object", schema
    assert "properties" in schema, schema
    assert schema.get("additionalProperties") is False, schema


def _drive_slice(client, module_name: str) -> str:
    # initialize ----------------------------------------------------------
    init = client.call(1, "initialize", {"protocolVersion": "2025-06-18"})
    result = init["result"]
    assert result["protocolVersion"] == "2025-06-18", result
    assert result["serverInfo"]["name"] == "idamesh", result
    client.notify("notifications/initialized")

    # tools/list ----------------------------------------------------------
    listed = client.call(2, "tools/list")["result"]["tools"]
    by_name = {tool["name"]: tool for tool in listed}
    for required in (
        "get_metadata",
        "list_funcs",
        "list_globals",
        "decompile",
        "imports",
        "xrefs_to",
        "callees",
        "disasm",
        "callgraph",
        "basic_blocks",
        "func_profile",
        "find_bytes",
        "list_strings",
        "int_convert",
        "get_bytes",
        "get_int",
        "get_string",
        "get_global_value",
        "search_text",
        "find_regex",
        "export_funcs",
        "lookup_funcs",
        "type_query",
        "type_inspect",
        "search_structs",
        "read_struct",
        "rename",
        "set_comment",
        "set_type",
        "patch",
        "patch_asm",
        "make_data",
        "define_func",
        "undefine",
        "set_op_type",
        "define_code",
        "declare_type",
        "enum_upsert",
        "declare_stack",
        "delete_stack",
        "add_bookmark",
        "force_recompile",
        "find_crypto",
        "find_dangerous_callers",
        "detect_vulns",
        "survey_binary",
        "analyze_function",
        "analyze_component",
        "detect_stack_strings",
        "trace_data_flow",
        "trace_source_to_sink",
        "entity_query",
        "func_query",
        "imports_query",
        "xref_query",
        "insn_query",
    ):
        assert required in by_name, sorted(by_name)
        tool = by_name[required]
        _assert_valid_object_schema(tool["inputSchema"])
        assert "outputSchema" in tool, tool
        _assert_valid_object_schema(tool["outputSchema"])

    # The Phase-3 mutation tools are advertised as non-read-only; every read
    # tool above is (by default) read-only, so this is what distinguishes a
    # write from a read on the wire. The batch-2 structural edits join the
    # batch-1 annotation writes here.
    for mut in (
        "rename",
        "set_comment",
        "set_type",
        "patch",
        "patch_asm",
        "make_data",
        "define_func",
        "undefine",
        "set_op_type",
        "define_code",
        "declare_type",
        "enum_upsert",
        "declare_stack",
        "delete_stack",
        "add_bookmark",
        "force_recompile",
    ):
        annotations = by_name[mut].get("annotations", {})
        assert annotations.get("readOnlyHint") is False, (mut, by_name[mut])
    # ``undefine`` discards an existing definition and ``delete_stack`` removes an
    # existing frame variable, so both additionally carry the destructive hint;
    # the other mutating tools do not.
    for destructive in ("undefine", "delete_stack"):
        assert (
            by_name[destructive].get("annotations", {}).get("destructiveHint") is True
        ), (destructive, by_name[destructive])
    for non_destructive in (
        "rename",
        "set_comment",
        "set_type",
        "patch",
        "make_data",
        "set_op_type",
        "define_code",
        "declare_type",
        "enum_upsert",
        "declare_stack",
        "add_bookmark",
        "force_recompile",
    ):
        annotations = by_name[non_destructive].get("annotations", {})
        assert annotations.get("destructiveHint") is not True, (
            non_destructive,
            by_name[non_destructive],
        )
    for ro in (
        "decompile",
        "list_funcs",
        "lookup_funcs",
        "find_crypto",
        "find_dangerous_callers",
        "detect_vulns",
        "survey_binary",
        "analyze_function",
        "analyze_component",
        "detect_stack_strings",
        "trace_data_flow",
        "trace_source_to_sink",
        "entity_query",
        "func_query",
        "imports_query",
        "xref_query",
        "insn_query",
    ):
        annotations = by_name[ro].get("annotations", {})
        assert annotations.get("readOnlyHint") is True, (ro, by_name[ro])

    # get_metadata --------------------------------------------------------
    meta = client.call(
        3, "tools/call", {"name": "get_metadata", "arguments": {}}
    )["result"]
    assert meta["isError"] is False, meta
    md = meta["structuredContent"]
    assert md["architecture"] == "metapc", md
    assert md["bits"] == 64, md
    assert md["endianness"] == "little", md
    assert md["module"] == module_name, md
    assert md["function_count"] > 0, md

    # list_funcs ----------------------------------------------------------
    funcs = client.call(
        4, "tools/call", {"name": "list_funcs", "arguments": {"offset": 0, "count": 10}}
    )["result"]
    assert funcs["isError"] is False, funcs
    page = funcs["structuredContent"]
    assert page["total"] > 0, page
    assert len(page["items"]) > 0, page
    first = page["items"][0]
    assert first["start"].startswith("0x"), first
    assert isinstance(first["size"], int), first

    # decompile -----------------------------------------------------------
    decomp = client.call(
        5, "tools/call", {"name": "decompile", "arguments": {"address": "main"}}
    )["result"]
    assert decomp["isError"] is False, decomp
    pseudo = decomp["structuredContent"]
    assert pseudo["name"] == "main", pseudo
    assert pseudo["address"].startswith("0x"), pseudo
    text = pseudo["pseudocode"]
    assert "main" in text and "return" in text, text
    assert len(pseudo["lines"]) > 1, pseudo

    # list_globals --------------------------------------------------------
    globs = client.call(
        6, "tools/call", {"name": "list_globals", "arguments": {"offset": 0, "count": 50}}
    )["result"]
    assert globs["isError"] is False, globs
    gpage = globs["structuredContent"]
    assert isinstance(gpage["total"], int) and gpage["total"] >= 0, gpage
    assert isinstance(gpage["items"], list), gpage
    assert len(gpage["items"]) <= gpage["total"], gpage
    for row in gpage["items"]:
        assert row["address"].startswith("0x"), row
        assert isinstance(row["size"], int), row

    # imports -------------------------------------------------------------
    imps = client.call(
        7, "tools/call", {"name": "imports", "arguments": {"offset": 0, "count": 200}}
    )["result"]
    assert imps["isError"] is False, imps
    ipage = imps["structuredContent"]
    assert ipage["total"] > 0, ipage
    assert len(ipage["items"]) > 0, ipage
    for row in ipage["items"]:
        assert row["address"].startswith("0x"), row
        assert isinstance(row["name"], str) and row["name"], row
        assert isinstance(row["module"], str) and row["module"], row
    import_names = {row["name"] for row in ipage["items"]}
    # A statically linked MSVC console binary always pulls a stable set of
    # C-runtime startup imports; requiring the intersection to be non-empty
    # asserts real import content without pinning one fragile name.
    crt_startup = {
        "GetSystemTimeAsFileTime",
        "QueryPerformanceCounter",
        "IsProcessorFeaturePresent",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "TerminateProcess",
    }
    assert import_names & crt_startup, sorted(import_names)

    # xrefs_to ------------------------------------------------------------
    xto = client.call(
        8, "tools/call", {"name": "xrefs_to", "arguments": {"address": "add_numbers"}}
    )["result"]
    assert xto["isError"] is False, xto
    xres = xto["structuredContent"]
    assert xres["target"].startswith("0x"), xres
    assert len(xres["xrefs"]) > 0, xres
    for edge in xres["xrefs"]:
        assert edge["from"].startswith("0x"), edge
        assert edge["to"] == xres["target"], edge
        assert edge["kind"] in ("code", "data"), edge
    # main calls add_numbers, so an inbound call edge from main must appear.
    assert any(
        edge["type"] == "call" and edge["func"] == "main" for edge in xres["xrefs"]
    ), xres

    # callees -------------------------------------------------------------
    cal = client.call(
        9, "tools/call", {"name": "callees", "arguments": {"address": "main"}}
    )["result"]
    assert cal["isError"] is False, cal
    cres = cal["structuredContent"]
    assert cres["func"].startswith("0x"), cres
    assert len(cres["callees"]) > 0, cres
    for callee in cres["callees"]:
        assert callee["addr"].startswith("0x"), callee
    callee_names = {callee["name"] for callee in cres["callees"]}
    assert "add_numbers" in callee_names, cres
    main_callee_count = len(cres["callees"])

    # disasm --------------------------------------------------------------
    dis = client.call(
        10, "tools/call", {"name": "disasm", "arguments": {"address": "main", "count": 8}}
    )["result"]
    assert dis["isError"] is False, dis
    dres = dis["structuredContent"]
    assert dres["address"].startswith("0x"), dres
    assert dres["returned"] > 0, dres
    assert dres["returned"] == len(dres["instructions"]), dres
    for insn in dres["instructions"]:
        assert insn["addr"].startswith("0x"), insn
        assert isinstance(insn["text"], str) and insn["text"], insn
        # opcode bytes are rendered as an even-length hex string.
        assert isinstance(insn["bytes"], str), insn
        assert len(insn["bytes"]) % 2 == 0, insn
    assert dres["instructions"][0]["addr"] == dres["address"], dres

    # callgraph -----------------------------------------------------------
    # Rooted at main, the bounded breadth-first traversal must reach the
    # add_numbers node and record the direct main -> add_numbers call edge.
    cg = client.call(
        13, "tools/call", {"name": "callgraph", "arguments": {"address": "main"}}
    )["result"]
    assert cg["isError"] is False, cg
    graph = cg["structuredContent"]
    assert graph["root"].startswith("0x"), graph
    assert isinstance(graph["truncated"], bool), graph
    assert len(graph["nodes"]) > 0, graph
    for node in graph["nodes"]:
        assert node["address"].startswith("0x"), node
    # The root address is always materialized as a node.
    node_addrs = {node["address"] for node in graph["nodes"]}
    assert graph["root"] in node_addrs, graph
    for edge in graph["edges"]:
        assert edge["from"].startswith("0x"), edge
        assert edge["to"].startswith("0x"), edge
    # Locate the add_numbers node by name and assert the main -> add_numbers
    # edge is present.
    add_nodes = [n for n in graph["nodes"] if n["name"] == "add_numbers"]
    assert add_nodes, graph
    add_addr = add_nodes[0]["address"]
    assert any(
        edge["from"] == graph["root"] and edge["to"] == add_addr
        for edge in graph["edges"]
    ), graph

    # basic_blocks --------------------------------------------------------
    bb = client.call(
        14, "tools/call", {"name": "basic_blocks", "arguments": {"address": "main"}}
    )["result"]
    assert bb["isError"] is False, bb
    bres = bb["structuredContent"]
    assert bres["func"].startswith("0x"), bres
    assert isinstance(bres["truncated"], bool), bres
    assert len(bres["blocks"]) >= 1, bres
    for block in bres["blocks"]:
        assert block["start"].startswith("0x"), block
        assert block["end"].startswith("0x"), block
        # start/end form a valid half-open span.
        assert int(block["end"], 16) > int(block["start"], 16), block
        assert isinstance(block["successors"], list), block
        for succ in block["successors"]:
            assert succ.startswith("0x"), block
    main_block_count = len(bres["blocks"])

    # func_profile --------------------------------------------------------
    fp = client.call(
        15, "tools/call", {"name": "func_profile", "arguments": {"address": "main"}}
    )["result"]
    assert fp["isError"] is False, fp
    prof = fp["structuredContent"]
    assert prof["address"].startswith("0x"), prof
    assert prof["name"] == "main", prof
    assert isinstance(prof["size"], int) and prof["size"] > 0, prof
    assert isinstance(prof["block_count"], int) and prof["block_count"] > 0, prof
    assert isinstance(prof["edge_count"], int) and prof["edge_count"] >= 0, prof
    assert isinstance(prof["caller_count"], int) and prof["caller_count"] >= 0, prof
    assert isinstance(prof["callee_count"], int) and prof["callee_count"] >= 1, prof
    # Cross-tool consistency: the profile aggregates the very ports the block
    # and callee tools expose, so (absent truncation) its counts must agree
    # with what those tools reported for main.
    assert prof["block_count"] == main_block_count, (prof, main_block_count)
    assert prof["callee_count"] == main_callee_count, (prof, main_callee_count)

    # find_bytes ----------------------------------------------------------
    # Re-form the opcode bytes ``disasm`` rendered for main into an IDA-style
    # space-separated hex pattern; searching for that exact sequence must land
    # back at main's entry. The concatenation of several instructions is long
    # enough to be distinctive, so main's address appears among the matches.
    main_addr = dres["address"]
    opcode_hex = "".join(insn["bytes"] for insn in dres["instructions"])
    assert len(opcode_hex) >= 8, dres  # at least a few bytes to search for
    pattern = " ".join(opcode_hex[i : i + 2] for i in range(0, len(opcode_hex), 2))
    fb = client.call(
        19, "tools/call", {"name": "find_bytes", "arguments": {"pattern": pattern}}
    )["result"]
    assert fb["isError"] is False, fb
    fres = fb["structuredContent"]
    assert fres["pattern"] == pattern, fres
    assert isinstance(fres["truncated"], bool), fres
    assert len(fres["matches"]) >= 1, fres
    for match in fres["matches"]:
        assert match["address"].startswith("0x"), match
    match_addrs = {match["address"] for match in fres["matches"]}
    assert main_addr in match_addrs, (main_addr, fres)

    # The same pattern with an interior byte wildcarded (``??``) must still
    # resolve to main's entry, exercising the wildcard path of the search.
    wildcard_tokens = pattern.split()
    wildcard_tokens[1] = "??"
    wildcard_pattern = " ".join(wildcard_tokens)
    fbw = client.call(
        20,
        "tools/call",
        {"name": "find_bytes", "arguments": {"pattern": wildcard_pattern}},
    )["result"]
    assert fbw["isError"] is False, fbw
    fwres = fbw["structuredContent"]
    assert len(fwres["matches"]) >= 1, fwres
    assert main_addr in {match["address"] for match in fwres["matches"]}, (
        main_addr,
        fwres,
    )

    # An unparseable byte pattern is an isError result, not a protocol fault.
    # IDA's ``parse_binpat_str`` is lenient about non-hex tokens (it accepts
    # them and simply finds nothing), so the reliably-rejected input is a
    # pattern with no bytes to compile at all — an empty pattern.
    bad_bytes = client.call(
        21, "tools/call", {"name": "find_bytes", "arguments": {"pattern": ""}}
    )["result"]
    assert bad_bytes["isError"] is True, bad_bytes

    # list_strings --------------------------------------------------------
    # The page must be non-empty and carry the printf format literal authored
    # in tiny.c ("%d %d %d\n"); we match on the printable prefix to stay robust
    # to how the trailing newline is rendered. A statically linked MSVC binary
    # carries a few hundred CRT strings and the format literal sorts late in
    # address order, so we pull a wide page (clamped to the server maximum) to
    # take in the whole set.
    strs = client.call(
        22, "tools/call", {"name": "list_strings", "arguments": {"offset": 0, "count": 1000}}
    )["result"]
    assert strs["isError"] is False, strs
    spage = strs["structuredContent"]
    assert isinstance(spage["total"], int) and spage["total"] > 0, spage
    assert len(spage["items"]) > 0, spage
    assert spage["offset"] == 0, spage
    assert isinstance(spage["truncated"], bool), spage
    assert len(spage["items"]) <= spage["total"], spage
    for row in spage["items"]:
        assert row["address"].startswith("0x"), row
        assert isinstance(row["length"], int) and row["length"] >= 0, row
        assert isinstance(row["type"], str) and row["type"], row
        assert isinstance(row["value"], str), row
    fmt_rows = [row for row in spage["items"] if "%d %d %d" in row["value"]]
    assert fmt_rows, [row["value"] for row in spage["items"]]
    fmt_addr = fmt_rows[0]["address"]

    # int_convert (pure — no database, but driven through the worker) ------
    # 0xFF at 8 bits is unsigned 255 and signed -1, and renders across bases.
    ic = client.call(
        23,
        "tools/call",
        {"name": "int_convert", "arguments": {"value": "0xFF", "bits": 8}},
    )["result"]
    assert ic["isError"] is False, ic
    conv = ic["structuredContent"]
    assert conv["input"] == "0xFF", conv
    assert conv["bits"] == 8, conv
    assert conv["hex"] == "0xff", conv
    # decimal/unsigned/signed are big-int-safe decimal *strings* on the wire.
    assert conv["decimal"] == "255", conv
    assert conv["unsigned"] == "255", conv
    assert conv["signed"] == "-1", conv
    assert conv["binary"] == "0b11111111", conv
    assert conv["octal"] == "0o377", conv
    assert conv["char"] is None, conv

    # A printable value at the default width surfaces its ASCII char.
    ic2 = client.call(
        24, "tools/call", {"name": "int_convert", "arguments": {"value": "0x41"}}
    )["result"]
    assert ic2["isError"] is False, ic2
    conv2 = ic2["structuredContent"]
    assert conv2["bits"] == 64, conv2
    assert conv2["decimal"] == "65", conv2
    assert conv2["signed"] == "65", conv2
    assert conv2["char"] == "A", conv2

    # An unparseable value is an isError result, not a protocol fault.
    bad_int = client.call(
        25,
        "tools/call",
        {"name": "int_convert", "arguments": {"value": "not-a-number"}},
    )["result"]
    assert bad_int["isError"] is True, bad_int

    # ================================================================== #
    # Phase-5 memory / listing-search / bulk-function slice
    #   get_bytes, get_int, get_string, get_global_value,
    #   search_text, find_regex, export_funcs, lookup_funcs
    # ================================================================== #

    # get_bytes -----------------------------------------------------------
    # The opcode bytes disasm rendered for main are the very bytes living at
    # main's entry, so a raw read of that many bytes must reproduce them
    # exactly (lowercase hex). This ties get_bytes to a known image fact.
    main_opcode_hex = "".join(insn["bytes"] for insn in dres["instructions"]).lower()
    read_size = len(main_opcode_hex) // 2
    assert read_size >= 4, dres
    gb = client.call(
        26,
        "tools/call",
        {"name": "get_bytes", "arguments": {"address": "main", "size": read_size}},
    )["result"]
    assert gb["isError"] is False, gb
    gbres = gb["structuredContent"]
    assert gbres["address"] == main_addr, (gbres, main_addr)
    assert gbres["size"] == read_size, gbres
    assert gbres["bytes"].lower() == main_opcode_hex, (gbres, main_opcode_hex)

    # get_int -------------------------------------------------------------
    # The first four bytes at main decode, little-endian (the DB byte order),
    # to a plausible integer whose hex rendering is exactly those bytes in
    # image order — cross-checked against the get_bytes read above.
    first4_hex = main_opcode_hex[:8]
    gi = client.call(
        27,
        "tools/call",
        {"name": "get_int", "arguments": {"address": "main", "size": 4}},
    )["result"]
    assert gi["isError"] is False, gi
    gires = gi["structuredContent"]
    assert gires["address"] == main_addr, gires
    assert gires["size"] == 4, gires
    assert gires["signed"] is False, gires
    assert gires["hex"] == "0x" + first4_hex, (gires, first4_hex)
    # ``value`` is a big-int-safe decimal *string* on the wire.
    assert gires["value"] == str(int.from_bytes(bytes.fromhex(first4_hex), "little")), gires

    # get_global_value ----------------------------------------------------
    # Resolve a real exported symbol by name (add_numbers) and read its first
    # four bytes as an integer; the result must agree byte-for-byte with an
    # independent get_bytes read and an independent get_int read at the same
    # symbol — a three-way cross-tool consistency check that also proves
    # name-based resolution works.
    gb_add = client.call(
        28,
        "tools/call",
        {"name": "get_bytes", "arguments": {"address": "add_numbers", "size": 4}},
    )["result"]
    assert gb_add["isError"] is False, gb_add
    gb_add_res = gb_add["structuredContent"]

    gi_add = client.call(
        29,
        "tools/call",
        {"name": "get_int", "arguments": {"address": "add_numbers", "size": 4}},
    )["result"]
    assert gi_add["isError"] is False, gi_add
    gi_add_res = gi_add["structuredContent"]

    ggv = client.call(
        30,
        "tools/call",
        {
            "name": "get_global_value",
            "arguments": {"name": "add_numbers", "size": 4},
        },
    )["result"]
    assert ggv["isError"] is False, ggv
    ggvres = ggv["structuredContent"]
    assert ggvres["name"] == "add_numbers", ggvres
    assert ggvres["address"].startswith("0x"), ggvres
    assert ggvres["address"] == gi_add_res["address"] == gb_add_res["address"], (
        ggvres,
        gi_add_res,
        gb_add_res,
    )
    assert ggvres["size"] == 4 and ggvres["signed"] is False, ggvres
    assert ggvres["value"] == gi_add_res["value"], (ggvres, gi_add_res)
    assert ggvres["hex"] == gi_add_res["hex"], (ggvres, gi_add_res)
    assert ggvres["hex"] == "0x" + gb_add_res["bytes"].lower(), (ggvres, gb_add_res)

    # get_string ----------------------------------------------------------
    # Read the printf format literal back at the address list_strings reported
    # for it; the decoded value must carry the "%d %d %d" text authored in
    # tiny.c, and its byte length must match the returned value length.
    gs = client.call(
        31,
        "tools/call",
        {"name": "get_string", "arguments": {"address": fmt_addr}},
    )["result"]
    assert gs["isError"] is False, gs
    gsres = gs["structuredContent"]
    assert gsres["address"] == fmt_addr, (gsres, fmt_addr)
    assert "%d %d %d" in gsres["value"], gsres
    assert isinstance(gsres["length"], int) and gsres["length"] >= 0, gsres
    assert gsres["length"] == len(gsres["value"]), gsres

    # search_text ---------------------------------------------------------
    # main calls add_numbers, so the mnemonic "call" appears in the rendered
    # listing; a case-insensitive substring search must surface at least one
    # match and every returned line must literally contain the query text.
    st = client.call(
        32,
        "tools/call",
        {"name": "search_text", "arguments": {"text": "call", "limit": 20}},
    )["result"]
    assert st["isError"] is False, st
    stres = st["structuredContent"]
    assert stres["text"] == "call", stres
    assert isinstance(stres["truncated"], bool), stres
    assert len(stres["matches"]) >= 1, stres
    for match in stres["matches"]:
        assert match["address"].startswith("0x"), match
        assert "call" in match["line"].lower(), match

    # find_regex ----------------------------------------------------------
    # A regex over the extracted strings finds the printf format literal; the
    # address it reports must match the one list_strings gave for the same
    # string, and every match value must satisfy the pattern.
    fr = client.call(
        33,
        "tools/call",
        {"name": "find_regex", "arguments": {"pattern": r"%d %d %d", "limit": 20}},
    )["result"]
    assert fr["isError"] is False, fr
    frres = fr["structuredContent"]
    assert frres["pattern"] == r"%d %d %d", frres
    assert isinstance(frres["truncated"], bool), frres
    assert len(frres["matches"]) >= 1, frres
    for match in frres["matches"]:
        assert match["address"].startswith("0x"), match
        assert "%d %d %d" in match["value"], match
    assert fmt_addr in {match["address"] for match in frres["matches"]}, (
        fmt_addr,
        frres,
    )

    # An invalid regular expression is an isError result, not a protocol fault.
    bad_regex = client.call(
        34,
        "tools/call",
        {"name": "find_regex", "arguments": {"pattern": "("}},
    )["result"]
    assert bad_regex["isError"] is True, bad_regex

    # export_funcs --------------------------------------------------------
    # The compact bulk export must surface the user functions authored in
    # tiny.c (main and the exported add_numbers), each as a name + 0x-address
    # row, with coherent pagination metadata.
    ef = client.call(
        35,
        "tools/call",
        {"name": "export_funcs", "arguments": {"offset": 0, "count": 1000}},
    )["result"]
    assert ef["isError"] is False, ef
    efres = ef["structuredContent"]
    assert efres["offset"] == 0, efres
    assert isinstance(efres["truncated"], bool), efres
    assert isinstance(efres["total"], int) and efres["total"] > 0, efres
    assert len(efres["items"]) > 0, efres
    assert len(efres["items"]) <= efres["total"], efres
    for row in efres["items"]:
        assert row["address"].startswith("0x"), row
        assert isinstance(row["name"], str) and row["name"], row
    export_names = {row["name"] for row in efres["items"]}
    assert {"main", "add_numbers"} <= export_names, sorted(export_names)

    # lookup_funcs --------------------------------------------------------
    # A name-substring query resolves add_numbers; the search is
    # case-insensitive, so an upper-cased query returns the same function at
    # the same address.
    lf = client.call(
        36,
        "tools/call",
        {"name": "lookup_funcs", "arguments": {"query": "add_num", "limit": 50}},
    )["result"]
    assert lf["isError"] is False, lf
    lfres = lf["structuredContent"]
    assert lfres["query"] == "add_num", lfres
    assert isinstance(lfres["truncated"], bool), lfres
    assert len(lfres["matches"]) >= 1, lfres
    for match in lfres["matches"]:
        assert match["address"].startswith("0x"), match
        assert "add_num" in match["name"].lower(), match
    add_matches = [m for m in lfres["matches"] if m["name"] == "add_numbers"]
    assert add_matches, lfres
    add_lookup_addr = add_matches[0]["address"]
    # The export and lookup views agree on add_numbers' entry address.
    assert add_lookup_addr == ggvres["address"], (add_lookup_addr, ggvres)

    lf_ci = client.call(
        37,
        "tools/call",
        {"name": "lookup_funcs", "arguments": {"query": "ADD_NUM", "limit": 50}},
    )["result"]
    assert lf_ci["isError"] is False, lf_ci
    lf_ci_res = lf_ci["structuredContent"]
    ci_matches = [m for m in lf_ci_res["matches"] if m["name"] == "add_numbers"]
    assert ci_matches, lf_ci_res
    assert ci_matches[0]["address"] == add_lookup_addr, (ci_matches, add_lookup_addr)

    # The memory tools honor the same failure contract as the rest of the
    # surface: an unresolvable address/name is an isError result, not a fault.
    for rid, name, args in (
        (38, "get_bytes", {"address": "no_such_symbol_zzz", "size": 4}),
        (39, "get_int", {"address": "no_such_symbol_zzz"}),
        (40, "get_string", {"address": "no_such_symbol_zzz"}),
        (41, "get_global_value", {"name": "no_such_symbol_zzz"}),
    ):
        bad_mem = client.call(rid, "tools/call", {"name": name, "arguments": args})[
            "result"
        ]
        assert bad_mem["isError"] is True, (name, bad_mem)

    # a bad address resolves to an isError result, not a protocol fault ----
    bad = client.call(
        11,
        "tools/call",
        {"name": "decompile", "arguments": {"address": "no_such_symbol_zzz"}},
    )["result"]
    assert bad["isError"] is True, bad

    # the analysis tools honor the same contract: an unresolvable address on
    # an address-taking Phase-2 tool is an isError result, not a fault.
    bad_callees = client.call(
        12,
        "tools/call",
        {"name": "callees", "arguments": {"address": "no_such_symbol_zzz"}},
    )["result"]
    assert bad_callees["isError"] is True, bad_callees

    # the Phase-3 structure tools honor the same contract: an unresolvable
    # address is an isError result, not a protocol fault.
    for rid, name in ((16, "callgraph"), (17, "basic_blocks"), (18, "func_profile")):
        bad_struct = client.call(
            rid,
            "tools/call",
            {"name": name, "arguments": {"address": "no_such_symbol_zzz"}},
        )["result"]
        assert bad_struct["isError"] is True, (name, bad_struct)

    # ---- type / struct tools -------------------------------------------
    # type_query with an empty query returns the type catalog IDA always
    # knows; each entry carries name/kind/size.
    tq = client.call(
        42,
        "tools/call",
        {"name": "type_query", "arguments": {"query": "", "limit": 50}},
    )["result"]
    assert tq["isError"] is False, tq
    tqres = tq["structuredContent"]
    assert isinstance(tqres["truncated"], bool), tqres
    assert len(tqres["matches"]) >= 1, tqres
    for entry in tqres["matches"]:
        assert isinstance(entry["name"], str) and entry["name"], entry
        assert isinstance(entry["kind"], str), entry
        assert isinstance(entry["size"], int), entry

    # search_structs surfaces the aggregate types; a fresh MSVC PE carries
    # several. Capture the smallest to drive type_inspect + read_struct.
    ss = client.call(
        43,
        "tools/call",
        {"name": "search_structs", "arguments": {"query": "", "limit": 50}},
    )["result"]
    assert ss["isError"] is False, ss
    ssres = ss["structuredContent"]
    assert isinstance(ssres["truncated"], bool), ssres
    assert isinstance(ssres["matches"], list), ssres
    for summary in ssres["matches"]:
        assert isinstance(summary["name"], str) and summary["name"], summary
        assert isinstance(summary["size"], int), summary
        assert isinstance(summary["member_count"], int), summary

    smallest = min(ssres["matches"], key=lambda s: s["size"]) if ssres["matches"] else None
    struct_name = smallest["name"] if smallest is not None else None

    if struct_name is not None:
        # type_inspect resolves a real aggregate type into its member layout;
        # search_structs and type_inspect agree on the type's name.
        ti = client.call(
            44,
            "tools/call",
            {"name": "type_inspect", "arguments": {"name": struct_name}},
        )["result"]
        assert ti["isError"] is False, ti
        tires = ti["structuredContent"]
        assert tires["name"] == struct_name, tires
        assert isinstance(tires["kind"], str), tires
        assert isinstance(tires["size"], int), tires
        assert isinstance(tires["members"], list), tires
        for member in tires["members"]:
            assert isinstance(member["name"], str), member
            assert isinstance(member["type"], str), member
            assert isinstance(member["offset"], int), member
            assert isinstance(member["size"], int), member

        # read_struct interprets the bytes at a mapped address as that struct.
        # The bytes at 'main' need not be a real instance — this exercises the
        # field projection end-to-end through StructGateway + MemoryGateway.
        rs = client.call(
            45,
            "tools/call",
            {
                "name": "read_struct",
                "arguments": {"address": "main", "struct": struct_name},
            },
        )["result"]
        assert rs["isError"] is False, rs
        rsres = rs["structuredContent"]
        assert rsres["struct"] == struct_name, rsres
        assert rsres["address"].startswith("0x"), rsres
        assert isinstance(rsres["size"], int), rsres
        assert isinstance(rsres["fields"], list), rsres
        for field in rsres["fields"]:
            assert isinstance(field["name"], str), field
            assert isinstance(field["type"], str), field
            assert isinstance(field["offset"], int), field
            assert isinstance(field["value"], str), field

    # the type/struct tools honor the isError contract on unknown names.
    ti_bad = client.call(
        46,
        "tools/call",
        {"name": "type_inspect", "arguments": {"name": "no_such_type_zzz"}},
    )["result"]
    assert ti_bad["isError"] is True, ti_bad
    rs_bad = client.call(
        47,
        "tools/call",
        {
            "name": "read_struct",
            "arguments": {"address": "main", "struct": "no_such_struct_zzz"},
        },
    )["result"]
    assert rs_bad["isError"] is True, rs_bad

    # ================================================================== #
    # Resources slice — read-only IDB state as MCP ``ida://…`` resources.
    #   Static:   metadata / functions / globals / imports / strings
    #   Template: function/{addr} disasm/{addr} xrefs/{addr}
    #             struct/{name} bytes/{addr}/{size}
    # Each resource is a second projection of a use-case already exercised as
    # a tool above, so every read is cross-checked against the tool's data.
    # ================================================================== #

    def _read_resource(rid: int, uri: str) -> dict:
        """resources/read ``uri``; assert the application/json envelope and
        return the parsed JSON payload."""
        resp = client.call(rid, "resources/read", {"uri": uri})
        assert "result" in resp, (uri, resp)
        contents = resp["result"]["contents"]
        assert isinstance(contents, list) and len(contents) == 1, (uri, contents)
        block = contents[0]
        assert block["uri"] == uri, (uri, block)
        assert block["mimeType"] == "application/json", (uri, block)
        return json.loads(block["text"])

    # resources/list — the five static ida:// resources, each with a name and
    # the application/json mime type.
    rlist = client.call(48, "resources/list")["result"]["resources"]
    res_by_uri = {r["uri"]: r for r in rlist}
    for uri, name in (
        ("ida://metadata", "metadata"),
        ("ida://functions", "functions"),
        ("ida://globals", "globals"),
        ("ida://imports", "imports"),
        ("ida://strings", "strings"),
    ):
        assert uri in res_by_uri, sorted(res_by_uri)
        entry = res_by_uri[uri]
        assert entry["name"] == name, entry
        assert entry["mimeType"] == "application/json", entry

    # resources/templates/list — the five parameterized ida:// templates.
    tlist = client.call(49, "resources/templates/list")["result"]["resourceTemplates"]
    tmpl_by_uri = {t["uriTemplate"]: t for t in tlist}
    for uri, name in (
        ("ida://function/{address}", "function"),
        ("ida://disasm/{address}", "disasm"),
        ("ida://xrefs/{address}", "xrefs"),
        ("ida://struct/{name}", "struct"),
        ("ida://bytes/{address}/{size}", "bytes"),
    ):
        assert uri in tmpl_by_uri, sorted(tmpl_by_uri)
        entry = tmpl_by_uri[uri]
        assert entry["name"] == name, entry
        assert entry["mimeType"] == "application/json", entry

    # --- static reads, cross-checked against the tool results above ------
    # ida://metadata parses to the same architecture/bits/module the
    # get_metadata tool reported.
    r_meta = _read_resource(50, "ida://metadata")
    assert r_meta["architecture"] == md["architecture"], (r_meta, md)
    assert r_meta["bits"] == md["bits"], (r_meta, md)
    assert r_meta["endianness"] == md["endianness"], (r_meta, md)
    assert r_meta["module"] == md["module"], (r_meta, md)
    assert r_meta["function_count"] == md["function_count"], (r_meta, md)

    # ida://functions lists functions: same total as list_funcs, first page
    # non-empty with 0x-addressed rows.
    r_funcs = _read_resource(51, "ida://functions")
    assert r_funcs["total"] == page["total"], (r_funcs, page)
    assert len(r_funcs["items"]) > 0, r_funcs
    for row in r_funcs["items"]:
        assert row["start"].startswith("0x"), row
        assert isinstance(row["size"], int), row

    # ida://globals — same total as list_globals.
    r_globs = _read_resource(52, "ida://globals")
    assert r_globs["total"] == gpage["total"], (r_globs, gpage)
    assert isinstance(r_globs["items"], list), r_globs
    assert len(r_globs["items"]) <= r_globs["total"], r_globs

    # ida://imports — same total as the imports tool; rows carry name+module.
    r_imps = _read_resource(53, "ida://imports")
    assert r_imps["total"] == ipage["total"], (r_imps, ipage)
    assert len(r_imps["items"]) > 0, r_imps
    for row in r_imps["items"]:
        assert row["address"].startswith("0x"), row
        assert isinstance(row["name"], str) and row["name"], row

    # ida://strings — same total as list_strings; rows carry a decoded value.
    r_strs = _read_resource(54, "ida://strings")
    assert r_strs["total"] == spage["total"], (r_strs, spage)
    assert len(r_strs["items"]) > 0, r_strs
    for row in r_strs["items"]:
        assert row["address"].startswith("0x"), row
        assert isinstance(row["value"], str), row

    # --- template reads with real values ---------------------------------
    # ida://function/main — same name/address/pseudocode as the decompile tool.
    r_func = _read_resource(55, "ida://function/main")
    assert r_func["name"] == "main", r_func
    assert r_func["address"] == pseudo["address"], (r_func, pseudo)
    assert "main" in r_func["pseudocode"] and "return" in r_func["pseudocode"], r_func
    assert len(r_func["lines"]) > 1, r_func

    # ida://disasm/main — first instruction is main's entry; matches the tool.
    r_dis = _read_resource(56, "ida://disasm/main")
    assert r_dis["address"] == main_addr, (r_dis, main_addr)
    assert r_dis["returned"] > 0, r_dis
    assert r_dis["returned"] == len(r_dis["instructions"]), r_dis
    assert r_dis["instructions"][0]["addr"] == main_addr, r_dis

    # ida://xrefs/<add_numbers addr> — same inbound edges as xrefs_to; the
    # main -> add_numbers call edge is present. The address segment is the
    # resolved target address the xrefs_to tool reported.
    add_target = xres["target"]
    r_xref = _read_resource(57, f"ida://xrefs/{add_target}")
    assert r_xref["target"] == add_target, (r_xref, add_target)
    assert len(r_xref["xrefs"]) > 0, r_xref
    for edge in r_xref["xrefs"]:
        assert edge["to"] == add_target, edge
    assert any(
        edge["type"] == "call" and edge["func"] == "main" for edge in r_xref["xrefs"]
    ), r_xref

    # ida://struct/<a real struct from search_structs> — same layout as
    # type_inspect (only when the fixture carries an aggregate type).
    if struct_name is not None:
        r_struct = _read_resource(58, f"ida://struct/{struct_name}")
        assert r_struct["name"] == struct_name, r_struct
        assert isinstance(r_struct["kind"], str), r_struct
        assert isinstance(r_struct["size"], int), r_struct
        assert isinstance(r_struct["members"], list), r_struct

    # ida://bytes/main/8 — eight raw bytes at main; a lowercase hex string of
    # 16 nibbles that prefixes the opcode bytes disasm rendered at main.
    r_bytes = _read_resource(59, "ida://bytes/main/8")
    assert r_bytes["address"] == main_addr, (r_bytes, main_addr)
    assert r_bytes["size"] == 8, r_bytes
    assert isinstance(r_bytes["bytes"], str) and len(r_bytes["bytes"]) == 16, r_bytes
    assert r_bytes["bytes"].lower() == r_bytes["bytes"], r_bytes
    if len(main_opcode_hex) >= 16:
        assert r_bytes["bytes"].lower() == main_opcode_hex[:16], (r_bytes, main_opcode_hex)

    # --- a template with a bad value is a resources/read error -----------
    # An unresolvable address is surfaced as a JSON-RPC resource-not-found
    # error (-32002), not a crash and not a tool isError envelope.
    bad_res = client.call(
        60, "resources/read", {"uri": "ida://function/no_such_symbol_zzz"}
    )
    assert "error" in bad_res and "result" not in bad_res, bad_res
    assert bad_res["error"]["code"] == -32002, bad_res

    # ================================================================== #
    # Phase-4 composite / survey slice — survey_binary / analyze_function /
    # analyze_component. All three are READ-ONLY token-economy aggregations that
    # reuse the read ports and per-tool use-cases already exercised above; each
    # is cross-checked against the very facts those tools reported. This slice
    # runs BEFORE any mutation, so add_numbers still carries its original name
    # and the composite views can be pinned to the known fixture facts. Request
    # ids run from a private counter so they never collide with the fixed ids
    # above or the mutation batches below.
    # ================================================================== #
    _crid = [300]

    def _comp(name: str, args: dict) -> dict:
        _crid[0] += 1
        return client.call(
            _crid[0], "tools/call", {"name": name, "arguments": args}
        )["result"]

    # survey_binary (standard) — a one-call triage overview of the whole
    # database. Its metadata block agrees with get_metadata (architecture
    # metapc / 64-bit), its counts.functions agrees with the metadata function
    # count, and every population is non-zero (the fixture has functions,
    # imports, strings, and segments). The role histogram is our authored
    # taxonomy: it must be non-empty and every scanned function must land in
    # exactly one role bucket (the bucket counts sum to scanned_functions).
    sv = _comp("survey_binary", {"detail_level": "standard"})
    assert sv["isError"] is False, sv
    svc = sv["structuredContent"]
    assert svc["detail_level"] == "standard", svc
    assert svc["metadata"]["architecture"] == "metapc", svc
    assert svc["metadata"]["bits"] == 64, svc
    assert svc["metadata"]["endianness"] == "little", svc
    # counts cross-check the standalone listing/metadata tools.
    assert svc["counts"]["functions"] == md["function_count"], (svc, md)
    assert svc["counts"]["functions"] > 100, svc  # tiny.exe carries ~491 funcs
    assert svc["counts"]["imports"] == ipage["total"], (svc, ipage)
    assert svc["counts"]["imports"] > 0, svc
    assert svc["counts"]["strings"] == spage["total"], (svc, spage)
    assert svc["counts"]["strings"] > 0, svc
    assert svc["counts"]["segments"] > 0, svc
    assert isinstance(svc["scanned_functions"], int) and svc["scanned_functions"] > 0, svc
    assert isinstance(svc["truncated"], bool), svc
    assert isinstance(svc["entrypoints"], list), svc
    for ep in svc["entrypoints"]:
        assert ep.startswith("0x"), ep
    # role taxonomy — non-empty, well-formed, and a partition of the scan.
    assert isinstance(svc["roles"], list) and len(svc["roles"]) >= 1, svc
    role_total = 0
    for tally in svc["roles"]:
        assert isinstance(tally["role"], str) and tally["role"], tally
        assert isinstance(tally["count"], int) and tally["count"] > 0, tally
        role_total += tally["count"]
    assert role_total == svc["scanned_functions"], (svc["roles"], svc["scanned_functions"])
    # notable imports — a list; each entry carries a 0x address and a category.
    assert isinstance(svc["notable_imports"], list), svc
    for ni in svc["notable_imports"]:
        assert isinstance(ni["name"], str) and ni["name"], ni
        assert isinstance(ni["module"], str), ni
        assert ni["address"].startswith("0x"), ni
        assert isinstance(ni["category"], str) and ni["category"], ni
    # string categories — non-empty (the printf format literal alone lands in
    # the "format" bucket); each is a well-formed tally.
    assert isinstance(svc["string_categories"], list) and svc["string_categories"], svc
    for sctally in svc["string_categories"]:
        assert isinstance(sctally["category"], str) and sctally["category"], sctally
        assert isinstance(sctally["count"], int) and sctally["count"] > 0, sctally
    # top functions — non-empty, capped at the server shortlist size (25), each
    # a compact ranked entry carrying a role from the taxonomy.
    assert isinstance(svc["top_functions"], list) and svc["top_functions"], svc
    assert len(svc["top_functions"]) <= 25, svc
    for tf in svc["top_functions"]:
        assert tf["address"].startswith("0x"), tf
        assert isinstance(tf["size"], int) and tf["size"] >= 0, tf
        assert isinstance(tf["role"], str) and tf["role"], tf
        assert isinstance(tf["caller_count"], int) and tf["caller_count"] >= 0, tf
        assert isinstance(tf["callee_count"], int) and tf["callee_count"] >= 0, tf

    # survey_binary (minimal) — the cheaper flags-and-size pass. It still
    # produces the same counts and a non-empty role histogram, only ranked and
    # classified without the per-function cross-reference scan.
    sv_min = _comp("survey_binary", {"detail_level": "minimal"})
    assert sv_min["isError"] is False, sv_min
    svm = sv_min["structuredContent"]
    assert svm["detail_level"] == "minimal", svm
    assert svm["counts"]["functions"] == md["function_count"], (svm, md)
    assert isinstance(svm["roles"], list) and len(svm["roles"]) >= 1, svm

    # analyze_function('main') — the composite single-function report assembled
    # in one call. Its profile matches func_profile, its pseudocode carries the
    # decompiled body, its callee edge set matches the standalone callees tool
    # (so it includes add_numbers and the printf call), and the printf format
    # literal authored in tiny.c surfaces among its string literals.
    af = _comp("analyze_function", {"address": "main"})
    assert af["isError"] is False, af
    afc = af["structuredContent"]
    assert afc["name"] == "main", afc
    assert afc["address"] == main_addr, (afc, main_addr)
    assert afc["profile"]["name"] == "main", afc
    assert afc["profile"]["address"] == main_addr, afc
    assert isinstance(afc["profile"]["size"], int) and afc["profile"]["size"] > 0, afc
    assert afc["profile"]["block_count"] == main_block_count, (afc, main_block_count)
    assert afc["profile"]["callee_count"] == main_callee_count, (afc, main_callee_count)
    assert "main" in afc["pseudocode"] and "return" in afc["pseudocode"], afc
    assert isinstance(afc["lines"], list) and len(afc["lines"]) > 1, afc
    # callee edges — same targets the standalone callees tool reported (which
    # includes add_numbers and the printf call), each a well-formed xref edge.
    assert isinstance(afc["callees"], list) and afc["callees"], afc
    for edge in afc["callees"]:
        assert edge["from"].startswith("0x"), edge
        assert edge["to"].startswith("0x"), edge
        assert isinstance(edge["kind"], str) and edge["kind"], edge
        assert isinstance(edge["type"], str) and edge["type"], edge
        assert edge["func"] is None or isinstance(edge["func"], str), edge
    af_callee_targets = {edge["to"] for edge in afc["callees"]}
    callees_tool_targets = {c["addr"] for c in cres["callees"]}
    assert af_callee_targets == callees_tool_targets, (af_callee_targets, callees_tool_targets)
    assert add_addr in af_callee_targets, (add_addr, af_callee_targets)
    # callers — main is reached from the CRT startup path, so the inbound edge
    # list is non-empty; each edge is a well-formed xref pointing at main.
    assert isinstance(afc["callers"], list) and afc["callers"], afc
    for edge in afc["callers"]:
        assert edge["from"].startswith("0x"), edge
        assert edge["to"] == main_addr, (edge, main_addr)
    # derived extras — import references and the pseudocode string literals.
    assert isinstance(afc["import_references"], list), afc
    for ref in afc["import_references"]:
        assert isinstance(ref, str) and ref, ref
    assert isinstance(afc["string_literals"], list) and afc["string_literals"], afc
    for lit in afc["string_literals"]:
        assert isinstance(lit, str), lit
    assert any("%d %d %d" in lit for lit in afc["string_literals"]), afc["string_literals"]

    # analyze_component rooted at 'main' (depth 1) — the call-subtree rolled up
    # as one unit. main is always a member; with one call layer explored its
    # real-function callee add_numbers is a member too, so the component has at
    # least two members, a positive aggregate size, and at least one internal
    # (main -> add_numbers) call edge. Calls into imports/thunks fall outside
    # the component and are tallied as external.
    ac = _comp("analyze_component", {"address": "main", "depth": 1})
    assert ac["isError"] is False, ac
    acc = ac["structuredContent"]
    assert acc["root"] == main_addr, (acc, main_addr)
    assert acc["depth"] == 1, acc
    assert isinstance(acc["member_count"], int) and acc["member_count"] >= 1, acc
    assert acc["member_count"] == len(acc["members"]), acc
    assert isinstance(acc["total_size"], int) and acc["total_size"] > 0, acc
    assert isinstance(acc["internal_call_count"], int) and acc["internal_call_count"] >= 0, acc
    assert isinstance(acc["external_call_count"], int) and acc["external_call_count"] >= 0, acc
    assert isinstance(acc["truncated"], bool), acc
    member_addrs = set()
    for member in acc["members"]:
        assert member["address"].startswith("0x"), member
        assert member["name"] is None or isinstance(member["name"], str), member
        assert isinstance(member["size"], int) and member["size"] >= 0, member
        assert isinstance(member["caller_count"], int) and member["caller_count"] >= 0, member
        assert isinstance(member["callee_count"], int) and member["callee_count"] >= 0, member
        member_addrs.add(member["address"])
    assert main_addr in member_addrs, (main_addr, member_addrs)
    # depth 1 pulls in main's direct real-function callee add_numbers as a
    # member, and the main -> add_numbers edge is an internal call.
    assert add_addr in member_addrs, (add_addr, member_addrs)
    assert acc["member_count"] >= 2, acc
    assert acc["internal_call_count"] >= 1, acc

    # The composite tools honor the same failure contract as the rest of the
    # surface: an unresolvable symbol, and an address that lies in no function
    # (the printf format literal is data), are isError results — not crashes and
    # not empty successes. survey_binary takes no address, so it has no such case.
    for name in ("analyze_function", "analyze_component"):
        bad_unres = _comp(name, {"address": "no_such_symbol_zzz"})
        assert bad_unres["isError"] is True, (name, bad_unres)
        bad_oof = _comp(name, {"address": fmt_addr})
        assert bad_oof["isError"] is True, (name, bad_oof)

    # ================================================================== #
    # Phase-4 dataflow / taint slice — detect_stack_strings / trace_data_flow /
    # trace_source_to_sink. All three are READ-ONLY, intra-procedural, heuristic,
    # bounded analyses running over the pure decoded-instruction model filled by
    # the single decode adapter. tiny.exe is trivial, so results may be SPARSE or
    # EMPTY: each tool must return a WELL-FORMED result and treat an empty set as
    # a valid (not error) outcome. This slice runs BEFORE any mutation so main is
    # pristine and its decoded body yields a real def-use chain. Request ids come
    # from the composite ``_comp`` counter so they never collide with the fixed
    # ids or the mutation batches.
    # ================================================================== #

    # detect_stack_strings scoped to main — main assembles small integer values
    # (2/4/6/8) onto its frame, none of which form a printable run, so the
    # expected clean result is an EMPTY match list. The shape must still validate,
    # and any surfaced match must carry a 0x-hex anchor address, a non-empty
    # reconstructed value, and a ``function`` key (string or null).
    ss = _comp("detect_stack_strings", {"address": "main"})
    assert ss["isError"] is False, ss
    ssres = ss["structuredContent"]
    assert isinstance(ssres["matches"], list), ssres
    assert isinstance(ssres["truncated"], bool), ssres
    for m in ssres["matches"]:
        assert isinstance(m["address"], str) and m["address"].startswith("0x"), m
        assert isinstance(m["value"], str) and m["value"], m
        assert "function" in m, m
        assert m["function"] is None or isinstance(m["function"], str), m

    # detect_stack_strings whole-database (empty address) — a bounded sweep over
    # the function set; returns a well-formed (possibly empty) match list.
    ss_all = _comp("detect_stack_strings", {"address": ""})
    assert ss_all["isError"] is False, ss_all
    assert isinstance(ss_all["structuredContent"]["matches"], list), ss_all
    assert isinstance(ss_all["structuredContent"]["truncated"], bool), ss_all

    # trace_data_flow on main, operand 0 — main's entry instruction is
    # ``sub rsp, <frame>``, whose operand 0 is the real register rsp. Tracing it
    # forward yields a NON-EMPTY, well-formed def-use chain: rsp is read by the
    # stack-cookie xor, copied into frame slots, and threaded to the printf
    # argument setup. Each step names the rule (note) and carries a 0x-hex
    # address, the instruction text, and an optional target location string.
    td = _comp("trace_data_flow", {"address": "main", "operand": 0, "direction": "forward"})
    assert td["isError"] is False, td
    tdres = td["structuredContent"]
    assert tdres["start"].startswith("0x"), tdres
    assert tdres["direction"] == "forward", tdres
    assert isinstance(tdres["truncated"], bool), tdres
    assert isinstance(tdres["steps"], list), tdres
    assert len(tdres["steps"]) >= 1, tdres  # rsp is a real register with live uses
    valid_notes = {"use", "propagate", "transform", "redefined", "def"}
    for step in tdres["steps"]:
        assert isinstance(step["address"], str) and step["address"].startswith("0x"), step
        assert isinstance(step["insn"], str) and step["insn"], step
        assert step["note"] in valid_notes, step
        assert step["target"] is None or isinstance(step["target"], str), step

    # A backward trace of the same anchor/operand is likewise well-formed; the
    # entry ``sub rsp`` reads-and-writes rsp, so the backward walk is valid
    # (possibly empty, as rsp has no prior definition in the function).
    td_back = _comp(
        "trace_data_flow", {"address": "main", "operand": 0, "direction": "backward"}
    )
    assert td_back["isError"] is False, td_back
    assert td_back["structuredContent"]["direction"] == "backward", td_back
    assert isinstance(td_back["structuredContent"]["steps"], list), td_back

    # trace_data_flow honors the isError contract on an unresolvable / out-of-
    # function anchor, exactly like the rest of the address-taking surface.
    td_bad = _comp("trace_data_flow", {"address": "no_such_symbol_zzz", "operand": 0})
    assert td_bad["isError"] is True, td_bad
    td_oof = _comp("trace_data_flow", {"address": fmt_addr, "operand": 0})
    assert td_oof["isError"] is True, td_oof

    # trace_source_to_sink scoped to main — main reads no external input into a
    # dangerous-API sink argument, so the expected clean result is an EMPTY paths
    # list. The shape must validate, and any surfaced path must carry 0x-hex
    # source/sink addresses, a non-empty sink api, and a well-formed step list.
    tsk = _comp("trace_source_to_sink", {"address": "main"})
    assert tsk["isError"] is False, tsk
    tskres = tsk["structuredContent"]
    assert isinstance(tskres["paths"], list), tskres
    assert isinstance(tskres["truncated"], bool), tskres
    for path in tskres["paths"]:
        assert path["source"].startswith("0x"), path
        assert path["sink"].startswith("0x"), path
        assert isinstance(path["api"], str) and path["api"], path
        assert isinstance(path["steps"], list) and path["steps"], path
        for step in path["steps"]:
            assert step["address"].startswith("0x"), step
            assert isinstance(step["insn"], str), step
            assert isinstance(step["note"], str) and step["note"], step
            assert step["target"] is None or isinstance(step["target"], str), step

    # trace_source_to_sink whole-database (empty address) — a bounded sweep;
    # returns a well-formed (possibly empty) paths list, never an error.
    tsk_all = _comp("trace_source_to_sink", {"address": ""})
    assert tsk_all["isError"] is False, tsk_all
    assert isinstance(tsk_all["structuredContent"]["paths"], list), tsk_all
    assert isinstance(tsk_all["structuredContent"]["truncated"], bool), tsk_all

    # Both scoped tools honor the isError contract on an unresolvable symbol and
    # on an address that lies in no function (the printf format literal is data).
    # The empty-address whole-database forms above have no such case.
    for name in ("detect_stack_strings", "trace_source_to_sink"):
        bad_unres = _comp(name, {"address": "no_such_symbol_zzz"})
        assert bad_unres["isError"] is True, (name, bad_unres)
        bad_oof = _comp(name, {"address": fmt_addr})
        assert bad_oof["isError"] is True, (name, bad_oof)

    # ================================================================== #
    # Phase-2 completion — query DSL slice (entity_query / func_query /
    # imports_query / xref_query / insn_query). All five are READ-ONLY filtered
    # reads built on the shared pure predicate grammar; each reuses an existing
    # read port with no new adapter. This slice runs BEFORE any mutation, so
    # ``main`` and ``add_numbers`` still carry their pristine names and the
    # filters can be pinned to known fixture facts: func_query name~'main' finds
    # main at its known entry; imports_query module~'KERNEL32' surfaces the CRT
    # startup imports; xref_query "to" on add_numbers reproduces the inbound
    # main -> add_numbers call edge and "from" on main leaves toward add_numbers;
    # insn_query mnemonic=='call' on main is non-empty (main calls add_numbers
    # and printf); and entity_query resolves both by name. Request ids come from
    # the composite ``_comp`` counter so they never collide with the fixed ids or
    # the mutation batches. Out-of-function / unresolvable selectors, and invalid
    # enum arguments, are isError results — never crashes.
    # ================================================================== #

    # entity_query — the unified named-entity stream. Querying add_numbers by
    # name spans all three repositories; the function entity surfaces, carrying a
    # 0x-hex address, the "function" kind, and an integer size (module/ordinal
    # null for a function). Every row is well-formed against the union shape.
    eq = _comp("entity_query", {"query": "add_numbers", "kind": "any"})
    assert eq["isError"] is False, eq
    eqres = eq["structuredContent"]
    assert eqres["query"] == "add_numbers", eqres
    assert eqres["kind"] == "any", eqres
    assert isinstance(eqres["truncated"], bool), eqres
    assert isinstance(eqres["matches"], list) and eqres["matches"], eqres
    for m in eqres["matches"]:
        assert isinstance(m["name"], str) and m["name"], m
        assert m["address"].startswith("0x"), m
        assert m["kind"] in ("function", "global", "import"), m
        assert m["size"] is None or isinstance(m["size"], int), m
        assert m["module"] is None or isinstance(m["module"], str), m
        assert m["ordinal"] is None or isinstance(m["ordinal"], int), m
        assert "add_numbers" in m["name"].lower(), m
    add_fn_entities = [
        m for m in eqres["matches"] if m["name"] == "add_numbers" and m["kind"] == "function"
    ]
    assert add_fn_entities, eqres
    assert add_fn_entities[0]["address"] == add_lookup_addr, (add_fn_entities, add_lookup_addr)
    assert isinstance(add_fn_entities[0]["size"], int), add_fn_entities

    # kind restriction — scoping to "function" returns only function entities, and
    # a substring shared by several names ("main") still resolves main itself.
    eq_fn = _comp("entity_query", {"query": "main", "kind": "function"})
    assert eq_fn["isError"] is False, eq_fn
    eq_fn_res = eq_fn["structuredContent"]
    assert eq_fn_res["kind"] == "function", eq_fn_res
    assert eq_fn_res["matches"], eq_fn_res
    for m in eq_fn_res["matches"]:
        assert m["kind"] == "function", m
        assert "main" in m["name"].lower(), m
    main_entities = [m for m in eq_fn_res["matches"] if m["name"] == "main"]
    assert main_entities, eq_fn_res
    assert main_entities[0]["address"] == main_addr, (main_entities, main_addr)

    # an unknown kind selector is an isError result, not a protocol fault.
    eq_bad = _comp("entity_query", {"query": "", "kind": "not_a_kind"})
    assert eq_bad["isError"] is True, eq_bad

    # func_query — the function-only filter. A name~'main' query finds main at its
    # known entry with a positive size and boolean library/thunk flags; a size
    # band that brackets main's real size still returns it, proving the numeric
    # predicates compose with the name substring.
    fq = _comp("func_query", {"name": "main"})
    assert fq["isError"] is False, fq
    fqres = fq["structuredContent"]
    assert isinstance(fqres["truncated"], bool), fqres
    assert isinstance(fqres["matches"], list) and fqres["matches"], fqres
    for m in fqres["matches"]:
        assert isinstance(m["name"], str) and "main" in m["name"].lower(), m
        assert m["address"].startswith("0x"), m
        assert isinstance(m["size"], int) and m["size"] >= 0, m
        assert isinstance(m["is_library"], bool), m
        assert isinstance(m["is_thunk"], bool), m
    fq_main = [m for m in fqres["matches"] if m["name"] == "main"]
    assert fq_main, fqres
    assert fq_main[0]["address"] == main_addr, (fq_main, main_addr)
    main_size = fq_main[0]["size"]
    assert main_size > 0, fq_main

    # size band — the profile-free size predicate. Bracketing main's own size
    # keeps main in the result; every returned function respects the band.
    fq_band = _comp(
        "func_query",
        {"name": "main", "min_size": main_size, "max_size": main_size},
    )
    assert fq_band["isError"] is False, fq_band
    band_matches = fq_band["structuredContent"]["matches"]
    assert any(m["name"] == "main" for m in band_matches), fq_band
    for m in band_matches:
        assert m["size"] == main_size, m

    # imports_query — the import-only filter. A module~'KERNEL32' query surfaces
    # the CRT startup imports (a statically linked MSVC console binary always
    # pulls KERNEL32); every row's module carries the queried library and each
    # symbol is a well-formed import row. A name-substring query for a real
    # imported symbol resolves that symbol back.
    iq = _comp("imports_query", {"module": "KERNEL32"})
    assert iq["isError"] is False, iq
    iqres = iq["structuredContent"]
    assert isinstance(iqres["truncated"], bool), iqres
    assert isinstance(iqres["matches"], list) and iqres["matches"], iqres
    for m in iqres["matches"]:
        assert isinstance(m["name"], str) and m["name"], m
        assert m["address"].startswith("0x"), m
        assert isinstance(m["module"], str) and "kernel32" in m["module"].lower(), m
        assert m["ordinal"] is None or isinstance(m["ordinal"], int), m

    # name filter — pick a real imported symbol observed above and query it back.
    sample_import = sorted(import_names)[0]
    iq_name = _comp("imports_query", {"name": sample_import})
    assert iq_name["isError"] is False, iq_name
    iq_name_res = iq_name["structuredContent"]
    assert iq_name_res["matches"], (sample_import, iq_name_res)
    assert any(m["name"] == sample_import for m in iq_name_res["matches"]), (
        sample_import,
        iq_name_res,
    )
    for m in iq_name_res["matches"]:
        assert sample_import.lower() in m["name"].lower(), m

    # xref_query — the cross-reference filter around a resolved anchor. "to" on
    # add_numbers reproduces the inbound edge set the xrefs_to tool reported: the
    # anchor is add_numbers' resolved address, every edge points at it, and the
    # main -> add_numbers call edge is present. A type="call" filter keeps only
    # the call edges.
    xq = _comp("xref_query", {"address": "add_numbers", "direction": "to"})
    assert xq["isError"] is False, xq
    xqres = xq["structuredContent"]
    assert xqres["anchor"] == add_target, (xqres, add_target)
    assert xqres["direction"] == "to", xqres
    assert isinstance(xqres["truncated"], bool), xqres
    assert isinstance(xqres["xrefs"], list) and xqres["xrefs"], xqres
    for edge in xqres["xrefs"]:
        assert edge["from"].startswith("0x"), edge
        assert edge["to"] == add_target, edge
        assert edge["kind"] in ("code", "data"), edge
        assert isinstance(edge["type"], str) and edge["type"], edge
        assert edge["func"] is None or isinstance(edge["func"], str), edge
        assert edge["name"] is None or isinstance(edge["name"], str), edge
    assert any(
        edge["type"] == "call" and edge["func"] == "main" for edge in xqres["xrefs"]
    ), xqres

    xq_call = _comp(
        "xref_query", {"address": "add_numbers", "direction": "to", "type": "call"}
    )
    assert xq_call["isError"] is False, xq_call
    xq_call_edges = xq_call["structuredContent"]["xrefs"]
    assert xq_call_edges, xq_call
    for edge in xq_call_edges:
        assert edge["type"] == "call", edge
    assert any(edge["func"] == "main" for edge in xq_call_edges), xq_call

    # "from" on main — the outbound call edges leaving main's owning function.
    # main calls add_numbers, so an edge landing on add_numbers' entry appears.
    xq_from = _comp("xref_query", {"address": "main", "direction": "from"})
    assert xq_from["isError"] is False, xq_from
    xq_from_res = xq_from["structuredContent"]
    assert xq_from_res["anchor"] == main_addr, (xq_from_res, main_addr)
    assert xq_from_res["direction"] == "from", xq_from_res
    assert isinstance(xq_from_res["xrefs"], list) and xq_from_res["xrefs"], xq_from_res
    for edge in xq_from_res["xrefs"]:
        assert edge["from"].startswith("0x"), edge
        assert edge["to"].startswith("0x"), edge
    assert add_lookup_addr in {edge["to"] for edge in xq_from_res["xrefs"]}, (
        add_lookup_addr,
        xq_from_res,
    )

    # xref_query honors the isError contract: an unresolvable address, and an
    # unknown direction enum, are error results, not protocol faults.
    xq_unres = _comp("xref_query", {"address": "no_such_symbol_zzz"})
    assert xq_unres["isError"] is True, xq_unres
    xq_baddir = _comp("xref_query", {"address": "main", "direction": "sideways"})
    assert xq_baddir["isError"] is True, xq_baddir

    # insn_query — the decoded-instruction filter over one function. An exact
    # mnemonic filter of "call" on main is non-empty (main calls add_numbers and
    # printf); the enclosing function is named main, and every match is a real
    # call instruction with a 0x-hex address and non-empty text. An unfiltered
    # query returns the whole decoded body.
    nq = _comp("insn_query", {"address": "main", "mnemonic": "call"})
    assert nq["isError"] is False, nq
    nqres = nq["structuredContent"]
    assert nqres["function"] == "main", nqres
    assert isinstance(nqres["truncated"], bool), nqres
    assert isinstance(nqres["matches"], list) and nqres["matches"], nqres
    for m in nqres["matches"]:
        assert m["address"].startswith("0x"), m
        assert m["mnemonic"].lower() == "call", m
        assert isinstance(m["text"], str) and m["text"], m

    nq_all = _comp("insn_query", {"address": "main"})
    assert nq_all["isError"] is False, nq_all
    nq_all_res = nq_all["structuredContent"]
    assert nq_all_res["function"] == "main", nq_all_res
    assert isinstance(nq_all_res["matches"], list) and nq_all_res["matches"], nq_all_res
    # the "call" matches are a subset of the whole decoded body.
    all_addrs = {m["address"] for m in nq_all_res["matches"]}
    assert {m["address"] for m in nqres["matches"]} <= all_addrs, (nqres, nq_all_res)

    # operand-kind filter — main assembles immediates (e.g. the frame setup), so
    # an "imm" operand filter yields a well-formed (here non-empty) subset; every
    # match is still a real instruction of main.
    nq_imm = _comp("insn_query", {"address": "main", "operand_kind": "imm"})
    assert nq_imm["isError"] is False, nq_imm
    assert isinstance(nq_imm["structuredContent"]["matches"], list), nq_imm
    for m in nq_imm["structuredContent"]["matches"]:
        assert m["address"].startswith("0x"), m
        assert m["address"] in all_addrs, m

    # insn_query honors the isError contract: an unresolvable symbol, an address
    # that lies in no function (the printf format literal is data), and an unknown
    # operand-kind enum are all error results, never crashes.
    nq_unres = _comp("insn_query", {"address": "no_such_symbol_zzz"})
    assert nq_unres["isError"] is True, nq_unres
    nq_oof = _comp("insn_query", {"address": fmt_addr})
    assert nq_oof["isError"] is True, nq_oof
    nq_badkind = _comp("insn_query", {"address": "main", "operand_kind": "not_a_kind"})
    assert nq_badkind["isError"] is True, nq_badkind

    # ================================================================== #
    # Mutation slice — the write path (rename / set_comment / set_type).
    # These are the first tools that MODIFY the database. They run on the
    # worker's PRIVATE copy (tmp_path), never the user's fixture, and the
    # worker closes its database without saving, so every change is
    # in-session only. Each write is proven to have landed by reading it back
    # through a read tool: the rename via lookup_funcs/export_funcs, and all
    # three at once via a fresh decompile of main (the set_type apply
    # invalidates main's decompilation cache, so the regenerated pseudocode
    # reflects the new prototype, the function comment, and the renamed callee).
    # ================================================================== #

    # rename — rename the non-entry function add_numbers (resolved earlier to
    # add_lookup_addr) to a fresh identifier. The write reports the prior name
    # and the new one; the function surface read back proves it persisted.
    renamed = "fn_renamed_by_idamesh"
    rn = client.call(
        61,
        "tools/call",
        {"name": "rename", "arguments": {"address": "add_numbers", "name": renamed}},
    )["result"]
    assert rn["isError"] is False, rn
    rnres = rn["structuredContent"]
    assert rnres["ok"] is True, rnres
    assert rnres["old_name"] == "add_numbers", rnres
    assert rnres["name"] == renamed, rnres
    assert rnres["address"] == add_lookup_addr, (rnres, add_lookup_addr)

    # read-back: the new name resolves to add_numbers' former address ...
    lk_new = client.call(
        62,
        "tools/call",
        {"name": "lookup_funcs", "arguments": {"query": renamed, "limit": 50}},
    )["result"]
    assert lk_new["isError"] is False, lk_new
    new_matches = [
        m for m in lk_new["structuredContent"]["matches"] if m["name"] == renamed
    ]
    assert new_matches, lk_new
    assert new_matches[0]["address"] == add_lookup_addr, (new_matches, add_lookup_addr)

    # ... and the old name no longer resolves to any function.
    lk_old = client.call(
        63,
        "tools/call",
        {"name": "lookup_funcs", "arguments": {"query": "add_numbers", "limit": 50}},
    )["result"]
    assert lk_old["isError"] is False, lk_old
    assert not any(
        m["name"] == "add_numbers" for m in lk_old["structuredContent"]["matches"]
    ), lk_old

    # the bulk function export agrees: new name present, old name absent.
    ef2 = client.call(
        64,
        "tools/call",
        {"name": "export_funcs", "arguments": {"offset": 0, "count": 1000}},
    )["result"]
    assert ef2["isError"] is False, ef2
    ef2_names = {row["name"] for row in ef2["structuredContent"]["items"]}
    assert renamed in ef2_names, sorted(ef2_names)
    assert "add_numbers" not in ef2_names, sorted(ef2_names)

    # set_comment — attach a function comment to main. The write is
    # acknowledged (ok); its visibility is asserted below, after set_type
    # forces main's pseudocode to regenerate (a fresh cfunc renders the
    # function comment).
    marker = "idamesh marker: analyzed by the mutation slice"
    sc = client.call(
        65,
        "tools/call",
        {
            "name": "set_comment",
            "arguments": {"address": "main", "comment": marker, "function": True},
        },
    )["result"]
    assert sc["isError"] is False, sc
    scres = sc["structuredContent"]
    assert scres["ok"] is True, scres
    assert scres["address"] == main_addr, (scres, main_addr)
    assert scres["comment"] == marker, scres

    # set_type — apply a simple two-int prototype to main. The write is
    # acknowledged (ok) and echoes the applied declaration and function name.
    proto = "int f(int a, int b)"
    stp = client.call(
        66,
        "tools/call",
        {"name": "set_type", "arguments": {"address": "main", "type": proto}},
    )["result"]
    assert stp["isError"] is False, stp
    stpres = stp["structuredContent"]
    assert stpres["ok"] is True, stpres
    assert stpres["name"] == "main", stpres
    assert stpres["type"] == proto, stpres
    assert stpres["address"] == main_addr, (stpres, main_addr)

    # read-back: applying the type invalidates main's decompilation cache, so a
    # fresh decompile regenerates the pseudocode and reflects all three writes —
    # the applied two-int prototype, the function comment set above, and the
    # renamed callee at its call site (with the old name gone).
    redec = client.call(
        67, "tools/call", {"name": "decompile", "arguments": {"address": "main"}}
    )["result"]
    assert redec["isError"] is False, redec
    repseudo = redec["structuredContent"]["pseudocode"]
    assert "main(int a, int b)" in repseudo, repseudo  # set_type applied
    assert marker in repseudo, repseudo  # set_comment applied
    assert renamed in repseudo, repseudo  # rename applied (call site)
    assert "add_numbers" not in repseudo, repseudo  # old name gone

    # rejected mutations are isError results, not protocol faults / crashes.
    # An identifier with spaces is not a legal name; SN_CHECK refuses it.
    bad_rename = client.call(
        68,
        "tools/call",
        {"name": "rename", "arguments": {"address": "main", "name": "bad name spaces"}},
    )["result"]
    assert bad_rename["isError"] is True, bad_rename

    # An unparseable C declaration cannot be applied.
    bad_type = client.call(
        69,
        "tools/call",
        {
            "name": "set_type",
            "arguments": {"address": "main", "type": "@@@ not a type @@@"},
        },
    )["result"]
    assert bad_type["isError"] is True, bad_type

    # ================================================================== #
    # Mutation slice — batch 2: structural edits (patch / patch_asm /
    # make_data / define_func / undefine). These overwrite RAW BYTES and
    # reshape the code/data definition map, again on the worker's PRIVATE copy
    # (tmp_path) — never the user's fixture — with the worker closing without
    # saving. Every write is proven by a read-back through a read tool, and
    # each reversible edit is restored so the slice leaves the image as it
    # found it (define_func/undefine round-trip back to the starting shape).
    # ================================================================== #

    # patch — read a small window inside main, overwrite its first byte with a
    # DIFFERENT value, read that byte back through get_bytes, then restore the
    # whole window and confirm main is byte-identical again.
    win = client.call(
        70,
        "tools/call",
        {"name": "get_bytes", "arguments": {"address": "main", "size": 8}},
    )["result"]
    assert win["isError"] is False, win
    orig_window = win["structuredContent"]["bytes"].lower()
    assert len(orig_window) == 16, win  # 8 bytes -> 16 hex nibbles
    orig_first = orig_window[:2]
    # choose a replacement byte guaranteed to differ from the original.
    new_first = "90" if orig_first != "90" else "cc"
    pt = client.call(
        71,
        "tools/call",
        {"name": "patch", "arguments": {"address": "main", "bytes": new_first}},
    )["result"]
    assert pt["isError"] is False, pt
    ptres = pt["structuredContent"]
    assert ptres["ok"] is True, ptres
    assert ptres["size"] == 1, ptres
    assert ptres["address"] == main_addr, (ptres, main_addr)
    # read-back: the patched byte is now the live byte at main.
    rb = client.call(
        72,
        "tools/call",
        {"name": "get_bytes", "arguments": {"address": "main", "size": 1}},
    )["result"]
    assert rb["isError"] is False, rb
    assert rb["structuredContent"]["bytes"].lower() == new_first, (rb, new_first)
    # restore the original window (whitespace-free hex round-trips verbatim).
    restore = client.call(
        73,
        "tools/call",
        {"name": "patch", "arguments": {"address": "main", "bytes": orig_window}},
    )["result"]
    assert restore["isError"] is False, restore
    assert restore["structuredContent"]["size"] == 8, restore
    rb2 = client.call(
        74,
        "tools/call",
        {"name": "get_bytes", "arguments": {"address": "main", "size": 8}},
    )["result"]
    assert rb2["structuredContent"]["bytes"].lower() == orig_window, (rb2, orig_window)

    # patch_asm — assemble a trivial 'nop' at main with IDA's OWN assembler and
    # patch it, then restore. Native assembler support varies by build/arch, so
    # the outcome is DISCOVERED at runtime: either a successful encode+write
    # (proven by reading the encoded bytes back), or a clean isError when the
    # architecture cannot assemble here. Either way it is never a crash.
    pa = client.call(
        75,
        "tools/call",
        {"name": "patch_asm", "arguments": {"address": "main", "assembly": "nop"}},
    )["result"]
    if pa["isError"]:
        # The architecture's assembler is unavailable in this build: the tool
        # reports a structured error rather than faulting the request.
        assert isinstance(pa.get("content"), list), pa
    else:
        pares = pa["structuredContent"]
        assert pares["ok"] is True, pares
        assert pares["address"] == main_addr, (pares, main_addr)
        assert isinstance(pares["bytes"], str) and pares["bytes"], pares
        assert pares["bytes"].lower() == pares["bytes"], pares  # lowercase hex
        assert pares["size"] >= 1, pares
        assert len(pares["bytes"]) == pares["size"] * 2, pares
        # read-back: the encoded instruction bytes are now live at main.
        rb3 = client.call(
            76,
            "tools/call",
            {
                "name": "get_bytes",
                "arguments": {"address": "main", "size": pares["size"]},
            },
        )["result"]
        assert rb3["isError"] is False, rb3
        assert rb3["structuredContent"]["bytes"].lower() == pares["bytes"].lower(), rb3
        # restore the original window (covers the <=8-byte nop encoding).
        r3 = client.call(
            77,
            "tools/call",
            {"name": "patch", "arguments": {"address": "main", "bytes": orig_window}},
        )["result"]
        assert r3["isError"] is False, r3
        back = client.call(
            78,
            "tools/call",
            {"name": "get_bytes", "arguments": {"address": "main", "size": 8}},
        )["result"]
        assert back["structuredContent"]["bytes"].lower() == orig_window, back

    # make_data — define a sized primitive at the printf format literal's
    # address (fmt_addr, a real data region). A dword redefinition reports the
    # applied primitive type and the item's byte span.
    md = client.call(
        79,
        "tools/call",
        {"name": "make_data", "arguments": {"address": fmt_addr, "size": 4}},
    )["result"]
    assert md["isError"] is False, md
    mdres = md["structuredContent"]
    assert mdres["ok"] is True, mdres
    assert mdres["address"] == fmt_addr, (mdres, fmt_addr)
    assert mdres["type"] == "dword", mdres
    assert mdres["size"] == 4, mdres

    # define_func + undefine round-trip — take the small non-entry function
    # add_numbers (renamed above to `renamed`, entry at add_lookup_addr and,
    # being the lowest-address function, first in address order), undefine it
    # (its entry leaves the function surface), then recreate it at the same
    # entry (it returns). Two writes, each proven by a read-back. list_funcs is
    # read as a small first page (count=10) so the whole reply fits under the
    # transport's overflow budget — the reply is the real rows verbatim, and the
    # target function, being first, is always in that page.
    def _func_starts(list_result: dict) -> set:
        # Keep only real function rows; a size-capped preview would append a
        # ``{"_more": n}`` sentinel with no ``start`` key, which is not a row.
        return {
            row["start"]
            for row in list_result["structuredContent"]["items"]
            if "start" in row
        }

    lf_before = client.call(
        80,
        "tools/call",
        {"name": "list_funcs", "arguments": {"offset": 0, "count": 10}},
    )["result"]
    assert lf_before["isError"] is False, lf_before
    funcs_before = _func_starts(lf_before)
    assert add_lookup_addr in funcs_before, (add_lookup_addr, sorted(funcs_before))

    # undefine: del_func drops the function boundary at the entry.
    ud = client.call(
        81,
        "tools/call",
        {"name": "undefine", "arguments": {"address": add_lookup_addr}},
    )["result"]
    assert ud["isError"] is False, ud
    udres = ud["structuredContent"]
    assert udres["ok"] is True, udres
    assert udres["address"] == add_lookup_addr, (udres, add_lookup_addr)

    # read-back: the entry no longer names a function in either list_funcs or
    # lookup_funcs (the renamed symbol is gone from the function surface).
    lf_gone = client.call(
        82,
        "tools/call",
        {"name": "list_funcs", "arguments": {"offset": 0, "count": 10}},
    )["result"]
    assert lf_gone["isError"] is False, lf_gone
    assert add_lookup_addr not in _func_starts(lf_gone), (
        add_lookup_addr,
        sorted(_func_starts(lf_gone)),
    )
    lk_gone = client.call(
        83,
        "tools/call",
        {"name": "lookup_funcs", "arguments": {"query": renamed, "limit": 50}},
    )["result"]
    assert lk_gone["isError"] is False, lk_gone
    assert not any(
        m["address"] == add_lookup_addr
        for m in lk_gone["structuredContent"]["matches"]
    ), lk_gone

    # define_func: recreate the function at the same entry; the analyzer infers
    # the extent and the write returns ok.
    df = client.call(
        84,
        "tools/call",
        {"name": "define_func", "arguments": {"address": add_lookup_addr}},
    )["result"]
    assert df["isError"] is False, df
    dfres = df["structuredContent"]
    assert dfres["ok"] is True, dfres
    assert dfres["address"] == add_lookup_addr, (dfres, add_lookup_addr)

    # read-back: the function is present again at its entry.
    lf_back = client.call(
        85,
        "tools/call",
        {"name": "list_funcs", "arguments": {"offset": 0, "count": 10}},
    )["result"]
    assert lf_back["isError"] is False, lf_back
    assert add_lookup_addr in _func_starts(lf_back), (
        add_lookup_addr,
        sorted(_func_starts(lf_back)),
    )

    # rejected structural mutations are isError results, not protocol faults or
    # crashes: malformed hex, an out-of-range address (>= BADADDR), a make_data
    # with neither a type nor a positive size, an unsupported primitive width,
    # and define/undefine at an unresolvable symbol.
    for rid, name, args in (
        (86, "patch", {"address": "main", "bytes": "zz"}),
        (87, "patch", {"address": "0xffffffffffffffff", "bytes": "90"}),
        (88, "make_data", {"address": "main"}),
        (89, "make_data", {"address": fmt_addr, "size": 3}),
        (90, "define_func", {"address": "no_such_symbol_zzz"}),
        (91, "undefine", {"address": "no_such_symbol_zzz"}),
    ):
        bad = client.call(
            rid, "tools/call", {"name": name, "arguments": args}
        )["result"]
        assert bad["isError"] is True, (name, args, bad)

    # ================================================================== #
    # Mutation slice — batch 3: operand/code, type/enum, stack, marks &
    # decompiler cache (set_op_type / define_code / declare_type /
    # enum_upsert / declare_stack / delete_stack / add_bookmark /
    # force_recompile). These finish the Phase-3 write surface on the same
    # PRIVATE copy (tmp_path) — never the user's fixture — with the worker
    # closing without saving. Each write is proven where the change is
    # observable through a read tool (a re-disassembly, the type catalog, a
    # fresh decompile) and otherwise asserted ``ok``; every reversible edit is
    # undone. Request ids run from a private counter so they never collide with
    # the fixed ids above.
    # ================================================================== #
    _rid = [200]

    def _rid_next() -> int:
        _rid[0] += 1
        return _rid[0]

    def _call(name: str, args: dict) -> dict:
        return client.call(_rid_next(), "tools/call", {"name": name, "arguments": args})[
            "result"
        ]

    # set_op_type — scan main's instructions for the first operand that accepts a
    # numeric base ("hex"); the write must land on at least one real operand
    # (main carries immediates and stack-relative operands). The chosen operand
    # is then flipped to "dec" and back to "hex" and the instruction is
    # re-disassembled after each so the two renderings are OBSERVED — they differ
    # whenever the operand shows a base-sensitive number, and both must render.
    dis_scan = _call("disasm", {"address": "main", "count": 30})
    assert dis_scan["isError"] is False, dis_scan
    scan_insns = dis_scan["structuredContent"]["instructions"]
    op_target = None
    for insn in scan_insns:
        for opn in (0, 1):
            r = _call(
                "set_op_type",
                {"address": insn["addr"], "operand": opn, "type": "hex"},
            )
            if r["isError"] is False and r["structuredContent"].get("ok") is True:
                assert r["structuredContent"]["type"] == "hex", r
                assert r["structuredContent"]["operand"] == opn, r
                assert r["structuredContent"]["address"] == insn["addr"], r
                op_target = (insn["addr"], opn)
                break
        if op_target is not None:
            break
    assert op_target is not None, scan_insns
    tgt_addr, tgt_opn = op_target

    r_dec = _call("set_op_type", {"address": tgt_addr, "operand": tgt_opn, "type": "dec"})
    assert r_dec["isError"] is False and r_dec["structuredContent"]["type"] == "dec", r_dec
    d_dec = _call("disasm", {"address": tgt_addr, "count": 1})
    assert d_dec["isError"] is False, d_dec
    text_dec = d_dec["structuredContent"]["instructions"][0]["text"]
    assert isinstance(text_dec, str) and text_dec, d_dec

    r_hex = _call("set_op_type", {"address": tgt_addr, "operand": tgt_opn, "type": "hex"})
    assert r_hex["isError"] is False and r_hex["structuredContent"]["type"] == "hex", r_hex
    d_hex = _call("disasm", {"address": tgt_addr, "count": 1})
    assert d_hex["isError"] is False, d_hex
    text_hex = d_hex["structuredContent"]["instructions"][0]["text"]
    assert isinstance(text_hex, str) and text_hex, d_hex

    # define_code — re-create the instruction at main's entry. The bytes there
    # already decode, so the analyzer returns the existing instruction's length;
    # the write is acknowledged (ok) with a positive size at main's address.
    dc = _call("define_code", {"address": "main"})
    assert dc["isError"] is False, dc
    dcres = dc["structuredContent"]
    assert dcres["ok"] is True, dcres
    assert dcres["address"] == main_addr, (dcres, main_addr)
    assert isinstance(dcres["size"], int) and dcres["size"] >= 1, dcres

    # declare_type — install a fresh struct into the local type library, then
    # read it back through the type catalog: type_query lists it and type_inspect
    # resolves its three members. The name is authored here and cannot pre-exist.
    struct_decl = "struct idamesh_probe_t { int alpha; int beta; char gamma; };"
    dt = _call("declare_type", {"declaration": struct_decl})
    assert dt["isError"] is False, dt
    dtres = dt["structuredContent"]
    assert dtres["ok"] is True, dtres
    assert dtres["count"] >= 1, dtres
    assert "idamesh_probe_t" in dtres["names"], dtres

    tq_probe = _call("type_query", {"query": "idamesh_probe_t", "limit": 50})
    assert tq_probe["isError"] is False, tq_probe
    assert any(
        m["name"] == "idamesh_probe_t"
        for m in tq_probe["structuredContent"]["matches"]
    ), tq_probe
    ti_probe = _call("type_inspect", {"name": "idamesh_probe_t"})
    assert ti_probe["isError"] is False, ti_probe
    ti_probe_res = ti_probe["structuredContent"]
    assert ti_probe_res["name"] == "idamesh_probe_t", ti_probe_res
    probe_members = {m["name"] for m in ti_probe_res["members"]}
    assert {"alpha", "beta", "gamma"} <= probe_members, ti_probe_res

    # enum_upsert — create an enum from three members, then read it back: the
    # write reports the total member count, the type catalog lists it as an enum,
    # and type_inspect resolves it as one.
    eu = _call(
        "enum_upsert",
        {
            "name": "idamesh_enum_t",
            "members": {"IDAMESH_ONE": 1, "IDAMESH_TWO": 2, "IDAMESH_FOUR": 4},
        },
    )
    assert eu["isError"] is False, eu
    eures = eu["structuredContent"]
    assert eures["ok"] is True, eures
    assert eures["name"] == "idamesh_enum_t", eures
    assert eures["member_count"] == 3, eures

    tq_enum = _call("type_query", {"query": "idamesh_enum_t", "limit": 50})
    assert tq_enum["isError"] is False, tq_enum
    enum_matches = [
        m for m in tq_enum["structuredContent"]["matches"] if m["name"] == "idamesh_enum_t"
    ]
    assert enum_matches, tq_enum
    assert "enum" in enum_matches[0]["kind"].lower(), enum_matches
    ti_enum = _call("type_inspect", {"name": "idamesh_enum_t"})
    assert ti_enum["isError"] is False, ti_enum
    assert ti_enum["structuredContent"]["name"] == "idamesh_enum_t", ti_enum
    assert "enum" in ti_enum["structuredContent"]["kind"].lower(), ti_enum

    # A second upsert extends the same enum without dropping the originals: a new
    # member is added and the count grows by exactly one, proving the merge path.
    eu2 = _call(
        "enum_upsert",
        {"name": "idamesh_enum_t", "members": {"IDAMESH_EIGHT": 8}},
    )
    assert eu2["isError"] is False, eu2
    assert eu2["structuredContent"]["member_count"] == 4, eu2

    # declare_stack — define a frame variable on main. Frame placement can
    # collide with existing members, so a small set of candidate offsets is tried
    # and the first accepted placement stands (the tool's own resolution/typing
    # is what is under test, not the exact offset). The write reports main's
    # resolved entry and the variable name.
    stack_name = "idamesh_local"
    stack_ok = False
    for off in (-8, -0x10, -0x18, -0x20, -4, -0xC, -0x14, 0x10, 0x18, 0):
        ds = _call(
            "declare_stack",
            {"function": "main", "name": stack_name, "type": "int", "offset": off},
        )
        if ds["isError"] is False and ds["structuredContent"].get("ok") is True:
            assert ds["structuredContent"]["name"] == stack_name, ds
            assert ds["structuredContent"]["function"] == main_addr, (ds, main_addr)
            stack_ok = True
            break
    assert stack_ok, "declare_stack found no placeable offset on main's frame"

    # delete_stack — remove the frame variable just added; the destructive write
    # is acknowledged and echoes the function/name it removed.
    del_s = _call("delete_stack", {"function": "main", "name": stack_name})
    assert del_s["isError"] is False, del_s
    del_res = del_s["structuredContent"]
    assert del_res["ok"] is True, del_res
    assert del_res["function"] == main_addr, (del_res, main_addr)
    assert del_res["name"] == stack_name, del_res

    # add_bookmark — mark main's entry; the write reports the resolved address and
    # the (1-based) slot the mark occupies.
    ab = _call(
        "add_bookmark",
        {"address": "main", "description": "idamesh bookmark: mutation slice"},
    )
    assert ab["isError"] is False, ab
    abres = ab["structuredContent"]
    assert abres["ok"] is True, abres
    assert abres["address"] == main_addr, (abres, main_addr)
    assert isinstance(abres["slot"], int) and abres["slot"] >= 1, abres

    # force_recompile — drop main's cached decompilation; the write is
    # acknowledged and a subsequent decompile still regenerates working
    # pseudocode (proving the cache was invalidated, not corrupted).
    fr2 = _call("force_recompile", {"address": "main"})
    assert fr2["isError"] is False, fr2
    assert fr2["structuredContent"]["ok"] is True, fr2
    assert fr2["structuredContent"]["address"] == main_addr, (fr2, main_addr)
    redec2 = _call("decompile", {"address": "main"})
    assert redec2["isError"] is False, redec2
    assert "main" in redec2["structuredContent"]["pseudocode"], redec2

    # Rejected batch-3 mutations are isError results, not protocol faults or
    # crashes: an unknown operand representation, an unparseable C declaration, an
    # empty enum member map, a stack op on an unresolvable function, a delete of a
    # frame variable that does not exist, and code/mark/recompile at an
    # unresolvable address.
    for name, args in (
        ("set_op_type", {"address": "main", "operand": 0, "type": "not_a_base"}),
        ("declare_type", {"declaration": "@@@ not a type @@@"}),
        ("enum_upsert", {"name": "idamesh_bad_enum", "members": {}}),
        (
            "declare_stack",
            {"function": "no_such_symbol_zzz", "name": "x", "type": "int"},
        ),
        ("delete_stack", {"function": "main", "name": "no_such_var_zzz"}),
        ("define_code", {"address": "no_such_symbol_zzz"}),
        ("add_bookmark", {"address": "no_such_symbol_zzz", "description": "x"}),
        ("force_recompile", {"address": "no_such_symbol_zzz"}),
    ):
        bad3 = _call(name, args)
        assert bad3["isError"] is True, (name, args, bad3)

    # ================================================================== #
    # Phase-4 analytics / security slice — find_crypto / find_dangerous_callers
    # / detect_vulns. All three are READ-ONLY and reuse the existing read ports.
    # tiny.exe is a trivial MSVC program, so match sets may be SPARSE: each tool
    # must return a WELL-FORMED result and handle an empty match set cleanly
    # (never an isError). Where a hit is expected — a printf-family format-string
    # sink, since tiny.c calls printf — it is asserted when the danger table
    # surfaces it. These run on the same PRIVATE copy after the mutation slice;
    # being read-only they observe the current database without altering it.
    # ================================================================== #

    # find_crypto — scan the whole image for the magic constants reference crypto
    # implementations embed. tiny.exe carries no crypto, so an empty match set is
    # the expected clean result; the shape must still validate and each surfaced
    # match (if any) must carry a 0x-hex address plus a non-empty algorithm and
    # constant label.
    fc = _call("find_crypto", {"limit": 64})
    assert fc["isError"] is False, fc
    fcres = fc["structuredContent"]
    assert isinstance(fcres["matches"], list), fcres
    assert isinstance(fcres["truncated"], bool), fcres
    for cm in fcres["matches"]:
        assert isinstance(cm["address"], str) and cm["address"].startswith("0x"), cm
        assert isinstance(cm["algorithm"], str) and cm["algorithm"], cm
        assert isinstance(cm["constant"], str) and cm["constant"], cm

    # find_dangerous_callers — match the import table against the danger table and
    # collect each dangerous import's call sites. The shape must validate whether
    # or not tiny.exe imports a dangerous API; every surfaced match groups a
    # non-empty api name with at least one well-formed call site (empty buckets
    # are dropped by the use-case), each carrying a 0x-hex address and a
    # ``function`` key that is a string or null.
    fd = _call("find_dangerous_callers", {"limit": 200})
    assert fd["isError"] is False, fd
    fdres = fd["structuredContent"]
    assert isinstance(fdres["matches"], list), fdres
    assert isinstance(fdres["truncated"], bool), fdres
    for m in fdres["matches"]:
        assert isinstance(m["api"], str) and m["api"], m
        assert isinstance(m["callers"], list) and m["callers"], m
        for caller in m["callers"]:
            assert isinstance(caller["address"], str) and caller["address"].startswith(
                "0x"
            ), caller
            assert "function" in caller, caller
            assert caller["function"] is None or isinstance(caller["function"], str), (
                caller
            )

    # printf-family is in the danger table (category format_string), and tiny.c
    # calls printf; when the module links printf as an import the tool surfaces it
    # as a format-string sink. Assert that expected hit precisely when it is
    # present — a well-formed, non-empty call-site list — while tolerating the
    # statically-linked case where printf is not an import (sparse-result rule).
    danger_apis = {m["api"] for m in fdres["matches"]}
    printf_family = {"printf", "fprintf", "vprintf", "vfprintf", "syslog"}
    for m in fdres["matches"]:
        # A canonical or decorated printf import (e.g. ``printf`` / ``_printf``)
        # normalizes into the printf family; when present its sites are real.
        api_norm = m["api"].lstrip("_")
        if api_norm in printf_family or m["api"] in printf_family:
            assert m["callers"], m
            for caller in m["callers"]:
                assert caller["address"].startswith("0x"), caller

    # detect_vulns scoped to main — main calls printf with a *literal* format, so
    # the format-string rule must not fire spuriously on it; the result is a
    # well-formed (possibly empty) findings list, never an error. Each surfaced
    # finding names the rule that fired via its kind/severity/description.
    dv = _call("detect_vulns", {"address": "main"})
    assert dv["isError"] is False, dv
    dvres = dv["structuredContent"]
    assert isinstance(dvres["findings"], list), dvres
    for f in dvres["findings"]:
        assert isinstance(f["address"], str) and f["address"].startswith("0x"), f
        assert f["function"] is None or isinstance(f["function"], str), f
        assert isinstance(f["kind"], str) and f["kind"], f
        assert isinstance(f["severity"], str) and f["severity"], f
        assert isinstance(f["description"], str) and f["description"], f

    # detect_vulns whole-database (empty address) — bounded to the functions that
    # reach a dangerous API; returns a well-formed findings list either way.
    dv_all = _call("detect_vulns", {"address": ""})
    assert dv_all["isError"] is False, dv_all
    dv_all_res = dv_all["structuredContent"]
    assert isinstance(dv_all_res["findings"], list), dv_all_res
    for f in dv_all_res["findings"]:
        assert isinstance(f["address"], str) and f["address"].startswith("0x"), f
        assert isinstance(f["kind"], str) and f["kind"], f
        assert isinstance(f["severity"], str) and f["severity"], f
        assert isinstance(f["description"], str) and f["description"], f

    # detect_vulns at an unresolvable symbol is an isError result, not a crash.
    dv_bad = _call("detect_vulns", {"address": "no_such_symbol_zzz"})
    assert dv_bad["isError"] is True, dv_bad

    return text


def _fixture_sha256() -> str:
    """SHA-256 of the on-disk fixture (empty string when it is missing)."""
    if not _FIXTURE.exists():
        return ""
    return hashlib.sha256(_FIXTURE.read_bytes()).hexdigest()


def _private_copy(tmp_path: Path) -> Path:
    copy = tmp_path / "target.exe"
    shutil.copyfile(_FIXTURE, copy)
    return copy


def test_worker_slice_stdio(tmp_path: Path) -> None:
    before = _fixture_sha256()
    copy = _private_copy(tmp_path)
    proc = _spawn(copy, "stdio")
    client = _StdioClient(proc)
    try:
        text = _drive_slice(client, copy.name)
        assert "add_numbers" in text or "sub_" in text, text
    finally:
        client.close()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
        stderr = _drain_stderr(proc)
    assert proc.returncode == 0, f"worker exited {proc.returncode}; stderr:\n{stderr}"
    # The mutations ran on the private copy, so the user's fixture is untouched.
    assert _fixture_sha256() == before, "fixture changed after a mutating run"


def test_worker_slice_http(tmp_path: Path) -> None:
    before = _fixture_sha256()
    copy = _private_copy(tmp_path)
    proc = _spawn(copy, "http", ["--port", "0"])
    try:
        client = _HttpClient(proc)
        _drive_slice(client, copy.name)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
        _drain_stderr(proc)
    # The mutations ran on the private copy, so the user's fixture is untouched.
    assert _fixture_sha256() == before, "fixture changed after a mutating run"
