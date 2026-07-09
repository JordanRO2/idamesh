"""Unit tests for the address-keyed code resources (no IDA).

Drives ``register_code_resources`` end-to-end through the real MCP engine with
fake use-cases and an inline executor: the three ``ida://function|disasm|xrefs/
{address}`` templates list correctly, read back the reused tool-catalog wire
views, extract the ``{address}`` path segment straight into the command, and map
a failing target to a ``resources/read`` resource-not-found error (never a tool
``isError`` envelope). Nothing here imports ``ida*``.
"""

from __future__ import annotations

import json
from typing import Callable, List, Optional, TypeVar

import pytest

from idamesh.application.dto.decompiler import DecompileCommand, DecompileResult
from idamesh.application.dto.disasm import DisasmCommand, DisasmResult
from idamesh.application.dto.xrefs import XrefsToCommand, XrefsToResult
from idamesh.domain.entities.decompilation import Pseudocode
from idamesh.domain.entities.disasm import DisasmLine
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.values.address import Address
from idamesh.interface.catalog.resources.code import (
    DISASM_URI_TEMPLATE,
    FUNCTION_URI_TEMPLATE,
    XREFS_URI_TEMPLATE,
    register_code_resources,
)
from idamesh.interface.mcp.engine import ErrorCode, McpEngine, McpError
from idamesh.interface.mcp.registry import Registry
from tests.mcp.support import FakeCtx

T = TypeVar("T")


# -- fakes ------------------------------------------------------------------- #


class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs the job inline on the caller's thread."""

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        return job()

    def on_kernel_thread(self) -> bool:
        return True


class _RecordingUseCase:
    """A use-case whose ``execute`` records the command and returns ``result``.

    When ``error`` is set, ``execute`` raises it instead — modelling a bad target
    (e.g. an unresolvable address), which the use-case surfaces as an exception.
    """

    def __init__(self, result: object = None, error: Optional[Exception] = None) -> None:
        self._result = result
        self._error = error
        self.commands: List[object] = []

    def execute(self, command: object) -> object:
        self.commands.append(command)
        if self._error is not None:
            raise self._error
        return self._result


def _decompile_result() -> DecompileResult:
    return DecompileResult(
        pseudocode=Pseudocode(
            ea=Address(0x401000),
            text="int sub_401000() {\n  return 0;\n}",
            lines=("int sub_401000() {", "  return 0;", "}"),
            name="sub_401000",
        )
    )


def _disasm_result() -> DisasmResult:
    return DisasmResult(
        address=Address(0x401000),
        lines=(
            DisasmLine(ea=Address(0x401000), text="push rbp", raw=b"\x55"),
            DisasmLine(ea=Address(0x401001), text="mov rbp, rsp", raw=b"\x48\x89\xe5"),
        ),
        truncated=False,
    )


def _xrefs_result() -> XrefsToResult:
    edge = Xref(
        source=Address(0x401500),
        target=Address(0x401000),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
        source_func="caller",
    )
    return XrefsToResult(target=Address(0x401000), xrefs=(edge,), truncated=False)


def _build_engine(
    *,
    decompile: _RecordingUseCase,
    disasm: _RecordingUseCase,
    xrefs: _RecordingUseCase,
) -> McpEngine:
    registry = Registry()
    register_code_resources(
        registry,
        decompile_use_case=decompile,  # type: ignore[arg-type]
        disasm_use_case=disasm,  # type: ignore[arg-type]
        xrefs_to_use_case=xrefs,  # type: ignore[arg-type]
        executor=_InlineExecutor(),
    )
    engine = McpEngine(registry)
    engine.initialized(None, FakeCtx())  # past the init gate for the default session
    return engine


def _read(engine: McpEngine, uri: str) -> dict:
    contents = engine.resources_read({"uri": uri}, FakeCtx())["contents"]
    assert len(contents) == 1
    entry = contents[0]
    assert entry["uri"] == uri
    assert entry["mimeType"] == "application/json"
    return json.loads(entry["text"])


# -- template listing -------------------------------------------------------- #


def test_templates_list_advertises_the_three_code_resources():
    engine = _build_engine(
        decompile=_RecordingUseCase(),
        disasm=_RecordingUseCase(),
        xrefs=_RecordingUseCase(),
    )

    templates = engine.resources_templates_list(None, FakeCtx())["resourceTemplates"]
    by_uri = {t["uriTemplate"]: t for t in templates}

    assert by_uri.keys() == {
        FUNCTION_URI_TEMPLATE,
        DISASM_URI_TEMPLATE,
        XREFS_URI_TEMPLATE,
    }
    assert by_uri[FUNCTION_URI_TEMPLATE]["name"] == "function"
    assert by_uri[DISASM_URI_TEMPLATE]["name"] == "disasm"
    assert by_uri[XREFS_URI_TEMPLATE]["name"] == "xrefs"
    for template in templates:
        assert template["mimeType"] == "application/json"
        assert template["description"]  # every handler carries a fresh docstring

    # Templated resources never leak into the literal-resource listing.
    assert engine.resources_list(None, FakeCtx())["resources"] == []


# -- happy-path reads + param extraction ------------------------------------- #


def test_function_resource_reads_pseudocode_view():
    decompile = _RecordingUseCase(result=_decompile_result())
    engine = _build_engine(
        decompile=decompile,
        disasm=_RecordingUseCase(),
        xrefs=_RecordingUseCase(),
    )

    payload = _read(engine, "ida://function/0x401000")

    assert payload == {
        "name": "sub_401000",
        "address": "0x401000",
        "pseudocode": "int sub_401000() {\n  return 0;\n}",
        "lines": ["int sub_401000() {", "  return 0;", "}"],
    }
    # The path segment is extracted verbatim and handed to the command as a string.
    assert len(decompile.commands) == 1
    assert isinstance(decompile.commands[0], DecompileCommand)
    assert decompile.commands[0].address == "0x401000"


def test_disasm_resource_reads_listing_view():
    disasm = _RecordingUseCase(result=_disasm_result())
    engine = _build_engine(
        decompile=_RecordingUseCase(),
        disasm=disasm,
        xrefs=_RecordingUseCase(),
    )

    payload = _read(engine, "ida://disasm/0x401000")

    assert payload["address"] == "0x401000"
    assert payload["returned"] == 2
    assert payload["truncated"] is False
    assert payload["instructions"][0] == {
        "addr": "0x401000",
        "bytes": "55",
        "text": "push rbp",
    }
    assert isinstance(disasm.commands[0], DisasmCommand)
    assert disasm.commands[0].address == "0x401000"


def test_xrefs_resource_reads_edges_view():
    xrefs = _RecordingUseCase(result=_xrefs_result())
    engine = _build_engine(
        decompile=_RecordingUseCase(),
        disasm=_RecordingUseCase(),
        xrefs=xrefs,
    )

    payload = _read(engine, "ida://xrefs/0x401000")

    assert payload["target"] == "0x401000"
    assert payload["truncated"] is False
    assert payload["xrefs"] == [
        {
            "from": "0x401500",
            "to": "0x401000",
            "kind": "code",
            "type": "call",
            "func": "caller",
        }
    ]
    assert isinstance(xrefs.commands[0], XrefsToCommand)
    assert xrefs.commands[0].address == "0x401000"


def test_symbol_name_address_segment_flows_to_command():
    # A ``{address}`` segment need not be numeric: a symbol name arrives as the
    # raw string, resolved downstream by the use-case (here just recorded).
    decompile = _RecordingUseCase(result=_decompile_result())
    engine = _build_engine(
        decompile=decompile,
        disasm=_RecordingUseCase(),
        xrefs=_RecordingUseCase(),
    )

    _read(engine, "ida://function/main")

    assert decompile.commands[0].address == "main"


# -- failing target -> resource-not-found ------------------------------------ #


@pytest.mark.parametrize(
    "uri",
    [
        "ida://function/0xbadbad",
        "ida://disasm/0xbadbad",
        "ida://xrefs/0xbadbad",
    ],
)
def test_bad_address_is_resource_not_found(uri: str):
    error = ValueError("could not resolve address")
    engine = _build_engine(
        decompile=_RecordingUseCase(error=error),
        disasm=_RecordingUseCase(error=error),
        xrefs=_RecordingUseCase(error=error),
    )

    with pytest.raises(McpError) as exc:
        engine.resources_read({"uri": uri}, FakeCtx())

    assert exc.value.code == ErrorCode.RESOURCE_NOT_FOUND
    assert exc.value.data == {"uri": uri}
