"""Command/Result DTOs — the tool I/O contracts for the Phase-1 slice."""

from __future__ import annotations

from idamesh.application.dto.analyze_component import (
    AnalyzeComponentCommand,
    AnalyzeComponentResult,
)
from idamesh.application.dto.analyze_function import (
    AnalyzeFunctionCommand,
    AnalyzeFunctionResult,
)
from idamesh.application.dto.basic_blocks import (
    BasicBlocksCommand,
    BasicBlocksResult,
)
from idamesh.application.dto.call_graph import (
    CallgraphCommand,
    CallgraphResult,
)
from idamesh.application.dto.core import (
    GetMetadataCommand,
    GetMetadataResult,
    ServerHealthCommand,
    ServerHealthResult,
)
from idamesh.application.dto.decompiler import DecompileCommand, DecompileResult
from idamesh.application.dto.detect_stack_strings import (
    DetectStackStringsCommand,
    DetectStackStringsResult,
)
from idamesh.application.dto.define_func import (
    DefineFuncCommand,
    DefineFuncResult,
    UndefineCommand,
    UndefineResult,
)
from idamesh.application.dto.disasm import DisasmCommand, DisasmResult
from idamesh.application.dto.entity_query import (
    EntityQueryCommand,
    EntityQueryResult,
)
from idamesh.application.dto.export_funcs import (
    ExportFuncsCommand,
    ExportFuncsResult,
)
from idamesh.application.dto.func_query import (
    FuncQueryCommand,
    FuncQueryResult,
)
from idamesh.application.dto.find_bytes import (
    FindBytesCommand,
    FindBytesResult,
)
from idamesh.application.dto.find_regex import (
    FindRegexCommand,
    FindRegexResult,
)
from idamesh.application.dto.func_profile import (
    FuncProfileCommand,
    FuncProfileResult,
)
from idamesh.application.dto.functions import ListFuncsCommand, ListFuncsResult
from idamesh.application.dto.globals import ListGlobalsCommand, ListGlobalsResult
from idamesh.application.dto.imports import ListImportsCommand, ListImportsResult
from idamesh.application.dto.imports_query import (
    ImportsQueryCommand,
    ImportsQueryResult,
)
from idamesh.application.dto.insn_query import (
    InsnQueryCommand,
    InsnQueryResult,
)
from idamesh.application.dto.int_convert import (
    IntConvertCommand,
    IntConvertResult,
)
from idamesh.application.dto.list_strings import (
    ListStringsCommand,
    ListStringsResult,
)
from idamesh.application.dto.lookup_funcs import (
    LookupFuncsCommand,
    LookupFuncsResult,
)
from idamesh.application.dto.make_data import (
    MakeDataCommand,
    MakeDataResult,
)
from idamesh.application.dto.memory import (
    GetBytesCommand,
    GetBytesResult,
    GetGlobalValueCommand,
    GetGlobalValueResult,
    GetIntCommand,
    GetIntResult,
    GetStringCommand,
    GetStringResult,
)
from idamesh.application.dto.patch import (
    PatchAsmCommand,
    PatchAsmResult,
    PatchCommand,
    PatchResult,
)
from idamesh.application.dto.read_struct import (
    ReadStructCommand,
    ReadStructResult,
)
from idamesh.application.dto.rename import RenameCommand, RenameResult
from idamesh.application.dto.search_structs import (
    SearchStructsCommand,
    SearchStructsResult,
)
from idamesh.application.dto.search_text import (
    SearchTextCommand,
    SearchTextResult,
)
from idamesh.application.dto.survey_binary import (
    SurveyBinaryCommand,
    SurveyBinaryResult,
)
from idamesh.application.dto.set_comment import (
    SetCommentCommand,
    SetCommentResult,
)
from idamesh.application.dto.set_type import SetTypeCommand, SetTypeResult
from idamesh.application.dto.trace_data_flow import (
    TraceDataFlowCommand,
    TraceDataFlowResult,
)
from idamesh.application.dto.trace_source_to_sink import (
    TraceSourceToSinkCommand,
    TraceSourceToSinkResult,
)
from idamesh.application.dto.types import (
    TypeInspectCommand,
    TypeInspectResult,
    TypeQueryCommand,
    TypeQueryResult,
)
from idamesh.application.dto.xref_query import (
    XrefQueryCommand,
    XrefQueryResult,
)
from idamesh.application.dto.xrefs import (
    CalleesCommand,
    CalleesResult,
    XrefsToCommand,
    XrefsToResult,
)

__all__ = [
    "AnalyzeComponentCommand",
    "AnalyzeComponentResult",
    "AnalyzeFunctionCommand",
    "AnalyzeFunctionResult",
    "SurveyBinaryCommand",
    "SurveyBinaryResult",
    "GetMetadataCommand",
    "GetMetadataResult",
    "ServerHealthCommand",
    "ServerHealthResult",
    "DecompileCommand",
    "DecompileResult",
    "DisasmCommand",
    "DisasmResult",
    "ListFuncsCommand",
    "ListFuncsResult",
    "ListGlobalsCommand",
    "ListGlobalsResult",
    "ListImportsCommand",
    "ListImportsResult",
    "ListStringsCommand",
    "ListStringsResult",
    "FindBytesCommand",
    "FindBytesResult",
    "IntConvertCommand",
    "IntConvertResult",
    "XrefsToCommand",
    "XrefsToResult",
    "CalleesCommand",
    "CalleesResult",
    "CallgraphCommand",
    "CallgraphResult",
    "BasicBlocksCommand",
    "BasicBlocksResult",
    "FuncProfileCommand",
    "FuncProfileResult",
    "GetBytesCommand",
    "GetBytesResult",
    "GetIntCommand",
    "GetIntResult",
    "GetStringCommand",
    "GetStringResult",
    "GetGlobalValueCommand",
    "GetGlobalValueResult",
    "SearchTextCommand",
    "SearchTextResult",
    "FindRegexCommand",
    "FindRegexResult",
    "ExportFuncsCommand",
    "ExportFuncsResult",
    "LookupFuncsCommand",
    "LookupFuncsResult",
    "TypeQueryCommand",
    "TypeQueryResult",
    "TypeInspectCommand",
    "TypeInspectResult",
    "EntityQueryCommand",
    "EntityQueryResult",
    "FuncQueryCommand",
    "FuncQueryResult",
    "ImportsQueryCommand",
    "ImportsQueryResult",
    "XrefQueryCommand",
    "XrefQueryResult",
    "InsnQueryCommand",
    "InsnQueryResult",
    "SearchStructsCommand",
    "SearchStructsResult",
    "ReadStructCommand",
    "ReadStructResult",
    "RenameCommand",
    "RenameResult",
    "SetCommentCommand",
    "SetCommentResult",
    "SetTypeCommand",
    "SetTypeResult",
    "PatchCommand",
    "PatchResult",
    "PatchAsmCommand",
    "PatchAsmResult",
    "MakeDataCommand",
    "MakeDataResult",
    "DefineFuncCommand",
    "DefineFuncResult",
    "UndefineCommand",
    "UndefineResult",
    "DetectStackStringsCommand",
    "DetectStackStringsResult",
    "TraceDataFlowCommand",
    "TraceDataFlowResult",
    "TraceSourceToSinkCommand",
    "TraceSourceToSinkResult",
]
