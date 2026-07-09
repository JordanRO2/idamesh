"""Use-cases for the Phase-1 slice, one class per capability."""

from __future__ import annotations

from idamesh.application.contexts.analyze_component import (
    AnalyzeComponentUseCase,
)
from idamesh.application.contexts.analyze_function import AnalyzeFunctionUseCase
from idamesh.application.contexts.basic_blocks import BasicBlocksUseCase
from idamesh.application.contexts.call_graph import CallgraphUseCase
from idamesh.application.contexts.core import (
    GetMetadataUseCase,
    ServerHealthUseCase,
)
from idamesh.application.contexts.decompiler import DecompileUseCase
from idamesh.application.contexts.detect_stack_strings import (
    DetectStackStringsUseCase,
)
from idamesh.application.contexts.define_func import (
    DefineFuncUseCase,
    UndefineUseCase,
)
from idamesh.application.contexts.disasm import DisasmUseCase
from idamesh.application.contexts.entity_query import EntityQueryUseCase
from idamesh.application.contexts.export_funcs import ExportFuncsUseCase
from idamesh.application.contexts.find_bytes import FindBytesUseCase
from idamesh.application.contexts.func_query import FuncQueryUseCase
from idamesh.application.contexts.find_regex import FindRegexUseCase
from idamesh.application.contexts.func_profile import FuncProfileUseCase
from idamesh.application.contexts.functions import ListFuncsUseCase
from idamesh.application.contexts.globals import ListGlobalsUseCase
from idamesh.application.contexts.imports import ListImportsUseCase
from idamesh.application.contexts.imports_query import ImportsQueryUseCase
from idamesh.application.contexts.insn_query import InsnQueryUseCase
from idamesh.application.contexts.int_convert import IntConvertUseCase
from idamesh.application.contexts.list_strings import ListStringsUseCase
from idamesh.application.contexts.lookup_funcs import LookupFuncsUseCase
from idamesh.application.contexts.make_data import MakeDataUseCase
from idamesh.application.contexts.memory import (
    GetBytesUseCase,
    GetGlobalValueUseCase,
    GetIntUseCase,
    GetStringUseCase,
)
from idamesh.application.contexts.patch import (
    PatchAsmUseCase,
    PatchUseCase,
)
from idamesh.application.contexts.read_struct import ReadStructUseCase
from idamesh.application.contexts.rename import RenameUseCase
from idamesh.application.contexts.search_structs import SearchStructsUseCase
from idamesh.application.contexts.search_text import SearchTextUseCase
from idamesh.application.contexts.set_comment import SetCommentUseCase
from idamesh.application.contexts.survey_binary import SurveyBinaryUseCase
from idamesh.application.contexts.set_type import SetTypeUseCase
from idamesh.application.contexts.trace_data_flow import TraceDataFlowUseCase
from idamesh.application.contexts.trace_source_to_sink import (
    TraceSourceToSinkUseCase,
)
from idamesh.application.contexts.types import (
    TypeInspectUseCase,
    TypeQueryUseCase,
)
from idamesh.application.contexts.xref_query import XrefQueryUseCase
from idamesh.application.contexts.xrefs import CalleesUseCase, XrefsToUseCase

__all__ = [
    "AnalyzeComponentUseCase",
    "AnalyzeFunctionUseCase",
    "SurveyBinaryUseCase",
    "GetMetadataUseCase",
    "ServerHealthUseCase",
    "DecompileUseCase",
    "DisasmUseCase",
    "FindBytesUseCase",
    "IntConvertUseCase",
    "ListFuncsUseCase",
    "ListGlobalsUseCase",
    "ListImportsUseCase",
    "ListStringsUseCase",
    "XrefsToUseCase",
    "CalleesUseCase",
    "CallgraphUseCase",
    "BasicBlocksUseCase",
    "FuncProfileUseCase",
    "GetBytesUseCase",
    "GetIntUseCase",
    "GetStringUseCase",
    "GetGlobalValueUseCase",
    "SearchTextUseCase",
    "FindRegexUseCase",
    "ExportFuncsUseCase",
    "LookupFuncsUseCase",
    "TypeQueryUseCase",
    "TypeInspectUseCase",
    "EntityQueryUseCase",
    "FuncQueryUseCase",
    "ImportsQueryUseCase",
    "XrefQueryUseCase",
    "InsnQueryUseCase",
    "SearchStructsUseCase",
    "ReadStructUseCase",
    "RenameUseCase",
    "SetCommentUseCase",
    "SetTypeUseCase",
    "PatchUseCase",
    "PatchAsmUseCase",
    "MakeDataUseCase",
    "DefineFuncUseCase",
    "UndefineUseCase",
    "DetectStackStringsUseCase",
    "TraceDataFlowUseCase",
    "TraceSourceToSinkUseCase",
]
