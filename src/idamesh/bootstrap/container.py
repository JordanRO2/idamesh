"""Composition root.

The single place allowed to wire all four layers together. Each runtime (GUI
plugin, headless worker, supervisor) builds a container here, choosing which
:class:`~idamesh.domain.ports.execution.MainThreadExecutor` implementation and
transport to bind, then constructs the tool catalog over the resulting use-cases.

Wiring responsibilities:

* build the ports (adapters), the use-cases, and the ``Registry`` of ``ToolSpec``s;
* construct the :class:`~idamesh.interface.mcp.engine.McpEngine` over that registry;
* construct an :class:`~idamesh.infrastructure.rpc.router.Router`, then register
  every ``engine.methods()`` handler on it and set ``router.map_exception =
  engine.map_exception`` (this is where the interface/infrastructure seam is
  bridged — neither layer imports the other; the root does);
* hand the router (a ``Dispatcher``) to the chosen ``Transport``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple

from idamesh.application.contexts.add_bookmark import AddBookmarkUseCase
from idamesh.application.contexts.analyze_component import (
    AnalyzeComponentUseCase,
)
from idamesh.application.contexts.analyze_function import AnalyzeFunctionUseCase
from idamesh.application.contexts.annotations import (
    ApplyAnnotationsUseCase,
    ExportAnnotationsUseCase,
)
from idamesh.application.contexts.basic_blocks import BasicBlocksUseCase
from idamesh.application.contexts.call_graph import CallgraphUseCase
from idamesh.application.contexts.core import (
    GetMetadataUseCase,
    ServerHealthUseCase,
)
from idamesh.application.contexts.declare_type import DeclareTypeUseCase
from idamesh.application.contexts.decompiler import DecompileUseCase
from idamesh.application.contexts.detect_stack_strings import (
    DetectStackStringsUseCase,
)
from idamesh.application.contexts.detect_vulns import DetectVulnsUseCase
from idamesh.application.contexts.define_code import DefineCodeUseCase
from idamesh.application.contexts.define_func import (
    DefineFuncUseCase,
    UndefineUseCase,
)
from idamesh.application.contexts.disasm import DisasmUseCase
from idamesh.application.contexts.entity_query import EntityQueryUseCase
from idamesh.application.contexts.enum_upsert import EnumUpsertUseCase
from idamesh.application.contexts.force_recompile import ForceRecompileUseCase
from idamesh.application.contexts.export_funcs import ExportFuncsUseCase
from idamesh.application.contexts.func_query import FuncQueryUseCase
from idamesh.application.contexts.find_bytes import FindBytesUseCase
from idamesh.application.contexts.find_crypto import FindCryptoUseCase
from idamesh.application.contexts.find_dangerous_callers import (
    FindDangerousCallersUseCase,
)
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
from idamesh.application.contexts.set_op_type import SetOpTypeUseCase
from idamesh.application.contexts.set_type import SetTypeUseCase
from idamesh.application.contexts.snapshot import SnapshotUseCase
from idamesh.application.contexts.survey_binary import SurveyBinaryUseCase
from idamesh.application.contexts.stack import (
    DeclareStackUseCase,
    DeleteStackUseCase,
)
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
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.domain.services.component import ComponentService
from idamesh.domain.services.crypto_signatures import CryptoSignatureService
from idamesh.domain.services.dangerous_apis import DangerousApiService
from idamesh.domain.services.data_flow import DataFlowService
from idamesh.domain.services.number import NumberService
from idamesh.domain.services.stack_strings import StackStringService
from idamesh.domain.services.survey import SurveyService
from idamesh.domain.services.taint import TaintService
from idamesh.domain.services.vuln_heuristics import VulnHeuristicsService
from idamesh.infrastructure.execution.inline import InlineExecutor
from idamesh.infrastructure.ida.annotation_adapter import IdaAnnotationGateway
from idamesh.infrastructure.ida.basic_blocks_adapter import IdaBasicBlockGateway
from idamesh.infrastructure.ida.bookmark_adapter import IdaBookmarkGateway
from idamesh.infrastructure.ida.code_definition_adapter import (
    IdaCodeDefinitionGateway,
)
from idamesh.infrastructure.ida.comment_adapter import IdaCommentGateway
from idamesh.infrastructure.ida.data_definition_adapter import (
    IdaDataDefinitionGateway,
)
from idamesh.infrastructure.ida.database_adapter import IdaDatabaseGateway
from idamesh.infrastructure.ida.decompiler_adapter import IdaDecompilerGateway
from idamesh.infrastructure.ida.disasm_adapter import IdaDisassemblyGateway
from idamesh.infrastructure.ida.enum_adapter import IdaEnumGateway
from idamesh.infrastructure.ida.functions_adapter import IdaFunctionRepository
from idamesh.infrastructure.ida.globals_adapter import IdaGlobalRepository
from idamesh.infrastructure.ida.imports_adapter import IdaImportRepository
from idamesh.infrastructure.ida.instruction_adapter import IdaInstructionGateway
from idamesh.infrastructure.ida.instruction_decode_adapter import (
    IdaInstructionDecodeGateway,
)
from idamesh.infrastructure.ida.listing_search_adapter import (
    IdaListingSearchGateway,
)
from idamesh.infrastructure.ida.memory_adapter import IdaMemoryGateway
from idamesh.infrastructure.ida.naming_adapter import IdaNamingGateway
from idamesh.infrastructure.ida.operand_adapter import IdaOperandGateway
from idamesh.infrastructure.ida.patch_adapter import IdaPatchGateway
from idamesh.infrastructure.ida.recompile_adapter import IdaRecompileGateway
from idamesh.infrastructure.ida.search_adapter import IdaSearchGateway
from idamesh.infrastructure.ida.snapshot_adapter import IdaSnapshotGateway
from idamesh.infrastructure.ida.stack_adapter import IdaStackGateway
from idamesh.infrastructure.ida.strings_adapter import IdaStringsRepository
from idamesh.infrastructure.ida.structs_adapter import IdaStructGateway
from idamesh.infrastructure.ida.type_declaration_adapter import (
    IdaTypeDeclarationGateway,
)
from idamesh.infrastructure.ida.type_mutation_adapter import (
    IdaTypeMutationGateway,
)
from idamesh.infrastructure.ida.types_adapter import IdaTypeGateway
from idamesh.infrastructure.ida.xrefs_adapter import IdaXrefRepository
from idamesh.infrastructure.rpc.router import Router
from idamesh.interface.catalog import register_resources, register_slice
from idamesh.interface.mcp.engine import (
    SUPPORTED_PROTOCOL_VERSIONS,
    McpEngine,
    ServerInfo,
)
from idamesh.interface.mcp.registry import Registry


@dataclass(frozen=True)
class Container:
    """The wired object graph for one process (executor + registry + engine + router)."""

    executor: MainThreadExecutor
    registry: Registry
    engine: McpEngine
    router: Router
    #: Negotiable MCP protocol revisions, surfaced so a transport can validate
    #: the ``MCP-Protocol-Version`` header without importing the interface layer.
    protocol_versions: Tuple[str, ...] = field(
        default=tuple(SUPPORTED_PROTOCOL_VERSIONS)
    )


def build_worker_container(
    *,
    server_version: str = "0.0.1",
    executor: Optional[MainThreadExecutor] = None,
) -> Container:
    """Build the headless-worker container (IDA adapters + a main-thread executor).

    The default executor is the :class:`InlineExecutor`, which never marshals —
    correct for the single-threaded stdio worker whose request handler already
    runs on the database-owning thread. A caller serving on background threads
    (e.g. the HTTP worker) passes an executor that marshals onto that thread.
    """
    resolved_executor: MainThreadExecutor = executor or InlineExecutor()

    database = IdaDatabaseGateway()
    functions = IdaFunctionRepository()
    globals_repo = IdaGlobalRepository()
    decompiler = IdaDecompilerGateway()
    imports_repo = IdaImportRepository()
    xrefs_repo = IdaXrefRepository()
    disassembly = IdaDisassemblyGateway()
    basic_blocks_gateway = IdaBasicBlockGateway()
    search = IdaSearchGateway()
    strings_repo = IdaStringsRepository()
    memory = IdaMemoryGateway()
    listing_search = IdaListingSearchGateway()
    types_gateway = IdaTypeGateway()
    structs_gateway = IdaStructGateway()
    naming_gateway = IdaNamingGateway()
    comment_gateway = IdaCommentGateway()
    type_mutation_gateway = IdaTypeMutationGateway()
    patch_gateway = IdaPatchGateway()
    data_definition_gateway = IdaDataDefinitionGateway()
    code_definition_gateway = IdaCodeDefinitionGateway()
    operand_gateway = IdaOperandGateway()
    instruction_gateway = IdaInstructionGateway()
    instruction_decode_gateway = IdaInstructionDecodeGateway()
    type_declaration_gateway = IdaTypeDeclarationGateway()
    enum_gateway = IdaEnumGateway()
    stack_gateway = IdaStackGateway()
    bookmark_gateway = IdaBookmarkGateway()
    recompile_gateway = IdaRecompileGateway()
    annotation_gateway = IdaAnnotationGateway()
    snapshot_gateway = IdaSnapshotGateway()
    number_service = NumberService()
    crypto_signature_service = CryptoSignatureService()
    dangerous_api_service = DangerousApiService()
    vuln_heuristics_service = VulnHeuristicsService()
    stack_string_service = StackStringService()
    data_flow_service = DataFlowService()
    taint_service = TaintService(data_flow_service)
    survey_service = SurveyService()
    component_service = ComponentService()

    metadata_use_case = GetMetadataUseCase(database)
    health_use_case = ServerHealthUseCase(
        database,
        server_version=server_version,
        protocol_versions=SUPPORTED_PROTOCOL_VERSIONS,
    )
    list_funcs_use_case = ListFuncsUseCase(functions)
    list_globals_use_case = ListGlobalsUseCase(globals_repo)
    decompile_use_case = DecompileUseCase(decompiler, database)
    list_imports_use_case = ListImportsUseCase(imports_repo)
    xrefs_to_use_case = XrefsToUseCase(xrefs_repo, database)
    callees_use_case = CalleesUseCase(xrefs_repo, database)
    disasm_use_case = DisasmUseCase(disassembly, database)
    callgraph_use_case = CallgraphUseCase(xrefs_repo, database)
    basic_blocks_use_case = BasicBlocksUseCase(basic_blocks_gateway, database)
    func_profile_use_case = FuncProfileUseCase(
        functions, xrefs_repo, basic_blocks_gateway, database
    )
    find_bytes_use_case = FindBytesUseCase(search)
    find_crypto_use_case = FindCryptoUseCase(search, crypto_signature_service)
    find_dangerous_callers_use_case = FindDangerousCallersUseCase(
        imports_repo, xrefs_repo, functions, dangerous_api_service
    )
    detect_vulns_use_case = DetectVulnsUseCase(
        decompiler,
        functions,
        xrefs_repo,
        imports_repo,
        dangerous_api_service,
        vuln_heuristics_service,
        database,
    )
    detect_stack_strings_use_case = DetectStackStringsUseCase(
        instruction_decode_gateway,
        stack_string_service,
        functions,
        database,
    )
    trace_data_flow_use_case = TraceDataFlowUseCase(
        instruction_decode_gateway,
        data_flow_service,
        functions,
        database,
    )
    trace_source_to_sink_use_case = TraceSourceToSinkUseCase(
        instruction_decode_gateway,
        taint_service,
        functions,
        database,
        dangerous_api_service,
    )
    list_strings_use_case = ListStringsUseCase(strings_repo)
    int_convert_use_case = IntConvertUseCase(number_service)
    get_bytes_use_case = GetBytesUseCase(memory, database)
    get_int_use_case = GetIntUseCase(memory, database)
    get_string_use_case = GetStringUseCase(memory, database)
    get_global_value_use_case = GetGlobalValueUseCase(memory, database)
    search_text_use_case = SearchTextUseCase(listing_search)
    find_regex_use_case = FindRegexUseCase(strings_repo)
    export_funcs_use_case = ExportFuncsUseCase(functions)
    lookup_funcs_use_case = LookupFuncsUseCase(functions)
    type_query_use_case = TypeQueryUseCase(types_gateway)
    type_inspect_use_case = TypeInspectUseCase(types_gateway)
    entity_query_use_case = EntityQueryUseCase(
        functions, globals_repo, imports_repo
    )
    func_query_use_case = FuncQueryUseCase(functions)
    imports_query_use_case = ImportsQueryUseCase(imports_repo)
    xref_query_use_case = XrefQueryUseCase(xrefs_repo, database)
    insn_query_use_case = InsnQueryUseCase(
        instruction_decode_gateway, functions, database
    )
    search_structs_use_case = SearchStructsUseCase(structs_gateway)
    read_struct_use_case = ReadStructUseCase(structs_gateway, memory, database)
    rename_use_case = RenameUseCase(naming_gateway, database)
    set_comment_use_case = SetCommentUseCase(comment_gateway, database)
    set_type_use_case = SetTypeUseCase(type_mutation_gateway, database)
    patch_use_case = PatchUseCase(patch_gateway, database)
    patch_asm_use_case = PatchAsmUseCase(patch_gateway, database)
    make_data_use_case = MakeDataUseCase(data_definition_gateway, database)
    define_func_use_case = DefineFuncUseCase(code_definition_gateway, database)
    undefine_use_case = UndefineUseCase(code_definition_gateway, database)
    set_op_type_use_case = SetOpTypeUseCase(operand_gateway, database)
    define_code_use_case = DefineCodeUseCase(instruction_gateway, database)
    declare_type_use_case = DeclareTypeUseCase(type_declaration_gateway)
    enum_upsert_use_case = EnumUpsertUseCase(enum_gateway)
    declare_stack_use_case = DeclareStackUseCase(stack_gateway, database)
    delete_stack_use_case = DeleteStackUseCase(stack_gateway, database)
    add_bookmark_use_case = AddBookmarkUseCase(bookmark_gateway, database)
    force_recompile_use_case = ForceRecompileUseCase(recompile_gateway, database)
    export_annotations_use_case = ExportAnnotationsUseCase(
        annotation_gateway, database
    )
    apply_annotations_use_case = ApplyAnnotationsUseCase(annotation_gateway)
    snapshot_use_case = SnapshotUseCase(snapshot_gateway)
    survey_binary_use_case = SurveyBinaryUseCase(
        database,
        functions,
        imports_repo,
        strings_repo,
        xrefs_repo,
        survey_service,
    )
    analyze_function_use_case = AnalyzeFunctionUseCase(
        func_profile_use_case,
        decompile_use_case,
        xrefs_to_use_case,
        callees_use_case,
        imports_repo,
    )
    analyze_component_use_case = AnalyzeComponentUseCase(
        database,
        functions,
        xrefs_repo,
        component_service,
    )

    registry = Registry()
    register_slice(
        registry,
        metadata_use_case=metadata_use_case,
        health_use_case=health_use_case,
        list_funcs_use_case=list_funcs_use_case,
        list_globals_use_case=list_globals_use_case,
        decompile_use_case=decompile_use_case,
        list_imports_use_case=list_imports_use_case,
        xrefs_to_use_case=xrefs_to_use_case,
        callees_use_case=callees_use_case,
        disasm_use_case=disasm_use_case,
        callgraph_use_case=callgraph_use_case,
        basic_blocks_use_case=basic_blocks_use_case,
        func_profile_use_case=func_profile_use_case,
        find_bytes_use_case=find_bytes_use_case,
        find_crypto_use_case=find_crypto_use_case,
        find_dangerous_callers_use_case=find_dangerous_callers_use_case,
        detect_vulns_use_case=detect_vulns_use_case,
        detect_stack_strings_use_case=detect_stack_strings_use_case,
        trace_data_flow_use_case=trace_data_flow_use_case,
        trace_source_to_sink_use_case=trace_source_to_sink_use_case,
        list_strings_use_case=list_strings_use_case,
        int_convert_use_case=int_convert_use_case,
        get_bytes_use_case=get_bytes_use_case,
        get_int_use_case=get_int_use_case,
        get_string_use_case=get_string_use_case,
        get_global_value_use_case=get_global_value_use_case,
        search_text_use_case=search_text_use_case,
        find_regex_use_case=find_regex_use_case,
        export_funcs_use_case=export_funcs_use_case,
        lookup_funcs_use_case=lookup_funcs_use_case,
        type_query_use_case=type_query_use_case,
        type_inspect_use_case=type_inspect_use_case,
        entity_query_use_case=entity_query_use_case,
        func_query_use_case=func_query_use_case,
        imports_query_use_case=imports_query_use_case,
        xref_query_use_case=xref_query_use_case,
        insn_query_use_case=insn_query_use_case,
        search_structs_use_case=search_structs_use_case,
        read_struct_use_case=read_struct_use_case,
        rename_use_case=rename_use_case,
        set_comment_use_case=set_comment_use_case,
        set_type_use_case=set_type_use_case,
        patch_use_case=patch_use_case,
        patch_asm_use_case=patch_asm_use_case,
        make_data_use_case=make_data_use_case,
        define_func_use_case=define_func_use_case,
        undefine_use_case=undefine_use_case,
        set_op_type_use_case=set_op_type_use_case,
        define_code_use_case=define_code_use_case,
        declare_type_use_case=declare_type_use_case,
        enum_upsert_use_case=enum_upsert_use_case,
        declare_stack_use_case=declare_stack_use_case,
        delete_stack_use_case=delete_stack_use_case,
        add_bookmark_use_case=add_bookmark_use_case,
        force_recompile_use_case=force_recompile_use_case,
        export_annotations_use_case=export_annotations_use_case,
        apply_annotations_use_case=apply_annotations_use_case,
        snapshot_use_case=snapshot_use_case,
        survey_binary_use_case=survey_binary_use_case,
        analyze_function_use_case=analyze_function_use_case,
        analyze_component_use_case=analyze_component_use_case,
        executor=resolved_executor,
    )
    register_resources(
        registry,
        metadata_use_case=metadata_use_case,
        get_bytes_use_case=get_bytes_use_case,
        list_funcs_use_case=list_funcs_use_case,
        list_globals_use_case=list_globals_use_case,
        list_imports_use_case=list_imports_use_case,
        list_strings_use_case=list_strings_use_case,
        decompile_use_case=decompile_use_case,
        disasm_use_case=disasm_use_case,
        xrefs_to_use_case=xrefs_to_use_case,
        type_inspect_use_case=type_inspect_use_case,
        executor=resolved_executor,
    )

    engine = McpEngine(
        registry,
        server_info=ServerInfo(version=server_version),
    )

    router = Router(map_exception=engine.map_exception)
    for method, handler in engine.methods().items():
        router.register(
            method,
            handler,
            notification=method.startswith("notifications/"),
        )

    return Container(
        executor=resolved_executor,
        registry=registry,
        engine=engine,
        router=router,
        protocol_versions=tuple(SUPPORTED_PROTOCOL_VERSIONS),
    )
