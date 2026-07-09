"""Tool catalog — where ``ToolSpec``s are declared and bound to use-cases.

Each thin module here uses the :class:`~idamesh.interface.mcp.registry.Registry`
decorators to bind a tool name + schema + coercion to an application use-case.
The Phase-1 slice registers exactly three tools — ``get_metadata`` /
``server_health``, ``list_funcs``, and ``decompile`` — against the frozen DTOs in
:mod:`idamesh.application.dto`. :func:`register_slice` wires all three onto a
registry; the composition root calls it with the constructed use-cases and the
chosen main-thread executor.
"""

from __future__ import annotations

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
from idamesh.interface.catalog.add_bookmark import register_add_bookmark
from idamesh.interface.catalog.analyze_component import register_analyze_component
from idamesh.interface.catalog.analyze_function import register_analyze_function
from idamesh.interface.catalog.annotations import (
    register_apply_annotations,
    register_export_annotations,
)
from idamesh.interface.catalog.basic_blocks import register_basic_blocks
from idamesh.interface.catalog.callees import register_callees
from idamesh.interface.catalog.callgraph import register_callgraph
from idamesh.interface.catalog.core import register_core
from idamesh.interface.catalog.declare_stack import register_declare_stack
from idamesh.interface.catalog.declare_type import register_declare_type
from idamesh.interface.catalog.decompiler import register_decompiler
from idamesh.interface.catalog.define_code import register_define_code
from idamesh.interface.catalog.define_func import register_define_func
from idamesh.interface.catalog.delete_stack import register_delete_stack
from idamesh.interface.catalog.detect_stack_strings import (
    register_detect_stack_strings,
)
from idamesh.interface.catalog.detect_vulns import register_detect_vulns
from idamesh.interface.catalog.disasm import register_disasm
from idamesh.interface.catalog.entity_query import register_entity_query
from idamesh.interface.catalog.enum_upsert import register_enum_upsert
from idamesh.interface.catalog.force_recompile import register_force_recompile
from idamesh.interface.catalog.export_funcs import register_export_funcs
from idamesh.interface.catalog.func_query import register_func_query
from idamesh.interface.catalog.find_bytes import register_find_bytes
from idamesh.interface.catalog.find_crypto import register_find_crypto
from idamesh.interface.catalog.find_dangerous_callers import (
    register_find_dangerous_callers,
)
from idamesh.interface.catalog.find_regex import register_find_regex
from idamesh.interface.catalog.func_profile import register_func_profile
from idamesh.interface.catalog.functions import register_functions
from idamesh.interface.catalog.get_bytes import register_get_bytes
from idamesh.interface.catalog.get_global_value import register_get_global_value
from idamesh.interface.catalog.get_int import register_get_int
from idamesh.interface.catalog.get_string import register_get_string
from idamesh.interface.catalog.globals import register_globals
from idamesh.interface.catalog.imports import register_imports
from idamesh.interface.catalog.imports_query import register_imports_query
from idamesh.interface.catalog.insn_query import register_insn_query
from idamesh.interface.catalog.int_convert import register_int_convert
from idamesh.interface.catalog.list_strings import register_list_strings
from idamesh.interface.catalog.lookup_funcs import register_lookup_funcs
from idamesh.interface.catalog.make_data import register_make_data
from idamesh.interface.catalog.patch import register_patch
from idamesh.interface.catalog.patch_asm import register_patch_asm
from idamesh.interface.catalog.read_struct import register_read_struct
from idamesh.interface.catalog.rename import register_rename
from idamesh.interface.catalog.resources import register_resources
from idamesh.interface.catalog.search_structs import register_search_structs
from idamesh.interface.catalog.search_text import register_search_text
from idamesh.interface.catalog.set_comment import register_set_comment
from idamesh.interface.catalog.set_op_type import register_set_op_type
from idamesh.interface.catalog.set_type import register_set_type
from idamesh.interface.catalog.snapshot import register_idb_snapshot
from idamesh.interface.catalog.survey_binary import register_survey_binary
from idamesh.interface.catalog.trace_data_flow import register_trace_data_flow
from idamesh.interface.catalog.trace_source_to_sink import (
    register_trace_source_to_sink,
)
from idamesh.interface.catalog.type_inspect import register_type_inspect
from idamesh.interface.catalog.type_query import register_type_query
from idamesh.interface.catalog.undefine import register_undefine
from idamesh.interface.catalog.xref_query import register_xref_query
from idamesh.interface.catalog.xrefs import register_xrefs_to
from idamesh.interface.mcp.registry import Registry

__all__ = [
    "register_core",
    "register_functions",
    "register_globals",
    "register_decompiler",
    "register_imports",
    "register_xrefs_to",
    "register_callees",
    "register_disasm",
    "register_callgraph",
    "register_basic_blocks",
    "register_func_profile",
    "register_find_bytes",
    "register_find_crypto",
    "register_find_dangerous_callers",
    "register_detect_vulns",
    "register_detect_stack_strings",
    "register_trace_data_flow",
    "register_trace_source_to_sink",
    "register_list_strings",
    "register_int_convert",
    "register_get_bytes",
    "register_get_int",
    "register_get_string",
    "register_get_global_value",
    "register_search_text",
    "register_find_regex",
    "register_export_funcs",
    "register_lookup_funcs",
    "register_type_query",
    "register_type_inspect",
    "register_entity_query",
    "register_func_query",
    "register_imports_query",
    "register_xref_query",
    "register_insn_query",
    "register_search_structs",
    "register_read_struct",
    "register_rename",
    "register_set_comment",
    "register_set_type",
    "register_patch",
    "register_patch_asm",
    "register_make_data",
    "register_define_func",
    "register_undefine",
    "register_set_op_type",
    "register_define_code",
    "register_declare_type",
    "register_enum_upsert",
    "register_declare_stack",
    "register_delete_stack",
    "register_add_bookmark",
    "register_force_recompile",
    "register_export_annotations",
    "register_apply_annotations",
    "register_idb_snapshot",
    "register_survey_binary",
    "register_analyze_function",
    "register_analyze_component",
    "register_resources",
    "register_slice",
]


def register_slice(
    registry: Registry,
    *,
    metadata_use_case: GetMetadataUseCase,
    health_use_case: ServerHealthUseCase,
    list_funcs_use_case: ListFuncsUseCase,
    list_globals_use_case: ListGlobalsUseCase,
    decompile_use_case: DecompileUseCase,
    list_imports_use_case: ListImportsUseCase,
    xrefs_to_use_case: XrefsToUseCase,
    callees_use_case: CalleesUseCase,
    disasm_use_case: DisasmUseCase,
    callgraph_use_case: CallgraphUseCase,
    basic_blocks_use_case: BasicBlocksUseCase,
    func_profile_use_case: FuncProfileUseCase,
    find_bytes_use_case: FindBytesUseCase,
    find_crypto_use_case: FindCryptoUseCase,
    find_dangerous_callers_use_case: FindDangerousCallersUseCase,
    detect_vulns_use_case: DetectVulnsUseCase,
    detect_stack_strings_use_case: DetectStackStringsUseCase,
    trace_data_flow_use_case: TraceDataFlowUseCase,
    trace_source_to_sink_use_case: TraceSourceToSinkUseCase,
    list_strings_use_case: ListStringsUseCase,
    int_convert_use_case: IntConvertUseCase,
    get_bytes_use_case: GetBytesUseCase,
    get_int_use_case: GetIntUseCase,
    get_string_use_case: GetStringUseCase,
    get_global_value_use_case: GetGlobalValueUseCase,
    search_text_use_case: SearchTextUseCase,
    find_regex_use_case: FindRegexUseCase,
    export_funcs_use_case: ExportFuncsUseCase,
    lookup_funcs_use_case: LookupFuncsUseCase,
    type_query_use_case: TypeQueryUseCase,
    type_inspect_use_case: TypeInspectUseCase,
    entity_query_use_case: EntityQueryUseCase,
    func_query_use_case: FuncQueryUseCase,
    imports_query_use_case: ImportsQueryUseCase,
    xref_query_use_case: XrefQueryUseCase,
    insn_query_use_case: InsnQueryUseCase,
    search_structs_use_case: SearchStructsUseCase,
    read_struct_use_case: ReadStructUseCase,
    rename_use_case: RenameUseCase,
    set_comment_use_case: SetCommentUseCase,
    set_type_use_case: SetTypeUseCase,
    patch_use_case: PatchUseCase,
    patch_asm_use_case: PatchAsmUseCase,
    make_data_use_case: MakeDataUseCase,
    define_func_use_case: DefineFuncUseCase,
    undefine_use_case: UndefineUseCase,
    set_op_type_use_case: SetOpTypeUseCase,
    define_code_use_case: DefineCodeUseCase,
    declare_type_use_case: DeclareTypeUseCase,
    enum_upsert_use_case: EnumUpsertUseCase,
    declare_stack_use_case: DeclareStackUseCase,
    delete_stack_use_case: DeleteStackUseCase,
    add_bookmark_use_case: AddBookmarkUseCase,
    force_recompile_use_case: ForceRecompileUseCase,
    export_annotations_use_case: ExportAnnotationsUseCase,
    apply_annotations_use_case: ApplyAnnotationsUseCase,
    snapshot_use_case: SnapshotUseCase,
    survey_binary_use_case: SurveyBinaryUseCase,
    analyze_function_use_case: AnalyzeFunctionUseCase,
    analyze_component_use_case: AnalyzeComponentUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register the currently-shipping tools onto ``registry``."""
    register_core(
        registry,
        metadata_use_case=metadata_use_case,
        health_use_case=health_use_case,
        executor=executor,
    )
    register_functions(
        registry,
        list_funcs_use_case=list_funcs_use_case,
        executor=executor,
    )
    register_globals(
        registry,
        list_globals_use_case=list_globals_use_case,
        executor=executor,
    )
    register_decompiler(
        registry,
        decompile_use_case=decompile_use_case,
        executor=executor,
    )
    register_imports(
        registry,
        list_imports_use_case=list_imports_use_case,
        executor=executor,
    )
    register_xrefs_to(
        registry,
        xrefs_to_use_case=xrefs_to_use_case,
        executor=executor,
    )
    register_callees(
        registry,
        callees_use_case=callees_use_case,
        executor=executor,
    )
    register_disasm(
        registry,
        disasm_use_case=disasm_use_case,
        executor=executor,
    )
    register_callgraph(
        registry,
        callgraph_use_case=callgraph_use_case,
        executor=executor,
    )
    register_basic_blocks(
        registry,
        basic_blocks_use_case=basic_blocks_use_case,
        executor=executor,
    )
    register_func_profile(
        registry,
        func_profile_use_case=func_profile_use_case,
        executor=executor,
    )
    register_find_bytes(
        registry,
        find_bytes_use_case=find_bytes_use_case,
        executor=executor,
    )
    register_find_crypto(
        registry,
        find_crypto_use_case=find_crypto_use_case,
        executor=executor,
    )
    register_find_dangerous_callers(
        registry,
        find_dangerous_callers_use_case=find_dangerous_callers_use_case,
        executor=executor,
    )
    register_detect_vulns(
        registry,
        detect_vulns_use_case=detect_vulns_use_case,
        executor=executor,
    )
    register_detect_stack_strings(
        registry,
        detect_stack_strings_use_case=detect_stack_strings_use_case,
        executor=executor,
    )
    register_trace_data_flow(
        registry,
        trace_data_flow_use_case=trace_data_flow_use_case,
        executor=executor,
    )
    register_trace_source_to_sink(
        registry,
        trace_source_to_sink_use_case=trace_source_to_sink_use_case,
        executor=executor,
    )
    register_list_strings(
        registry,
        list_strings_use_case=list_strings_use_case,
        executor=executor,
    )
    register_int_convert(
        registry,
        int_convert_use_case=int_convert_use_case,
        executor=executor,
    )
    register_get_bytes(
        registry,
        get_bytes_use_case=get_bytes_use_case,
        executor=executor,
    )
    register_get_int(
        registry,
        get_int_use_case=get_int_use_case,
        executor=executor,
    )
    register_get_string(
        registry,
        get_string_use_case=get_string_use_case,
        executor=executor,
    )
    register_get_global_value(
        registry,
        get_global_value_use_case=get_global_value_use_case,
        executor=executor,
    )
    register_search_text(
        registry,
        search_text_use_case=search_text_use_case,
        executor=executor,
    )
    register_find_regex(
        registry,
        find_regex_use_case=find_regex_use_case,
        executor=executor,
    )
    register_export_funcs(
        registry,
        export_funcs_use_case=export_funcs_use_case,
        executor=executor,
    )
    register_lookup_funcs(
        registry,
        lookup_funcs_use_case=lookup_funcs_use_case,
        executor=executor,
    )
    register_type_query(
        registry,
        type_query_use_case=type_query_use_case,
        executor=executor,
    )
    register_type_inspect(
        registry,
        type_inspect_use_case=type_inspect_use_case,
        executor=executor,
    )
    register_entity_query(
        registry,
        entity_query_use_case=entity_query_use_case,
        executor=executor,
    )
    register_func_query(
        registry,
        func_query_use_case=func_query_use_case,
        executor=executor,
    )
    register_imports_query(
        registry,
        imports_query_use_case=imports_query_use_case,
        executor=executor,
    )
    register_xref_query(
        registry,
        xref_query_use_case=xref_query_use_case,
        executor=executor,
    )
    register_insn_query(
        registry,
        insn_query_use_case=insn_query_use_case,
        executor=executor,
    )
    register_search_structs(
        registry,
        search_structs_use_case=search_structs_use_case,
        executor=executor,
    )
    register_read_struct(
        registry,
        read_struct_use_case=read_struct_use_case,
        executor=executor,
    )
    register_rename(
        registry,
        rename_use_case=rename_use_case,
        executor=executor,
    )
    register_set_comment(
        registry,
        set_comment_use_case=set_comment_use_case,
        executor=executor,
    )
    register_set_type(
        registry,
        set_type_use_case=set_type_use_case,
        executor=executor,
    )
    register_patch(
        registry,
        patch_use_case=patch_use_case,
        executor=executor,
    )
    register_patch_asm(
        registry,
        patch_asm_use_case=patch_asm_use_case,
        executor=executor,
    )
    register_make_data(
        registry,
        make_data_use_case=make_data_use_case,
        executor=executor,
    )
    register_define_func(
        registry,
        define_func_use_case=define_func_use_case,
        executor=executor,
    )
    register_undefine(
        registry,
        undefine_use_case=undefine_use_case,
        executor=executor,
    )
    register_set_op_type(
        registry,
        set_op_type_use_case=set_op_type_use_case,
        executor=executor,
    )
    register_define_code(
        registry,
        define_code_use_case=define_code_use_case,
        executor=executor,
    )
    register_declare_type(
        registry,
        declare_type_use_case=declare_type_use_case,
        executor=executor,
    )
    register_enum_upsert(
        registry,
        enum_upsert_use_case=enum_upsert_use_case,
        executor=executor,
    )
    register_declare_stack(
        registry,
        declare_stack_use_case=declare_stack_use_case,
        executor=executor,
    )
    register_delete_stack(
        registry,
        delete_stack_use_case=delete_stack_use_case,
        executor=executor,
    )
    register_add_bookmark(
        registry,
        add_bookmark_use_case=add_bookmark_use_case,
        executor=executor,
    )
    register_force_recompile(
        registry,
        force_recompile_use_case=force_recompile_use_case,
        executor=executor,
    )
    register_export_annotations(
        registry,
        export_annotations_use_case=export_annotations_use_case,
        executor=executor,
    )
    register_apply_annotations(
        registry,
        apply_annotations_use_case=apply_annotations_use_case,
        executor=executor,
    )
    register_idb_snapshot(
        registry,
        snapshot_use_case=snapshot_use_case,
        executor=executor,
    )
    register_survey_binary(
        registry,
        survey_binary_use_case=survey_binary_use_case,
        executor=executor,
    )
    register_analyze_function(
        registry,
        analyze_function_use_case=analyze_function_use_case,
        executor=executor,
    )
    register_analyze_component(
        registry,
        analyze_component_use_case=analyze_component_use_case,
        executor=executor,
    )
