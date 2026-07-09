"""Domain entities: the shapes returned to clients."""

from __future__ import annotations

from idamesh.domain.entities.analyze_function import FunctionAnalysis
from idamesh.domain.entities.basic_block import BasicBlock
from idamesh.domain.entities.bookmark import Bookmark
from idamesh.domain.entities.byte_match import ByteMatch
from idamesh.domain.entities.call_graph import (
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
)
from idamesh.domain.entities.code_definition import (
    FunctionDefinition,
    Undefinition,
)
from idamesh.domain.entities.comment import CommentEdit
from idamesh.domain.entities.component import Component, ComponentMember
from idamesh.domain.entities.crypto_match import CryptoMatch
from idamesh.domain.entities.dangerous_caller import (
    DangerousApiMatch,
    DangerousCaller,
)
from idamesh.domain.entities.data import Global
from idamesh.domain.entities.data_definition import DataDefinition
from idamesh.domain.entities.data_flow import DataFlowStep
from idamesh.domain.entities.decoded_instruction import (
    DecodedInstruction,
    Operand,
)
from idamesh.domain.entities.decompilation import Pseudocode
from idamesh.domain.entities.disasm import DisasmLine
from idamesh.domain.entities.enum_definition import EnumDefinition
from idamesh.domain.entities.func_profile import FuncProfile
from idamesh.domain.entities.func_ref import FuncRef
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.imports import Import
from idamesh.domain.entities.instruction_definition import InstructionDefinition
from idamesh.domain.entities.memory import (
    ByteRead,
    GlobalValue,
    IntRead,
    StringRead,
)
from idamesh.domain.entities.metadata import (
    DatabaseMetadata,
    Endianness,
    HealthStatus,
)
from idamesh.domain.entities.number_conversion import NumberConversion
from idamesh.domain.entities.operand_type import OperandTypeSetting
from idamesh.domain.entities.patch import AsmPatch, BytePatch
from idamesh.domain.entities.recompilation import Recompilation
from idamesh.domain.entities.rename import Renaming
from idamesh.domain.entities.stack_variable import (
    StackVariableDefinition,
    StackVariableDeletion,
)
from idamesh.domain.entities.stack_string import StackString
from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.entities.taint import TaintPath
from idamesh.domain.entities.struct_layout import StructField, StructLayout
from idamesh.domain.entities.struct_read import (
    StructFieldValue,
    StructReadResult,
)
from idamesh.domain.entities.struct_summary import StructSummary
from idamesh.domain.entities.survey import (
    BinarySurvey,
    NotableFunction,
    NotableImport,
    RoleTally,
    StringCategoryTally,
    SurveyCounts,
)
from idamesh.domain.entities.text_match import TextMatch
from idamesh.domain.entities.type_application import TypeApplication
from idamesh.domain.entities.type_declaration import TypeDeclaration
from idamesh.domain.entities.type_info import TypeInfo, TypeMember
from idamesh.domain.entities.vuln_finding import VulnFinding
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType

__all__ = [
    "AsmPatch",
    "BasicBlock",
    "BinarySurvey",
    "Bookmark",
    "BytePatch",
    "ByteMatch",
    "ByteRead",
    "CallGraph",
    "CallGraphEdge",
    "CallGraphNode",
    "CommentEdit",
    "Component",
    "ComponentMember",
    "CryptoMatch",
    "DangerousApiMatch",
    "DangerousCaller",
    "DataDefinition",
    "DataFlowStep",
    "DecodedInstruction",
    "Operand",
    "StackString",
    "TaintPath",
    "EnumDefinition",
    "FuncProfile",
    "FuncRef",
    "FunctionAnalysis",
    "FunctionDefinition",
    "Global",
    "NotableFunction",
    "NotableImport",
    "RoleTally",
    "StringCategoryTally",
    "SurveyCounts",
    "GlobalValue",
    "InstructionDefinition",
    "IntRead",
    "Pseudocode",
    "DisasmLine",
    "Function",
    "Undefinition",
    "Import",
    "DatabaseMetadata",
    "Endianness",
    "HealthStatus",
    "NumberConversion",
    "OperandTypeSetting",
    "Recompilation",
    "Renaming",
    "StackVariableDefinition",
    "StackVariableDeletion",
    "StringItem",
    "StringRead",
    "StructField",
    "StructFieldValue",
    "StructLayout",
    "StructReadResult",
    "StructSummary",
    "TextMatch",
    "TypeApplication",
    "TypeDeclaration",
    "TypeInfo",
    "TypeMember",
    "VulnFinding",
    "Xref",
    "XrefKind",
    "XrefType",
]
