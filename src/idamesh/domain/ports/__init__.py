"""Outbound port protocols the application programs against.

Each is a :class:`typing.Protocol`; infrastructure supplies the adapters. The
main-thread execution seam lives here as :class:`MainThreadExecutor`.
"""

from __future__ import annotations

from idamesh.domain.ports.basic_blocks import BasicBlockGateway
from idamesh.domain.ports.bookmark import BookmarkGateway
from idamesh.domain.ports.code_definition import CodeDefinitionGateway
from idamesh.domain.ports.comments import CommentGateway
from idamesh.domain.ports.data_definition import DataDefinitionGateway
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.decompiler import DecompilerGateway
from idamesh.domain.ports.disasm import DisassemblyGateway
from idamesh.domain.ports.enum import EnumGateway
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.globals import GlobalRepository
from idamesh.domain.ports.imports import ImportRepository
from idamesh.domain.ports.instruction import InstructionGateway
from idamesh.domain.ports.instruction_decode import InstructionDecodeGateway
from idamesh.domain.ports.listing_search import ListingSearchGateway
from idamesh.domain.ports.memory import MemoryGateway
from idamesh.domain.ports.naming import NamingGateway
from idamesh.domain.ports.operand import OperandGateway
from idamesh.domain.ports.patch import PatchGateway
from idamesh.domain.ports.recompile import RecompileGateway
from idamesh.domain.ports.search import SearchGateway
from idamesh.domain.ports.stack import StackGateway
from idamesh.domain.ports.strings import StringsRepository
from idamesh.domain.ports.structs import StructGateway
from idamesh.domain.ports.type_declaration import TypeDeclarationGateway
from idamesh.domain.ports.type_mutation import TypeMutationGateway
from idamesh.domain.ports.types import TypeGateway
from idamesh.domain.ports.xrefs import XrefRepository

__all__ = [
    "BasicBlockGateway",
    "BookmarkGateway",
    "CodeDefinitionGateway",
    "CommentGateway",
    "DataDefinitionGateway",
    "DatabaseGateway",
    "DecompilerGateway",
    "DisassemblyGateway",
    "EnumGateway",
    "MainThreadExecutor",
    "FunctionRepository",
    "GlobalRepository",
    "ImportRepository",
    "InstructionGateway",
    "InstructionDecodeGateway",
    "ListingSearchGateway",
    "MemoryGateway",
    "NamingGateway",
    "OperandGateway",
    "PatchGateway",
    "RecompileGateway",
    "SearchGateway",
    "StackGateway",
    "StringsRepository",
    "StructGateway",
    "TypeDeclarationGateway",
    "TypeGateway",
    "TypeMutationGateway",
    "XrefRepository",
]
