"""Catalog registration and wire-shape projection for ``find_crypto``.

The ``CryptoMatchView`` / ``FindCryptoView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`find_crypto_view` renders each
recognized constant into that flat shape (address as ``0x`` hex, plus the
algorithm and constant label that evidence it). The field names mirror the
interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.find_crypto import FindCryptoUseCase
from idamesh.application.dto.find_crypto import (
    DEFAULT_MATCH_LIMIT,
    FindCryptoCommand,
    FindCryptoResult,
)
from idamesh.domain.entities.crypto_match import CryptoMatch
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class CryptoMatchView(TypedDict):
    """One recognized crypto constant in a ``find_crypto`` result."""

    address: str
    algorithm: str
    constant: str


class FindCryptoView(TypedDict):
    """The cryptographic constants recognized across the image."""

    matches: List[CryptoMatchView]
    truncated: bool


def crypto_match_view(match: CryptoMatch) -> CryptoMatchView:
    """Project one :class:`CryptoMatch` into its wire shape (address as ``0x`` hex)."""
    return CryptoMatchView(
        address=match.address.hex(),
        algorithm=match.algorithm,
        constant=match.constant,
    )


def find_crypto_view(result: FindCryptoResult) -> FindCryptoView:
    """Project a ``find_crypto`` result into its wire shape."""
    return FindCryptoView(
        matches=[crypto_match_view(match) for match in result.matches],
        truncated=result.truncated,
    )


def register_find_crypto(
    registry: Registry,
    *,
    find_crypto_use_case: FindCryptoUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``find_crypto`` against the crypto-constant scan use-case."""

    @registry.tool(name="find_crypto")
    def find_crypto(limit: int = DEFAULT_MATCH_LIMIT) -> FindCryptoView:
        """Identify cryptography in the loaded image by its constant signatures.

        Scans for the magic constants that reference implementations embed — the
        AES S-box and inverse S-box, the MD5 / SHA-1 / SHA-256 initialization
        vectors, the reversed CRC-32 polynomial, the Base64 alphabets, and the
        like — and reports each hit's ``address`` (``0x`` hex), the ``algorithm``
        the constant belongs to, and a ``constant`` label naming which constant
        matched. ``limit`` caps how many matches are returned across the whole
        signature table (clamped to a server maximum); ``truncated`` is set when
        the cap elided further matches. Read-only."""
        command = FindCryptoCommand(limit=limit)
        result = run_use_case(
            executor, lambda: find_crypto_use_case.execute(command)
        )
        return find_crypto_view(result)
