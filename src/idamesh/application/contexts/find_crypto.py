"""The find_crypto use-case.

Detects cryptography by constant signatures: it walks the pure
:class:`~idamesh.domain.services.crypto_signatures.CryptoSignatureService` table,
turns each entry into an IDA-style byte pattern, and scans the image for it
through the reused :class:`~idamesh.domain.ports.search.SearchGateway` — no new
adapter. Every hit is tagged with the algorithm and constant it evidences and
aggregated under one bounded match budget.
"""

from __future__ import annotations

from typing import List

from idamesh.application.dto.find_crypto import (
    MAX_MATCH_LIMIT,
    FindCryptoCommand,
    FindCryptoResult,
)
from idamesh.domain.entities.crypto_match import CryptoMatch
from idamesh.domain.ports.search import SearchGateway
from idamesh.domain.services.crypto_signatures import CryptoSignatureService


class FindCryptoUseCase:
    """Scan the image for known crypto constants and label each hit.

    Clamps the requested match ``limit`` to :data:`MAX_MATCH_LIMIT`, then walks
    the signature table in its deterministic (most-distinctive-first) order. Each
    signature is rendered to an IDA-style hex pattern and searched via the
    :class:`~idamesh.domain.ports.search.SearchGateway`; every returned address
    becomes a :class:`~idamesh.domain.entities.crypto_match.CryptoMatch` carrying
    the algorithm and constant that matched. The aggregate is capped at the
    clamped limit, with ``truncated`` set when the cap (or a per-signature cap)
    elided further hits.
    """

    def __init__(
        self, search: SearchGateway, signatures: CryptoSignatureService
    ) -> None:
        self._search = search
        self._signatures = signatures

    def execute(self, command: FindCryptoCommand) -> FindCryptoResult:
        """Render each signature, scan for it, and aggregate the labeled hits.

        The requested budget is bounded to :data:`MAX_MATCH_LIMIT` first. Each
        signature is searched with the *remaining* budget so the total number of
        matches never exceeds the limit; the scan stops early once the budget is
        exhausted. ``truncated`` is set when the budget was reached with table
        entries still unscanned, or when a per-signature search filled its own
        remaining budget exactly (so further hits of that constant may exist). A
        signature whose pattern cannot be parsed by the gateway is skipped rather
        than failing the whole scan.
        """
        limit = min(command.limit, MAX_MATCH_LIMIT)
        if limit < 0:
            limit = 0

        matches: List[CryptoMatch] = []
        truncated = False

        for signature in self._signatures.signatures():
            if len(matches) >= limit:
                # Budget exhausted with signatures still unscanned: partial scan.
                truncated = True
                break
            remaining = limit - len(matches)
            try:
                addresses = self._search.find_bytes(
                    signature.ida_pattern(), remaining
                )
            except ValueError:
                # A signature the gateway cannot parse is a table defect, not a
                # client error — skip it rather than aborting every other scan.
                continue
            for address in addresses:
                matches.append(
                    CryptoMatch(
                        address=address,
                        algorithm=signature.algorithm,
                        constant=signature.constant,
                    )
                )
            # A search that exactly filled its budget was stopped on the cap, so
            # further hits of this constant may exist.
            if remaining > 0 and len(addresses) >= remaining:
                truncated = True

        return FindCryptoResult(matches=tuple(matches), truncated=truncated)
