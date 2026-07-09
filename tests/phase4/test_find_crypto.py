"""Unit tests for ``find_crypto`` — the crypto-constant scan (no IDA).

Three layers are exercised entirely off-host:

* the pure :class:`CryptoSignatureService` — its published constant *facts* (the
  AES S-box, the MD5/SHA/SHA-512 init vectors, the CRC-32 polynomials, the
  ChaCha20 sigma string, …), the IDA-pattern rendering, and the match/lookup API;
* the :class:`FindCryptoUseCase` — driven by a fake :class:`SearchGateway` that
  returns planted hits per pattern, so labelling, aggregation across the table,
  the decreasing per-signature budget, truncation inference, limit clamping, and
  unparseable-signature skipping are all asserted with no database; and
* the catalog projection and registration — the flat ``0x``-hex wire shape and
  the read-only tool wiring.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple, TypeVar

import pytest

from idamesh.application.contexts.find_crypto import FindCryptoUseCase
from idamesh.application.dto.find_crypto import (
    DEFAULT_MATCH_LIMIT,
    MAX_MATCH_LIMIT,
    FindCryptoCommand,
    FindCryptoResult,
)
from idamesh.domain.entities.crypto_match import CryptoMatch
from idamesh.domain.services.crypto_signatures import (
    CryptoSignature,
    CryptoSignatureService,
)
from idamesh.domain.values.address import Address
from idamesh.interface.catalog.find_crypto import (
    crypto_match_view,
    find_crypto_view,
    register_find_crypto,
)
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- fakes ------------------------------------------------------------------


class _FakeSearchGateway:
    """An in-memory ``SearchGateway`` returning planted hits keyed by pattern.

    ``hits`` maps an IDA-style pattern string to the addresses a scan for it
    should return; a pattern with no entry yields no matches. The port contract
    of returning *at most* ``limit`` addresses is honoured, and every
    ``(pattern, limit)`` call is recorded so the use-case's decreasing per-
    signature budget can be asserted. Any pattern in ``unparseable`` raises
    ``ValueError`` to model a signature the adapter cannot compile.
    """

    def __init__(
        self,
        hits: Dict[str, List[int]] | None = None,
        *,
        unparseable: frozenset[str] = frozenset(),
    ) -> None:
        self._hits = hits or {}
        self._unparseable = unparseable
        self.calls: List[Tuple[str, int]] = []

    def find_bytes(self, pattern: str, limit: int) -> List[Address]:
        self.calls.append((pattern, limit))
        if pattern in self._unparseable:
            raise ValueError(f"unparseable byte pattern: {pattern!r}")
        return [Address(ea) for ea in self._hits.get(pattern, [])][:limit]


@dataclass
class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording affinity."""

    write_flags: List[bool] = field(default_factory=list)

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# -- helpers ----------------------------------------------------------------


def _sig(service: CryptoSignatureService, algorithm: str, constant: str) -> CryptoSignature:
    """Return the one signature with the given algorithm/constant labels."""
    for signature in service.signatures():
        if signature.algorithm == algorithm and signature.constant == constant:
            return signature
    raise AssertionError(f"no signature {algorithm!r}/{constant!r} in the table")


def _pattern(service: CryptoSignatureService, algorithm: str, constant: str) -> str:
    return _sig(service, algorithm, constant).ida_pattern()


# -- service: the table of published facts ----------------------------------


def test_table_covers_the_expected_algorithm_families():
    algorithms = set(CryptoSignatureService().algorithms())
    # The families the tool advertises must all be present.
    assert {
        "AES",
        "SHA-1",
        "SHA-256",
        "SHA-512",
        "MD5",
        "CRC-32",
        "Base64",
        "RC4",
        "Blowfish",
        "ChaCha20/Salsa20",
        "TEA/XTEA",
    } <= algorithms


def test_every_signature_has_bytes_and_a_unique_label():
    signatures = CryptoSignatureService().signatures()
    assert signatures, "the table must not be empty"
    labels = [(s.algorithm, s.constant) for s in signatures]
    assert len(labels) == len(set(labels)), "each (algorithm, constant) is unique"
    assert all(len(s.signature) > 0 for s in signatures)


def test_ida_pattern_is_uppercase_hex_space_separated():
    for signature in CryptoSignatureService().signatures():
        pattern = signature.ida_pattern()
        tokens = pattern.split(" ")
        assert len(tokens) == len(signature.signature)
        assert pattern == " ".join(f"{b:02X}" for b in signature.signature)
        assert all(len(tok) == 2 and tok == tok.upper() for tok in tokens)
        # A constant signature is wildcard-free — the gateway gets exact bytes.
        assert "?" not in pattern


@pytest.mark.parametrize(
    "algorithm, constant, first_bytes",
    [
        # Published algorithmic facts — identical in every correct implementation.
        ("AES", "S-box", (0x63, 0x7C, 0x77, 0x7B)),
        ("AES", "inverse S-box", (0x52, 0x09, 0x6A, 0xD5)),
        ("AES", "Rcon round constants", (0x01, 0x02, 0x04, 0x08)),
        ("MD5", "A..D init vector", (0x01, 0x23, 0x45, 0x67)),
        ("SHA-1", "H0..H4 init vector", (0x67, 0x45, 0x23, 0x01)),
        ("SHA-256", "H0..H7 init vector", (0x6A, 0x09, 0xE6, 0x67)),
        ("SHA-512", "H0..H3 init vector", (0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08)),
        ("CRC-32", "reversed polynomial 0xEDB88320", (0x20, 0x83, 0xB8, 0xED)),
        ("CRC-32", "normal polynomial 0x04C11DB7", (0xB7, 0x1D, 0xC1, 0x04)),
        ("TEA/XTEA", "delta 0x9E3779B9", (0xB9, 0x79, 0x37, 0x9E)),
    ],
)
def test_known_constant_values_are_the_published_facts(algorithm, constant, first_bytes):
    signature = _sig(CryptoSignatureService(), algorithm, constant)
    assert signature.signature[: len(first_bytes)] == bytes(first_bytes)


def test_base64_alphabets_are_the_rfc4648_alphabets():
    service = CryptoSignatureService()
    std = _sig(service, "Base64", "standard alphabet").signature
    url = _sig(service, "Base64", "URL-safe alphabet").signature
    assert std == (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        b"abcdefghijklmnopqrstuvwxyz"
        b"0123456789+/"
    )
    # The URL-safe alphabet differs only in its final two symbols.
    assert url[:62] == std[:62]
    assert bytes(url[62:]) == b"-_"


def test_chacha_sigma_and_tau_are_the_expected_ascii():
    service = CryptoSignatureService()
    assert _sig(service, "ChaCha20/Salsa20", 'sigma "expand 32-byte k"').signature == (
        b"expand 32-byte k"
    )
    assert _sig(service, "ChaCha20/Salsa20", 'tau "expand 16-byte k"').signature == (
        b"expand 16-byte k"
    )


def test_specific_ida_patterns_render_as_expected():
    service = CryptoSignatureService()
    assert _pattern(service, "CRC-32", "reversed polynomial 0xEDB88320") == "20 83 B8 ED"
    assert _pattern(service, "AES", "S-box").startswith("63 7C 77 7B")
    assert _pattern(service, "ChaCha20/Salsa20", 'sigma "expand 32-byte k"') == (
        "65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B"
    )


def test_table_is_ordered_most_distinctive_first():
    signatures = CryptoSignatureService().signatures()
    lengths = [len(s.signature) for s in signatures]
    # The short, collision-prone immediates and the RC4 identity hint sit late:
    # the AES S-box (a strong 16-byte signpost) precedes any 4-byte entry.
    sbox_idx = next(i for i, s in enumerate(signatures) if s.constant == "S-box")
    four_byte_idxs = [i for i, n in enumerate(lengths) if n == 4]
    assert four_byte_idxs, "expected some 4-byte immediates"
    assert sbox_idx < min(four_byte_idxs)
    # The RC4 identity permutation is the weakest hint — it is dead last.
    assert signatures[-1].algorithm == "RC4"


# -- service: the match / lookup API ----------------------------------------


def test_for_algorithm_filters_case_insensitively():
    service = CryptoSignatureService()
    aes = service.for_algorithm("aes")
    assert len(aes) >= 3
    assert {s.algorithm for s in aes} == {"AES"}
    # Case and surrounding whitespace do not matter.
    assert service.for_algorithm("  AES ") == aes


def test_for_algorithm_unknown_returns_empty():
    assert CryptoSignatureService().for_algorithm("Twofish") == ()


def test_algorithms_are_distinct_and_in_first_seen_order():
    service = CryptoSignatureService()
    algorithms = service.algorithms()
    assert len(algorithms) == len(set(algorithms))
    assert algorithms[0] == "AES"  # the table opens with the AES group


def test_match_finds_every_embedded_constant_in_table_order():
    service = CryptoSignatureService()
    sbox = _sig(service, "AES", "S-box").signature
    sigma = _sig(service, "ChaCha20/Salsa20", 'sigma "expand 32-byte k"').signature
    blob = b"\x00\x01\x02" + sbox + b"padding" + sigma + b"\xff"

    hits = service.match(blob)

    labels = [(h.algorithm, h.constant) for h in hits]
    assert ("AES", "S-box") in labels
    assert ("ChaCha20/Salsa20", 'sigma "expand 32-byte k"') in labels
    # Order follows the table, not the blob: AES precedes ChaCha here.
    assert labels.index(("AES", "S-box")) < labels.index(
        ("ChaCha20/Salsa20", 'sigma "expand 32-byte k"')
    )


def test_match_empty_blob_matches_nothing():
    assert CryptoSignatureService().match(b"") == ()


def test_match_requires_the_whole_signature_contiguously():
    service = CryptoSignatureService()
    sbox = _sig(service, "AES", "S-box").signature
    # A truncated S-box (missing its last byte) must not be reported as AES.
    truncated = sbox[:-1]
    labels = [(h.algorithm, h.constant) for h in service.match(truncated)]
    assert ("AES", "S-box") not in labels


# -- use-case: labelling & aggregation --------------------------------------


def test_planted_hit_is_labelled_with_algorithm_and_constant():
    service = CryptoSignatureService()
    sbox_pattern = _pattern(service, "AES", "S-box")
    gateway = _FakeSearchGateway({sbox_pattern: [0x401000, 0x402000]})
    use_case = FindCryptoUseCase(gateway, service)

    result = use_case.execute(FindCryptoCommand(limit=64))

    assert isinstance(result, FindCryptoResult)
    assert result.matches == (
        CryptoMatch(address=Address(0x401000), algorithm="AES", constant="S-box"),
        CryptoMatch(address=Address(0x402000), algorithm="AES", constant="S-box"),
    )
    assert result.truncated is False


def test_aggregates_hits_across_multiple_signatures():
    service = CryptoSignatureService()
    sbox_pattern = _pattern(service, "AES", "S-box")
    sha_pattern = _pattern(service, "SHA-256", "H0..H7 init vector")
    gateway = _FakeSearchGateway(
        {sbox_pattern: [0x401000], sha_pattern: [0x403000, 0x404000]}
    )
    use_case = FindCryptoUseCase(gateway, service)

    result = use_case.execute(FindCryptoCommand(limit=64))

    labelled = {(m.algorithm, m.constant, m.address.value) for m in result.matches}
    assert labelled == {
        ("AES", "S-box", 0x401000),
        ("SHA-256", "H0..H7 init vector", 0x403000),
        ("SHA-256", "H0..H7 init vector", 0x404000),
    }
    assert result.truncated is False


def test_every_signature_is_scanned_when_budget_is_ample():
    service = CryptoSignatureService()
    gateway = _FakeSearchGateway({})
    use_case = FindCryptoUseCase(gateway, service)

    use_case.execute(FindCryptoCommand(limit=MAX_MATCH_LIMIT))

    # One search per table entry, each rendered from its signature.
    scanned = [pattern for pattern, _ in gateway.calls]
    assert scanned == [s.ida_pattern() for s in service.signatures()]


def test_empty_scan_is_not_truncated():
    service = CryptoSignatureService()
    gateway = _FakeSearchGateway({})
    use_case = FindCryptoUseCase(gateway, service)

    result = use_case.execute(FindCryptoCommand(limit=64))

    assert result.matches == ()
    assert result.truncated is False


# -- use-case: budget, clamping, truncation ---------------------------------


def test_default_limit_applied_when_omitted():
    service = CryptoSignatureService()
    gateway = _FakeSearchGateway({})
    use_case = FindCryptoUseCase(gateway, service)

    use_case.execute(FindCryptoCommand())

    # The first (empty) scan sees the full default budget.
    assert gateway.calls[0][1] == DEFAULT_MATCH_LIMIT


def test_limit_is_clamped_to_the_server_maximum():
    service = CryptoSignatureService()
    gateway = _FakeSearchGateway({})
    use_case = FindCryptoUseCase(gateway, service)

    use_case.execute(FindCryptoCommand(limit=1_000_000))

    # The gateway never sees the raw oversized limit — only the clamp.
    assert gateway.calls[0][1] == MAX_MATCH_LIMIT


def test_per_signature_budget_decreases_as_matches_accumulate():
    service = CryptoSignatureService()
    sbox_pattern = _pattern(service, "AES", "S-box")
    gateway = _FakeSearchGateway({sbox_pattern: [0x401000, 0x402000]})
    use_case = FindCryptoUseCase(gateway, service)

    use_case.execute(FindCryptoCommand(limit=10))

    # The first signature (S-box) took the full budget of 10; after two hits the
    # second signature is searched with the remaining 8.
    assert gateway.calls[0] == (sbox_pattern, 10)
    assert gateway.calls[1][1] == 8


def test_budget_exhausted_flags_truncation_and_stops_early():
    service = CryptoSignatureService()
    sbox_pattern = _pattern(service, "AES", "S-box")
    # More hits than the budget on the very first signature.
    gateway = _FakeSearchGateway(
        {sbox_pattern: [0x401000, 0x402000, 0x403000, 0x404000, 0x405000]}
    )
    use_case = FindCryptoUseCase(gateway, service)

    result = use_case.execute(FindCryptoCommand(limit=3))

    assert len(result.matches) == 3
    assert all(m.algorithm == "AES" for m in result.matches)
    assert result.truncated is True
    # The budget filled on the first signature, so no later signature was scanned.
    assert len(gateway.calls) == 1


def test_partial_fill_across_the_whole_table_is_not_truncated():
    service = CryptoSignatureService()
    sbox_pattern = _pattern(service, "AES", "S-box")
    gateway = _FakeSearchGateway({sbox_pattern: [0x401000, 0x402000]})
    use_case = FindCryptoUseCase(gateway, service)

    result = use_case.execute(FindCryptoCommand(limit=64))

    assert len(result.matches) == 2
    assert result.truncated is False
    # Every table entry got a scan because the budget was never exhausted.
    assert len(gateway.calls) == len(service.signatures())


def test_zero_limit_returns_nothing_and_reports_truncation():
    # limit==0 clamps the budget shut before the first scan; the tool reports
    # truncation because unscanned signatures may still hold matches.
    service = CryptoSignatureService()
    gateway = _FakeSearchGateway({})
    use_case = FindCryptoUseCase(gateway, service)

    result = use_case.execute(FindCryptoCommand(limit=0))

    assert result.matches == ()
    assert result.truncated is True
    assert gateway.calls == []  # nothing was scanned


def test_negative_limit_is_clamped_to_zero():
    service = CryptoSignatureService()
    gateway = _FakeSearchGateway({})
    use_case = FindCryptoUseCase(gateway, service)

    result = use_case.execute(FindCryptoCommand(limit=-5))

    assert result.matches == ()
    assert result.truncated is True
    assert gateway.calls == []


# -- use-case: robustness ---------------------------------------------------


def test_unparseable_signature_is_skipped_not_fatal():
    service = CryptoSignatureService()
    sbox_pattern = _pattern(service, "AES", "S-box")
    crc_pattern = _pattern(service, "CRC-32", "reversed polynomial 0xEDB88320")
    # The S-box pattern is rejected by the gateway; the CRC hit must still land.
    gateway = _FakeSearchGateway(
        {crc_pattern: [0x409000]},
        unparseable=frozenset({sbox_pattern}),
    )
    use_case = FindCryptoUseCase(gateway, service)

    result = use_case.execute(FindCryptoCommand(limit=64))

    labels = [(m.algorithm, m.constant, m.address.value) for m in result.matches]
    assert ("CRC-32", "reversed polynomial 0xEDB88320", 0x409000) in labels
    # The rejected signature contributed nothing but did not abort the scan.
    assert not any(m.constant == "S-box" for m in result.matches)
    assert sbox_pattern in [p for p, _ in gateway.calls]


# -- view projection --------------------------------------------------------


def test_crypto_match_view_projects_flat_shape():
    view = crypto_match_view(
        CryptoMatch(address=Address(0x14000A), algorithm="AES", constant="S-box")
    )
    assert view == {"address": "0x14000a", "algorithm": "AES", "constant": "S-box"}


def test_find_crypto_view_projects_result_to_wire_shape():
    result = FindCryptoResult(
        matches=(
            CryptoMatch(address=Address(0x401000), algorithm="AES", constant="S-box"),
            CryptoMatch(
                address=Address(0x402000),
                algorithm="CRC-32",
                constant="reversed polynomial 0xEDB88320",
            ),
        ),
        truncated=True,
    )

    view = find_crypto_view(result)

    assert view["matches"] == [
        {"address": "0x401000", "algorithm": "AES", "constant": "S-box"},
        {
            "address": "0x402000",
            "algorithm": "CRC-32",
            "constant": "reversed polynomial 0xEDB88320",
        },
    ]
    assert view["truncated"] is True


def test_find_crypto_view_projects_empty_result():
    view = find_crypto_view(FindCryptoResult(matches=(), truncated=False))
    assert view == {"matches": [], "truncated": False}


# -- catalog registration ---------------------------------------------------


def _register(gateway, executor) -> Registry:
    registry = Registry()
    register_find_crypto(
        registry,
        find_crypto_use_case=FindCryptoUseCase(gateway, CryptoSignatureService()),
        executor=executor,
    )
    return registry


def test_find_crypto_is_registered_read_only():
    registry = _register(_FakeSearchGateway({}), _InlineExecutor())

    spec = registry.get_tool("find_crypto")
    assert spec is not None
    # A pure constant scan mutates nothing.
    assert spec.annotations["readOnlyHint"] is True
    assert "destructiveHint" not in spec.annotations


def test_find_crypto_tool_invocation_returns_wire_shape():
    service = CryptoSignatureService()
    sbox_pattern = _pattern(service, "AES", "S-box")
    gateway = _FakeSearchGateway({sbox_pattern: [0x401000]})
    executor = _InlineExecutor()
    registry = _register(gateway, executor)

    view = registry.get_tool("find_crypto").invoke(limit=64)

    assert view == {
        "matches": [
            {"address": "0x401000", "algorithm": "AES", "constant": "S-box"}
        ],
        "truncated": False,
    }
    # The scan ran through the executor exactly once.
    assert len(executor.write_flags) == 1
