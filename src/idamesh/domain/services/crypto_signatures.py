"""The crypto-signature service — a pure, IDA-free constant-signature table.

:class:`CryptoSignatureService` holds the byte-pattern table that names known
cryptographic algorithms by the constants their reference implementations embed:
the AES S-box / inverse S-box / Rcon round constants / Te0 T-table, the MD5,
SHA-1, SHA-256 and SHA-512 initialization vectors and round-constant tables, the
CRC-32 polynomials, the Blowfish π-derived P-array, the ChaCha20 / Salsa20 sigma
constants, the TEA/XTEA delta, the RC4 identity-permutation hint, and the
standard and URL-safe Base64 alphabets. Each entry is a :class:`CryptoSignature`
pairing an algorithm name and a human-readable constant label with the exact
bytes to look for; its :meth:`CryptoSignature.ida_pattern` renders those bytes
into the space-separated uppercase hexadecimal an IDA-style byte search consumes.

Only *published algorithmic facts* live here — the constant values are the same
in every correct implementation of each algorithm and are not copyrightable — but
the selection of which constants to signature, the labels, the byte layouts, and
the table's shape and ordering are our authored design. Keeping the table as a
stateless domain service makes it fully unit-testable with no IDA present; the
application layer walks the table and scans the image through the search gateway.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class CryptoSignature:
    """One named crypto constant and the bytes that identify it.

    ``algorithm`` is the algorithm the constant belongs to (e.g. ``"AES"``),
    ``constant`` a human-readable label for the specific constant (e.g.
    ``"S-box"``), and ``signature`` the exact byte sequence a correct
    implementation embeds. The bytes are a public fact; the label and grouping
    are ours.
    """

    algorithm: str
    constant: str
    signature: bytes

    def ida_pattern(self) -> str:
        """Render the signature bytes as an IDA-style hex byte pattern.

        Each byte becomes two uppercase hexadecimal digits, separated by single
        spaces (for example ``b"\\x63\\x7c"`` -> ``"63 7C"``) — the wildcard-free
        form :meth:`~idamesh.domain.ports.search.SearchGateway.find_bytes`
        accepts. These constant signatures are exact, so no byte is wildcarded.
        """
        return " ".join(f"{byte:02X}" for byte in self.signature)


# -- Published constant signatures ---------------------------------------------
#
# Every byte sequence below is a documented constant of the named algorithm,
# identical across correct implementations (a fact, not creative expression).
# Multi-byte words are laid out in the byte order the constant most commonly
# compiles to for each algorithm; the endianness choice is noted per entry and is
# the one that appears in a static table on a little-endian target (x86/x64).

# AES forward S-box, first 16 entries (FIPS-197 Figure 7).
_AES_SBOX = bytes(
    (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
     0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76)
)
# AES inverse S-box, first 16 entries (FIPS-197 Figure 14).
_AES_INV_SBOX = bytes(
    (0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
     0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB)
)
# AES key-schedule round constants Rcon[1..10] = x**(i-1) in GF(2**8) (FIPS-197
# §5.2), the powers-of-two-then-reduce sequence stored one byte per round.
_AES_RCON = bytes(
    (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
)
# AES fast-implementation forward T-table Te0[0..3], the encryption tables used
# by table-driven AES (e.g. OpenSSL). Words c66363a5 f87c7c84 ee777799 f67b7b8d
# stored little-endian as they appear in a 32-bit static array on x86/x64.
_AES_TE0 = bytes(
    (0xA5, 0x63, 0x63, 0xC6, 0x84, 0x7C, 0x7C, 0xF8,
     0x99, 0x77, 0x77, 0xEE, 0x8D, 0x7B, 0x7B, 0xF6)
)
# MD5 initialization vector A,B,C,D as stored little-endian (RFC 1321 §3.3).
_MD5_IV = bytes(
    (0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10)
)
# MD5 per-round sine table K[0..3] = floor(abs(sin(i+1)) * 2**32) (RFC 1321
# §3.4), first four 32-bit words stored little-endian.
_MD5_SINE = bytes(
    (0x78, 0xA4, 0x6A, 0xD7, 0x56, 0xB7, 0xC7, 0xE8,
     0xDB, 0x70, 0x20, 0x24, 0xEE, 0xCE, 0xBD, 0xC1)
)
# SHA-1 H0..H4 initialization vector, big-endian words (FIPS-180 §5.3.1).
_SHA1_IV = bytes(
    (0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89,
     0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76,
     0xC3, 0xD2, 0xE1, 0xF0)
)
# SHA-256 H0..H7 initialization vector, big-endian words (FIPS-180 §5.3.3).
_SHA256_IV = bytes(
    (0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85,
     0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A,
     0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C,
     0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19)
)
# SHA-256 round-constant table K[0..3], big-endian words (FIPS-180 §4.2.2). These
# cube-root constants often survive even when the IV is computed at runtime.
_SHA256_K = bytes(
    (0x42, 0x8A, 0x2F, 0x98, 0x71, 0x37, 0x44, 0x91,
     0xB5, 0xC0, 0xFB, 0xCF, 0xE9, 0xB5, 0xDB, 0xA5)
)
# SHA-512 H0..H3 initialization vector, big-endian 64-bit words (FIPS-180
# §5.3.5). The full 32-byte run disambiguates it from SHA-256 (whose H0 shares
# only the leading 6A 09 E6 67).
_SHA512_IV = bytes(
    (0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08,
     0xBB, 0x67, 0xAE, 0x85, 0x84, 0xCA, 0xA7, 0x3B,
     0x3C, 0x6E, 0xF3, 0x72, 0xFE, 0x94, 0xF8, 0x2B,
     0xA5, 0x4F, 0xF5, 0x3A, 0x5F, 0x1D, 0x36, 0xF1)
)
# Blowfish P-array seed, the fractional digits of pi P[0..3] (Schneier, 1993),
# big-endian words as the reference table stores them.
_BLOWFISH_PI = bytes(
    (0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
     0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44)
)
# ChaCha20 / Salsa20 256-bit-key sigma constant, the ASCII "expand 32-byte k"
# (Bernstein). Distinctive because it is stored verbatim as the state's first row.
_CHACHA_SIGMA = b"expand 32-byte k"
# ChaCha20 / Salsa20 128-bit-key tau constant, the ASCII "expand 16-byte k".
_CHACHA_TAU = b"expand 16-byte k"
# TEA / XTEA / XXTEA round delta 0x9E3779B9, derived from the golden ratio
# (Wheeler & Needham), as a little-endian 32-bit immediate.
_TEA_DELTA = bytes((0xB9, 0x79, 0x37, 0x9E))
# CRC-32 reversed (reflected) polynomial 0xEDB88320, as a little-endian 32-bit
# immediate — the form zlib/PNG-style table generators embed.
_CRC32_POLY_REV = bytes((0x20, 0x83, 0xB8, 0xED))
# CRC-32 normal (unreflected) polynomial 0x04C11DB7, as a little-endian 32-bit
# immediate — the form MSB-first CRC implementations embed.
_CRC32_POLY_FWD = bytes((0xB7, 0x1D, 0xC1, 0x04))
# RC4 key-scheduling identity permutation S[i] = i, first 16 bytes (Rivest). A
# weak *hint*: the ascending run 00..0F also occurs in unrelated tables, so it is
# ordered last and labelled a hint.
_RC4_IDENTITY = bytes(range(16))
# Standard Base64 alphabet (RFC 4648 §4).
_BASE64_STD = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"abcdefghijklmnopqrstuvwxyz"
    b"0123456789+/"
)
# URL- and filename-safe Base64 alphabet (RFC 4648 §5).
_BASE64_URL = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"abcdefghijklmnopqrstuvwxyz"
    b"0123456789-_"
)

#: The frozen signature table. Ordered most-distinctive first so a bounded scan
#: that stops on the match cap has still tried the strongest signposts: the long,
#: unambiguous runs (init vectors, T-tables, alphabets) precede the short 4-byte
#: immediates and the RC4 identity hint, which are the most collision-prone.
_SIGNATURES: Tuple[CryptoSignature, ...] = (
    CryptoSignature("AES", "S-box", _AES_SBOX),
    CryptoSignature("AES", "inverse S-box", _AES_INV_SBOX),
    CryptoSignature("AES", "Te0 T-table", _AES_TE0),
    CryptoSignature("AES", "Rcon round constants", _AES_RCON),
    CryptoSignature("SHA-512", "H0..H3 init vector", _SHA512_IV),
    CryptoSignature("SHA-256", "H0..H7 init vector", _SHA256_IV),
    CryptoSignature("SHA-256", "K0..K3 round constants", _SHA256_K),
    CryptoSignature("SHA-1", "H0..H4 init vector", _SHA1_IV),
    CryptoSignature("MD5", "A..D init vector", _MD5_IV),
    CryptoSignature("MD5", "K0..K3 sine table", _MD5_SINE),
    CryptoSignature("Blowfish", "P-array pi init", _BLOWFISH_PI),
    CryptoSignature("ChaCha20/Salsa20", 'sigma "expand 32-byte k"', _CHACHA_SIGMA),
    CryptoSignature("ChaCha20/Salsa20", 'tau "expand 16-byte k"', _CHACHA_TAU),
    CryptoSignature("Base64", "standard alphabet", _BASE64_STD),
    CryptoSignature("Base64", "URL-safe alphabet", _BASE64_URL),
    CryptoSignature("CRC-32", "reversed polynomial 0xEDB88320", _CRC32_POLY_REV),
    CryptoSignature("CRC-32", "normal polynomial 0x04C11DB7", _CRC32_POLY_FWD),
    CryptoSignature("TEA/XTEA", "delta 0x9E3779B9", _TEA_DELTA),
    CryptoSignature("RC4", "identity permutation hint", _RC4_IDENTITY),
)


class CryptoSignatureService:
    """Expose and query the pure table of cryptographic constant signatures."""

    def signatures(self) -> Tuple[CryptoSignature, ...]:
        """Return every constant signature, most-distinctive first.

        The order is stable and deterministic, so a bounded scan that stops on a
        match cap has always tried the longest, least-ambiguous signatures (the
        S-boxes, init vectors, T-tables and alphabets) before the short ones (a
        4-byte polynomial, the RC4 identity hint).
        """
        return _SIGNATURES

    def algorithms(self) -> Tuple[str, ...]:
        """Return the distinct algorithm names covered, in first-seen order."""
        seen: dict[str, None] = {}
        for signature in _SIGNATURES:
            seen.setdefault(signature.algorithm, None)
        return tuple(seen)

    def for_algorithm(self, algorithm: str) -> Tuple[CryptoSignature, ...]:
        """Return the signatures belonging to ``algorithm`` (case-insensitive).

        Empty when the algorithm is unknown; the table order is preserved.
        """
        key = algorithm.strip().casefold()
        return tuple(
            signature
            for signature in _SIGNATURES
            if signature.algorithm.casefold() == key
        )

    def match(self, data: bytes) -> Tuple[CryptoSignature, ...]:
        """Return every signature whose bytes occur contiguously within ``data``.

        A pure, IDA-free lookup: it answers "which known crypto constants does
        this blob contain?" over an in-memory buffer (a dumped ``.rdata``
        section, a captured constant pool, a test fixture), in table order. It
        does not scan the live image — that is the search gateway's job in the
        use-case — but shares the same signature table, so a hit here predicts a
        hit there.
        """
        blob = bytes(data)
        return tuple(
            signature for signature in _SIGNATURES if signature.signature in blob
        )
