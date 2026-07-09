"""The ``tools/call`` middleware pipeline.

Cross-cutting concerns compose as an ordered chain wrapping the tool invocation:
rate-limit -> feature/profile gate -> invoke -> output-guard. The output-size
limiter is simply the outermost middleware, not a post-hoc patch.
"""

from __future__ import annotations

import collections.abc as cabc
from typing import Any, Callable, Mapping, Optional, Sequence

from idamesh.interface.mcp.overflow import OverflowStore, canonical_json
from idamesh.interface.mcp.specs import RequestView, ToolResult, ToolSpec

#: The terminal/continuation callable a middleware delegates to.
Invoke = Callable[[ToolSpec, Mapping[str, Any], RequestView], ToolResult]

#: ``_meta`` key for the overflow marker. Our reverse-DNS-style prefix keeps
#: clear of the ``mcp``/``modelcontextprotocol`` reserved namespace.
OVERFLOW_META_KEY = "com.idamesh/overflow"


def _text(message: str) -> dict[str, Any]:
    return {"type": "text", "text": message}


class CallMiddleware:
    """One stage of the ``tools/call`` pipeline."""

    def __call__(
        self,
        spec: ToolSpec,
        arguments: Mapping[str, Any],
        ctx: RequestView,
        nxt: Invoke,
    ) -> ToolResult:
        """Do work, then call ``nxt`` (or short-circuit with a result)."""
        raise NotImplementedError


class RateLimitMiddleware(CallMiddleware):
    """Optional per-tool token-bucket rate limiting.

    Disabled by default (pass-through). When enabled, a real deployment would
    swap in a populated bucket table; the seam is here so the concern is
    composition, not a patch.
    """

    def __init__(self, *, enabled: bool = False) -> None:
        self._enabled = enabled

    def __call__(self, spec, arguments, ctx, nxt):  # type: ignore[override]
        return nxt(spec, arguments, ctx)


class FeatureGateMiddleware(CallMiddleware):
    """Block tools whose feature group / profile is not enabled for the request.

    A blocked tool returns an ``isError`` result (not a protocol error), so a
    tool the client could not see in ``tools/list`` is never silently run.

    Single-source-of-truth note: the **feature-group** gate is applied
    authoritatively by ``McpEngine.tools_call`` (via ``McpEngine._is_gated``)
    before the chain runs, so a default engine does not wire this middleware.
    This stage exists for the *profile* allow-list (doc 02 §8.5), which the
    engine does not implement; wire it into ``McpEngine(middlewares=[...])`` to
    activate profile filtering. Its feature-group branch intentionally mirrors
    ``_is_gated`` so the two never diverge if both run.
    """

    def __init__(self, *, profile: Optional[frozenset[str]] = None) -> None:
        self._profile = profile

    def __call__(self, spec, arguments, ctx, nxt):  # type: ignore[override]
        feature = spec.feature
        if feature is not None:
            features = getattr(ctx, "features", frozenset()) or frozenset()
            if feature not in features:
                return ToolResult(
                    content=(_text(f"Tool '{spec.name}' is not enabled for this session."),),
                    is_error=True,
                )
        if self._profile is not None and spec.name not in self._profile:
            return ToolResult(
                content=(_text(f"Tool '{spec.name}' is not in the active profile."),),
                is_error=True,
            )
        return nxt(spec, arguments, ctx)


class OutputGuardMiddleware(CallMiddleware):
    """Spill oversized structured results to the overflow store as the outermost stage."""

    def __init__(self, overflow: OverflowStore, *, budget_chars: int = 50_000) -> None:
        self._overflow = overflow
        self._budget_chars = budget_chars

    def __call__(self, spec, arguments, ctx, nxt):  # type: ignore[override]
        result = nxt(spec, arguments, ctx)
        structured = result.structured_content
        if result.is_error or structured is None:
            return result
        if len(canonical_json(structured)) <= self._budget_chars:
            return result

        ref = self._overflow.put(structured)
        preview = self._overflow.make_preview(structured, budget_chars=self._budget_chars)
        preview_obj = preview if isinstance(preview, cabc.Mapping) else {"result": preview}
        hint = (
            f"Result truncated to a preview ({ref.total_chars} chars total). "
            f"Read {ref.uri} via resources/read for the full payload."
        )
        meta = {
            OVERFLOW_META_KEY: {
                "truncated": True,
                "totalChars": ref.total_chars,
                "ref": ref.uri,
            }
        }
        return ToolResult(
            content=(_text(canonical_json(preview_obj)), _text(hint)),
            structured_content=preview_obj,
            is_error=False,
            meta=meta,
        )


def build_chain(middlewares: Sequence[CallMiddleware], terminal: Invoke) -> Invoke:
    """Fold ``middlewares`` (outermost first) around ``terminal`` into one callable."""
    chain = terminal
    for middleware in reversed(list(middlewares)):
        chain = _wrap(middleware, chain)
    return chain


def _wrap(middleware: CallMiddleware, nxt: Invoke) -> Invoke:
    def call(spec: ToolSpec, arguments: Mapping[str, Any], ctx: RequestView) -> ToolResult:
        return middleware(spec, arguments, ctx, nxt)

    return call
