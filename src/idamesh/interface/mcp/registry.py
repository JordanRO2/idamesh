"""The tool/resource/prompt registry and its decorators.

``Registry`` exposes ``@tool`` / ``@resource`` / ``@prompt`` plus facet markers
(``feature`` group, ``mutating`` / ``destructive`` hints). Registration eagerly
compiles the descriptor (via :mod:`schema`) so any signature mistake fails at
import, not at first call. Decorators return the original function unchanged so
domain call sites are unaffected.
"""

from __future__ import annotations

import inspect
import re
from typing import Any, Callable, Dict, Mapping, Optional, Sequence

from idamesh.interface.mcp.schema import TypeAdapter, compile_signature
from idamesh.interface.mcp.specs import ParamSpec, PromptSpec, ResourceSpec, ToolSpec

#: A decorator that returns the function it wraps unchanged.
Decorator = Callable[[Callable[..., Any]], Callable[..., Any]]

# Function attributes the facet markers stash for the ``@tool`` decorator to read.
_FEATURE_ATTR = "_idamesh_feature"
_ANNOTATIONS_ATTR = "_idamesh_annotations"

#: MCP tool-name charset: 1–128 chars of ``[A-Za-z0-9_.-]`` (spec §6.2 / digest).
_TOOL_NAME_RE = re.compile(r"\A[A-Za-z0-9_.-]{1,128}\Z")


def _validate_tool_name(name: str) -> None:
    """Enforce the MCP tool-name charset at registration (raises ``ValueError``)."""
    if not isinstance(name, str) or not _TOOL_NAME_RE.match(name):
        raise ValueError(
            f"invalid tool name {name!r}: must be 1-128 characters of "
            "[A-Za-z0-9_.-] with no spaces or commas"
        )


def _clean_doc(doc: Optional[str]) -> str:
    """Trim a docstring into a tool description; empty when absent."""
    if not doc:
        return ""
    return inspect.cleandoc(doc).strip()


class Registry:
    """Collects compiled tool/resource/prompt specs keyed by name/URI."""

    def __init__(self, *, adapters: Optional[Sequence[TypeAdapter]] = None) -> None:
        self._adapters = tuple(adapters) if adapters is not None else None
        self._tools: Dict[str, ToolSpec] = {}
        self._resources: Dict[str, ResourceSpec] = {}
        self._prompts: Dict[str, PromptSpec] = {}

    def tool(
        self,
        func: Optional[Callable[..., Any]] = None,
        *,
        name: Optional[str] = None,
    ) -> Any:
        """Register a tool. Usable bare (``@reg.tool``) or called
        (``@reg.tool(name=...)``); the name defaults to ``func.__name__``."""

        def register(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            _validate_tool_name(tool_name)
            params, input_schema, output_schema = compile_signature(
                fn, adapters=self._adapters
            )
            annotations = dict(getattr(fn, _ANNOTATIONS_ATTR, {}))
            # Unmarked tools are advertised read-only; ``mutating``/``destructive``
            # override this.
            if "readOnlyHint" not in annotations:
                annotations["readOnlyHint"] = True
            spec = ToolSpec(
                name=tool_name,
                description=_clean_doc(fn.__doc__),
                params=params,
                input_schema=input_schema,
                output_schema=output_schema,
                invoke=fn,
                feature=getattr(fn, _FEATURE_ATTR, None),
                annotations=annotations,
            )
            self._tools[tool_name] = spec
            return fn

        if func is not None:
            return register(func)
        return register

    def resource(
        self,
        uri: str,
        *,
        name: Optional[str] = None,
    ) -> Decorator:
        """Register an MCP resource. A ``{param}`` in ``uri`` marks it a template."""

        def register(fn: Callable[..., Any]) -> Callable[..., Any]:
            params, _input, _output = compile_signature(fn, adapters=self._adapters)
            is_template = "{" in uri and "}" in uri
            spec = ResourceSpec(
                uri=uri,
                name=name or fn.__name__,
                description=_clean_doc(fn.__doc__),
                invoke=fn,
                is_template=is_template,
                params=params,
            )
            self._resources[uri] = spec
            return fn

        return register

    def prompt(
        self,
        func: Optional[Callable[..., Any]] = None,
        *,
        name: Optional[str] = None,
    ) -> Any:
        """Register an MCP prompt."""

        def register(fn: Callable[..., Any]) -> Callable[..., Any]:
            params, _input, _output = compile_signature(fn, adapters=self._adapters)
            spec = PromptSpec(
                name=name or fn.__name__,
                description=_clean_doc(fn.__doc__),
                arguments=params,
                invoke=fn,
            )
            self._prompts[spec.name] = spec
            return fn

        if func is not None:
            return register(func)
        return register

    def feature(self, group: str) -> Decorator:
        """Tag the decorated tool as belonging to an optional feature group."""

        def mark(fn: Callable[..., Any]) -> Callable[..., Any]:
            setattr(fn, _FEATURE_ATTR, group)
            return fn

        return mark

    def mutating(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Mark a tool as non-read-only (sets ``readOnlyHint: false``)."""
        annotations = dict(getattr(func, _ANNOTATIONS_ATTR, {}))
        annotations["readOnlyHint"] = False
        setattr(func, _ANNOTATIONS_ATTR, annotations)
        return func

    def destructive(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Mark a tool as destructive (sets ``destructiveHint: true``)."""
        annotations = dict(getattr(func, _ANNOTATIONS_ATTR, {}))
        annotations["readOnlyHint"] = False
        annotations["destructiveHint"] = True
        setattr(func, _ANNOTATIONS_ATTR, annotations)
        return func

    def tools(self) -> Mapping[str, ToolSpec]:
        """All registered tool specs, keyed by name."""
        return dict(self._tools)

    def resources(self) -> Mapping[str, ResourceSpec]:
        """All registered resource specs, keyed by URI."""
        return dict(self._resources)

    def prompts(self) -> Mapping[str, PromptSpec]:
        """All registered prompt specs, keyed by name."""
        return dict(self._prompts)

    def get_tool(self, name: str) -> Optional[ToolSpec]:
        """The tool spec for ``name``, or ``None`` if unregistered."""
        return self._tools.get(name)
