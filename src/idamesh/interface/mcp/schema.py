"""Schema compiler: Python type hints -> JSON Schema 2020-12 + coercers.

``compile_signature`` reflects a function once and, for each parameter, resolves
a :class:`Compiled` ``(schema, coerce)`` by walking an ordered
:class:`TypeAdapter` registry (first ``match`` wins; adapters recurse through the
shared :class:`SchemaContext`). Adding a supported annotation is a new adapter,
not a new branch. The same pass yields the precomputed ``input_schema`` and the
object-rooted ``output_schema`` MCP requires.
"""

from __future__ import annotations

import collections.abc as cabc
import enum
import inspect
import json
from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Literal,
    Optional,
    Sequence,
    Tuple,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

from idamesh.interface.mcp.specs import Coercer, ParamSpec

#: A JSON Schema fragment.
JsonSchema = dict

# PEP 604 unions (``X | Y``) are a distinct runtime type on 3.10+.
try:  # pragma: no cover - version dependent
    from types import UnionType as _UnionType
except ImportError:  # pragma: no cover
    _UnionType = None  # type: ignore[assignment]

# ``Required`` / ``NotRequired`` live in ``typing`` on 3.11+; treated as absent
# otherwise (they only affect TypedDict fields, handled there directly).
try:  # pragma: no cover - version dependent
    from typing import NotRequired as _NotRequired
    from typing import Required as _Required
except ImportError:  # pragma: no cover
    _Required = None  # type: ignore[assignment]
    _NotRequired = None  # type: ignore[assignment]

_NONE_TYPE = type(None)
_MISSING = object()


class CoercionError(ValueError):
    """A per-parameter coercion failure. Carries the offending ``param`` name.

    The engine's argument binder catches this and re-raises it as an
    ``INVALID_PARAMS`` protocol error with the parameter name attached.
    """

    def __init__(self, message: str, *, param: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.param = param


@dataclass(frozen=True)
class Compiled:
    """The compiled result for a single type: its schema and its coercer."""

    schema: JsonSchema
    coerce: Coercer
    required: bool = True


class TypeAdapter:
    """Strategy mapping a Python type to a :class:`Compiled` fragment.

    Implementations override :meth:`match` and :meth:`build`. They are consulted
    in priority order by a :class:`SchemaContext`.
    """

    def match(self, tp: Any) -> bool:
        """``True`` when this adapter handles ``tp``."""
        raise NotImplementedError

    def build(self, tp: Any, ctx: "SchemaContext") -> Compiled:
        """Compile ``tp`` (recursing into element types through ``ctx``)."""
        raise NotImplementedError


class SchemaContext:
    """Ordered adapter registry + the recursive ``build`` entry point."""

    def __init__(self, adapters: Sequence[TypeAdapter]) -> None:
        self._adapters = tuple(adapters)

    @property
    def adapters(self) -> tuple[TypeAdapter, ...]:
        return self._adapters

    def build(self, tp: Any) -> Compiled:
        """Resolve ``tp`` against the registry; first matching adapter wins."""
        for adapter in self._adapters:
            if adapter.match(tp):
                return adapter.build(tp, self)
        # The fallback adapter matches everything, so this is unreachable when
        # the default chain is in use; it guards against a truncated registry.
        raise TypeError(f"no schema adapter matched type {tp!r}")


# --------------------------------------------------------------------------- #
# Shared coercion helpers
# --------------------------------------------------------------------------- #


def _json_rescue(value: Any) -> Any:
    """If ``value`` is a JSON string, parse it once; else return it unchanged.

    Some MCP clients send an ``object``/``array`` field as a *string* containing
    JSON. Structured coercers attempt this rescue before failing.
    """
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def _coerce_scalar(value: Any, tp: type) -> Any:
    if tp is bool:
        if isinstance(value, bool):
            return value
        raise CoercionError(f"expected boolean, got {type(value).__name__}")
    if tp is int:
        # ``bool`` is an ``int`` subclass; reject it so ``true`` never silently
        # becomes ``1``.
        if isinstance(value, bool):
            raise CoercionError("expected integer, got boolean")
        if isinstance(value, int):
            return value
        raise CoercionError(f"expected integer, got {type(value).__name__}")
    if tp is float:
        if isinstance(value, bool):
            raise CoercionError("expected number, got boolean")
        if isinstance(value, int):
            return float(value)  # int widens to float
        if isinstance(value, float):
            return value
        raise CoercionError(f"expected number, got {type(value).__name__}")
    if tp is str:
        if isinstance(value, str):
            return value
        raise CoercionError(f"expected string, got {type(value).__name__}")
    if tp is _NONE_TYPE:
        if value is None:
            return None
        raise CoercionError(f"expected null, got {type(value).__name__}")
    raise CoercionError(f"unsupported scalar type {tp!r}")


def _try_members(value: Any, members: Sequence[Compiled]) -> Any:
    """Try each union member coercer, with a single JSON-string rescue."""
    for member in members:
        try:
            return member.coerce(value)
        except (CoercionError, ValueError, TypeError):
            continue
    rescued = _json_rescue(value)
    if rescued is not value and not (isinstance(value, str) and rescued == value):
        for member in members:
            try:
                return member.coerce(rescued)
            except (CoercionError, ValueError, TypeError):
                continue
    raise CoercionError(f"value {value!r} did not match any accepted type")


def _nullable(schema: JsonSchema) -> JsonSchema:
    """Return a schema equivalent to ``schema`` that also permits ``null``.

    A plain scalar type is widened in place (``{"type": "string"}`` ->
    ``{"type": ["string", "null"]}``); a value-constrained schema (``enum`` /
    ``const``) or one without a simple scalar type is unioned with
    ``{"type": "null"}`` so its original constraints survive. An unconstrained
    ``{}`` already admits null. This keeps a null-valued ``Optional`` field valid
    against its own declared schema (MCP requires ``structuredContent`` to
    conform to the tool's ``outputSchema``).
    """
    if not schema:
        return schema
    constrained = "enum" in schema or "const" in schema
    tp = schema.get("type")
    if not constrained and isinstance(tp, str) and tp != "null":
        widened = dict(schema)
        widened["type"] = [tp, "null"]
        return widened
    if not constrained and isinstance(tp, list) and "null" not in tp:
        widened = dict(schema)
        widened["type"] = [*tp, "null"]
        return widened
    return {"anyOf": [schema, {"type": "null"}]}


# --------------------------------------------------------------------------- #
# Adapters (ordered by priority in ``default_adapters``)
# --------------------------------------------------------------------------- #


class AnyAdapter(TypeAdapter):
    """``Any`` / bare ``object`` -> unconstrained schema, pass-through coerce."""

    def match(self, tp: Any) -> bool:
        return tp is Any or tp is object

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        return Compiled(schema={}, coerce=lambda v: v)


class AnnotatedAdapter(TypeAdapter):
    """``Annotated[T, ...]`` -> inner schema plus description/constraints."""

    def match(self, tp: Any) -> bool:
        return hasattr(tp, "__metadata__") and hasattr(tp, "__origin__")

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        inner = ctx.build(tp.__origin__)
        schema = dict(inner.schema)
        for meta in tp.__metadata__:
            if isinstance(meta, str):
                schema.setdefault("description", meta)
            elif isinstance(meta, cabc.Mapping):
                schema.update(dict(meta))
        return Compiled(schema=schema, coerce=inner.coerce, required=inner.required)


class WrapperAdapter(TypeAdapter):
    """``Required[T]`` / ``NotRequired[T]`` -> inner schema, toggling required."""

    def match(self, tp: Any) -> bool:
        if _Required is None:
            return False
        origin = get_origin(tp)
        return origin is _Required or origin is _NotRequired

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        (inner_tp,) = get_args(tp)
        inner = ctx.build(inner_tp)
        required = get_origin(tp) is _Required
        return Compiled(schema=inner.schema, coerce=inner.coerce, required=required)


class LiteralAdapter(TypeAdapter):
    """``Literal[...]`` -> ``{"enum": [...]}`` with an inferred scalar type."""

    def match(self, tp: Any) -> bool:
        return get_origin(tp) is Literal

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        values = list(get_args(tp))
        schema: JsonSchema = {"enum": values}
        types = {type(v) for v in values}
        if types == {bool}:
            schema["type"] = "boolean"
        elif types and types <= {int}:
            schema["type"] = "integer"
        elif types and types <= {str}:
            schema["type"] = "string"
        allowed = list(values)

        def coerce(value: Any) -> Any:
            for candidate in allowed:
                if type(value) is type(candidate) and value == candidate:
                    return value
            raise CoercionError(f"expected one of {allowed!r}, got {value!r}")

        return Compiled(schema=schema, coerce=coerce)


class EnumAdapter(TypeAdapter):
    """An ``enum.Enum`` subclass -> ``{"enum": [values]}``; value -> member."""

    def match(self, tp: Any) -> bool:
        return isinstance(tp, type) and issubclass(tp, enum.Enum)

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        members = list(tp)
        schema: JsonSchema = {"enum": [m.value for m in members]}

        def coerce(value: Any) -> Any:
            if isinstance(value, tp):
                return value
            for member in members:
                if member.value == value:
                    return member
            raise CoercionError(
                f"expected one of {[m.value for m in members]!r}, got {value!r}"
            )

        return Compiled(schema=schema, coerce=coerce)


class UnionAdapter(TypeAdapter):
    """``Union[...]`` / ``Optional[T]`` / ``X | Y`` -> ``anyOf`` (or bare T)."""

    def match(self, tp: Any) -> bool:
        if get_origin(tp) is Union:
            return True
        return _UnionType is not None and isinstance(tp, _UnionType)

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        args = list(get_args(tp))
        has_none = _NONE_TYPE in args
        non_none = [a for a in args if a is not _NONE_TYPE]
        members = [ctx.build(a) for a in non_none]

        if len(members) == 1:
            # ``T | None`` -> T's schema widened to also accept null, marked
            # not-required. Emitting a null-permitting schema (not the bare inner
            # one) keeps a null-valued optional field valid against the declared
            # outputSchema.
            inner = members[0]

            def coerce_single(value: Any, _inner: Compiled = inner) -> Any:
                if value is None:
                    return None
                return _try_members(value, [_inner])

            schema = _nullable(dict(inner.schema)) if has_none else dict(inner.schema)
            return Compiled(
                schema=schema,
                coerce=coerce_single,
                required=not has_none,
            )

        branches = [m.schema for m in members]
        if has_none:
            # An explicit null branch so the schema — not just the coercer —
            # admits null for a multi-member ``Optional`` union.
            branches.append({"type": "null"})
        schema: JsonSchema = {"anyOf": branches}

        def coerce_multi(value: Any, _members: Sequence[Compiled] = members) -> Any:
            if value is None and has_none:
                return None
            return _try_members(value, _members)

        return Compiled(schema=schema, coerce=coerce_multi, required=not has_none)


class TypedDictAdapter(TypeAdapter):
    """A ``TypedDict`` class -> object schema with per-field required flags."""

    def match(self, tp: Any) -> bool:
        return (
            isinstance(tp, type)
            and issubclass(tp, dict)
            and hasattr(tp, "__annotations__")
            and hasattr(tp, "__required_keys__")
            and hasattr(tp, "__optional_keys__")
        )

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        hints = get_type_hints(tp, include_extras=True)
        declared_required = set(getattr(tp, "__required_keys__", frozenset()))
        properties: dict[str, JsonSchema] = {}
        fields: dict[str, Compiled] = {}
        required: list[str] = []
        for key, hint in hints.items():
            compiled = ctx.build(hint)
            properties[key] = compiled.schema
            fields[key] = compiled
            if key in declared_required and compiled.required:
                required.append(key)
        schema: JsonSchema = {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        if required:
            schema["required"] = required

        def coerce(value: Any) -> Any:
            value = _json_rescue(value)
            if not isinstance(value, cabc.Mapping):
                raise CoercionError(f"expected object, got {type(value).__name__}")
            unknown = set(value) - set(fields)
            if unknown:
                raise CoercionError(f"unexpected keys: {sorted(unknown)}")
            missing = [key for key in required if key not in value]
            if missing:
                raise CoercionError(f"missing required keys: {missing}")
            return {key: fields[key].coerce(val) for key, val in value.items()}

        return Compiled(schema=schema, coerce=coerce)


class ListAdapter(TypeAdapter):
    """``list[T]`` / ``Sequence[T]`` / ``tuple[T, ...]`` -> array schema."""

    def match(self, tp: Any) -> bool:
        origin = get_origin(tp)
        return origin in (
            list,
            tuple,
            cabc.Sequence,
            cabc.MutableSequence,
        ) or tp in (list, tuple)

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        args = [a for a in get_args(tp) if a is not Ellipsis]
        item = ctx.build(args[0]) if args else Compiled(schema={}, coerce=lambda v: v)
        schema: JsonSchema = {"type": "array", "items": item.schema}

        def coerce(value: Any) -> Any:
            value = _json_rescue(value)
            if not isinstance(value, (list, tuple)):
                raise CoercionError(f"expected array, got {type(value).__name__}")
            return [item.coerce(element) for element in value]

        return Compiled(schema=schema, coerce=coerce)


class MappingAdapter(TypeAdapter):
    """``dict[str, V]`` / ``Mapping[str, V]`` -> object with ``additionalProperties``."""

    def match(self, tp: Any) -> bool:
        origin = get_origin(tp)
        return origin in (
            dict,
            cabc.Mapping,
            cabc.MutableMapping,
        ) or tp is dict

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        args = get_args(tp)
        value_compiled = (
            ctx.build(args[1]) if len(args) == 2 else Compiled(schema={}, coerce=lambda v: v)
        )
        schema: JsonSchema = {
            "type": "object",
            "additionalProperties": value_compiled.schema,
        }

        def coerce(value: Any) -> Any:
            value = _json_rescue(value)
            if not isinstance(value, cabc.Mapping):
                raise CoercionError(f"expected object, got {type(value).__name__}")
            return {key: value_compiled.coerce(val) for key, val in value.items()}

        return Compiled(schema=schema, coerce=coerce)


class ScalarAdapter(TypeAdapter):
    """``int`` / ``float`` / ``str`` / ``bool`` / ``None`` -> primitive schema."""

    _KEYWORDS = {
        int: "integer",
        float: "number",
        str: "string",
        bool: "boolean",
        _NONE_TYPE: "null",
    }

    def match(self, tp: Any) -> bool:
        return tp in self._KEYWORDS

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        schema: JsonSchema = {"type": self._KEYWORDS[tp]}

        def coerce(value: Any, _tp: type = tp) -> Any:
            return _coerce_scalar(value, _tp)

        return Compiled(schema=schema, coerce=coerce)


class FallbackAdapter(TypeAdapter):
    """Anything else -> best-effort object schema, pass-through coerce."""

    def match(self, tp: Any) -> bool:
        return True

    def build(self, tp: Any, ctx: SchemaContext) -> Compiled:
        return Compiled(schema={"type": "object"}, coerce=lambda v: v)


def default_adapters() -> tuple[TypeAdapter, ...]:
    """The built-in adapter chain (Any, Annotated, wrappers, Literal/Enum,
    Union, TypedDict, list/Sequence, dict, scalars, fallback), in priority order."""
    return (
        AnyAdapter(),
        AnnotatedAdapter(),
        WrapperAdapter(),
        LiteralAdapter(),
        EnumAdapter(),
        UnionAdapter(),
        TypedDictAdapter(),
        ListAdapter(),
        MappingAdapter(),
        ScalarAdapter(),
        FallbackAdapter(),
    )


# --------------------------------------------------------------------------- #
# Output-schema normalization
# --------------------------------------------------------------------------- #


def _object_rooted(schema: JsonSchema) -> JsonSchema:
    """Normalize a return schema to an object root, as MCP's ``outputSchema`` and
    ``structuredContent`` require.

    An object-shaped schema is emitted as-is; an ``anyOf`` whose branches are all
    object-shaped gets an explicit ``type:"object"`` hoisted alongside it; any
    other schema is wrapped under a ``result`` property.
    """
    if schema.get("type") == "object":
        return schema
    branches = schema.get("anyOf")
    if isinstance(branches, list) and branches and all(
        isinstance(b, cabc.Mapping) and b.get("type") == "object" for b in branches
    ):
        hoisted = dict(schema)
        hoisted["type"] = "object"
        return hoisted
    return {
        "type": "object",
        "properties": {"result": schema},
        "required": ["result"],
    }


def compile_signature(
    func: Callable[..., Any],
    *,
    adapters: Optional[Sequence[TypeAdapter]] = None,
) -> Tuple[tuple[ParamSpec, ...], JsonSchema, Optional[JsonSchema]]:
    """Reflect ``func`` once into ``(params, input_schema, output_schema)``.

    ``input_schema`` is an object-rooted JSON Schema 2020-12 document; the
    ``output_schema`` (from the return annotation) is normalized to an object
    root, wrapping non-object returns under a ``result`` property. Raises
    ``TypeError`` if a parameter's annotation cannot be resolved.
    """
    ctx = SchemaContext(adapters if adapters is not None else default_adapters())
    hints = get_type_hints(func, include_extras=True)
    signature = inspect.signature(func)

    params: list[ParamSpec] = []
    properties: dict[str, JsonSchema] = {}
    required_names: list[str] = []

    for name, parameter in signature.parameters.items():
        if name == "self":
            continue
        if parameter.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        annotation = hints.get(name, Any)
        compiled = ctx.build(annotation)
        has_default = parameter.default is not inspect.Parameter.empty
        required = compiled.required and not has_default
        params.append(
            ParamSpec(
                name=name,
                py_type=annotation,
                schema=compiled.schema,
                required=required,
                coerce=compiled.coerce,
            )
        )
        properties[name] = compiled.schema
        if required:
            required_names.append(name)

    input_schema: JsonSchema = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required_names:
        input_schema["required"] = required_names

    return_hint = hints.get("return", _MISSING)
    output_schema: Optional[JsonSchema] = None
    if return_hint is not _MISSING and return_hint is not _NONE_TYPE:
        output_schema = _object_rooted(ctx.build(return_hint).schema)

    return tuple(params), input_schema, output_schema
