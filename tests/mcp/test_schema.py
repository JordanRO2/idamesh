"""Unit tests for the schema compiler (type hints -> JSON Schema + coercers)."""

from __future__ import annotations

from typing import Annotated, Dict, List, Literal, Optional, Union

import pytest

try:  # Python 3.11+
    from typing import TypedDict
except ImportError:  # pragma: no cover
    from typing_extensions import TypedDict  # type: ignore

from idamesh.interface.mcp.schema import CoercionError, compile_signature


def _by_name(params):
    return {p.name: p for p in params}


def test_scalar_and_annotated_description():
    def f(a: int, b: Annotated[str, "the b param"]):
        ...

    params, schema, output = compile_signature(f)
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["a"] == {"type": "integer"}
    assert schema["properties"]["b"]["type"] == "string"
    assert schema["properties"]["b"]["description"] == "the b param"
    assert set(schema["required"]) == {"a", "b"}
    assert output is None


def test_annotated_dict_metadata_merges_constraints():
    def f(n: Annotated[int, {"minimum": 0}]):
        ...

    _params, schema, _ = compile_signature(f)
    assert schema["properties"]["n"] == {"type": "integer", "minimum": 0}


def test_default_makes_not_required():
    def f(a: int, b: int = 5):
        ...

    params, schema, _ = compile_signature(f)
    assert schema.get("required") == ["a"]
    by = _by_name(params)
    assert by["a"].required is True
    assert by["b"].required is False


def test_optional_marks_not_required_and_widens_type_to_null():
    def f(a: Optional[int] = None):
        ...

    _params, schema, _ = compile_signature(f)
    assert "required" not in schema
    # A null-permitting schema, so a null-valued optional field still validates
    # against its own declared schema.
    assert schema["properties"]["a"] == {"type": ["integer", "null"]}


def test_optional_scalar_coerces_null_and_value():
    def f(a: Optional[int] = None):
        ...

    params, _schema, _ = compile_signature(f)
    coerce = _by_name(params)["a"].coerce
    assert coerce(None) is None
    assert coerce(7) == 7


def test_optional_constrained_type_uses_anyof_with_null():
    # A value-constrained member (enum) can't just widen ``type`` — null would
    # still fail the enum — so it unions with an explicit null branch.
    def f(mode: Optional[Literal["r", "w"]] = None):
        ...

    _params, schema, _ = compile_signature(f)
    assert schema["properties"]["mode"] == {
        "anyOf": [{"enum": ["r", "w"], "type": "string"}, {"type": "null"}]
    }


def test_multimember_optional_union_includes_null_branch():
    def f(x: Union[int, str, None] = None):
        ...

    _params, schema, _ = compile_signature(f)
    assert schema["properties"]["x"]["anyOf"] == [
        {"type": "integer"},
        {"type": "string"},
        {"type": "null"},
    ]


def test_literal_becomes_enum_with_inferred_type():
    def f(mode: Literal["r", "w"]):
        ...

    params, schema, _ = compile_signature(f)
    assert schema["properties"]["mode"] == {"enum": ["r", "w"], "type": "string"}
    coerce = _by_name(params)["mode"].coerce
    assert coerce("r") == "r"
    with pytest.raises(CoercionError):
        coerce("x")


def test_list_schema_and_json_string_rescue():
    def f(xs: List[int]):
        ...

    params, schema, _ = compile_signature(f)
    assert schema["properties"]["xs"] == {"type": "array", "items": {"type": "integer"}}
    coerce = _by_name(params)["xs"].coerce
    assert coerce([1, 2, 3]) == [1, 2, 3]
    assert coerce("[1, 2, 3]") == [1, 2, 3]  # a JSON string is rescued
    with pytest.raises(CoercionError):
        coerce([1, "two"])


def test_dict_schema_and_coercion():
    def f(m: Dict[str, int]):
        ...

    params, schema, _ = compile_signature(f)
    assert schema["properties"]["m"] == {
        "type": "object",
        "additionalProperties": {"type": "integer"},
    }
    coerce = _by_name(params)["m"].coerce
    assert coerce({"a": 1}) == {"a": 1}
    with pytest.raises(CoercionError):
        coerce({"a": "x"})


class _Point(TypedDict):
    x: int
    y: int


def test_typeddict_schema_and_validation():
    def f(p: _Point):
        ...

    params, schema, _ = compile_signature(f)
    prop = schema["properties"]["p"]
    assert prop["type"] == "object"
    assert prop["additionalProperties"] is False
    assert set(prop["required"]) == {"x", "y"}
    coerce = _by_name(params)["p"].coerce
    assert coerce({"x": 1, "y": 2}) == {"x": 1, "y": 2}
    with pytest.raises(CoercionError):
        coerce({"x": 1})  # missing key
    with pytest.raises(CoercionError):
        coerce({"x": 1, "y": 2, "z": 3})  # unknown key


def test_scalar_rules_bool_and_widening():
    def f(a: int, b: float):
        ...

    params, _schema, _ = compile_signature(f)
    by = _by_name(params)
    with pytest.raises(CoercionError):
        by["a"].coerce(True)  # bool is not an int
    assert by["b"].coerce(3) == 3.0  # int widens to float
    assert isinstance(by["b"].coerce(3), float)


def test_union_anyof_schema_and_coercion():
    def f(v: Union[int, str]):
        ...

    params, schema, _ = compile_signature(f)
    assert schema["properties"]["v"] == {
        "anyOf": [{"type": "integer"}, {"type": "string"}]
    }
    coerce = _by_name(params)["v"].coerce
    assert coerce(5) == 5
    assert coerce("hi") == "hi"


def test_output_schema_wraps_non_object_return():
    def f() -> int:
        ...

    _params, _schema, output = compile_signature(f)
    assert output == {
        "type": "object",
        "properties": {"result": {"type": "integer"}},
        "required": ["result"],
    }


def test_output_schema_passthrough_for_object_return():
    def f() -> _Point:
        ...

    _params, _schema, output = compile_signature(f)
    assert output["type"] == "object"
    assert set(output["required"]) == {"x", "y"}


def test_no_params_input_schema():
    def f():
        ...

    _params, schema, _ = compile_signature(f)
    assert schema == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }
