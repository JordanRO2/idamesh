"""A small, pure predicate grammar shared by the ``*_query`` read tools.

This is the authored, IDA-free query model the filtered-read tools (``entity_query``
/ ``func_query`` / ``imports_query`` / ``xref_query`` / ``insn_query``) run over. It
is deliberately tiny and explainable: a :class:`Query` is a *conjunction* (logical
AND) of :class:`FieldPredicate`s, and each predicate names a *field*, a
:class:`FieldOp`, and an *operand*, evaluated against a plain ``field -> value``
feature mapping that a use-case projects from one domain entity. The entity types
never leak in here — each use-case authors the small feature projection for its
entity and reuses this grammar to filter, so the whole read-query surface shares
one evaluator that unit-tests on synthetic feature dicts with no IDA present.

Evaluation is total: a missing field, a type mismatch, or an inapplicable operator
yields ``False`` rather than raising, so a filter can be applied uniformly across a
heterogeneous stream. The operator set, the case-folding of string comparisons, and
the membership (``HAS``) form are our own authored design.
"""

from __future__ import annotations

import collections.abc as cabc
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional, Tuple


class FieldOp(Enum):
    """The comparison operators a :class:`FieldPredicate` may apply.

    * ``EQ`` / ``NE`` — equality / inequality (case-insensitive for strings).
    * ``CONTAINS`` — the operand is a case-insensitive substring of the field
      (the ``name~substr`` form).
    * ``GE`` / ``GT`` / ``LE`` / ``LT`` — integer magnitude comparisons.
    * ``IS_TRUE`` / ``IS_FALSE`` — the field is truthy / falsy (boolean flags).
    * ``HAS`` — the operand is a member of the field's collection value (used for
      the multi-valued operand features of ``insn_query``).
    """

    EQ = "=="
    NE = "!="
    CONTAINS = "~"
    GE = ">="
    GT = ">"
    LE = "<="
    LT = "<"
    IS_TRUE = "is_true"
    IS_FALSE = "is_false"
    HAS = "has"


def _as_text(value: Any) -> Optional[str]:
    """Return ``value`` when it is a string, else ``None`` (a non-match signal)."""
    return value if isinstance(value, str) else None


def _as_number(value: Any) -> Optional[int]:
    """Return ``value`` as an int when it is a non-boolean integer, else ``None``.

    ``bool`` is an ``int`` subclass but is never treated as a magnitude here, so a
    boolean field is only reachable through ``IS_TRUE`` / ``IS_FALSE``.
    """
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


@dataclass(frozen=True)
class FieldPredicate:
    """One ``field op operand`` clause, evaluable against a feature mapping."""

    field: str
    op: FieldOp
    operand: Any = None

    def evaluate(self, features: Mapping[str, Any]) -> bool:
        """Apply this predicate to ``features``; unknown/ill-typed fields are ``False``."""
        if self.field not in features:
            return False
        actual = features[self.field]
        op = self.op
        if op is FieldOp.IS_TRUE:
            return bool(actual) is True
        if op is FieldOp.IS_FALSE:
            return bool(actual) is False
        if op is FieldOp.CONTAINS:
            hay = _as_text(actual)
            needle = _as_text(self.operand)
            if hay is None or needle is None:
                return False
            return needle.casefold() in hay.casefold()
        if op is FieldOp.HAS:
            if isinstance(actual, (str, bytes)):
                return False
            if isinstance(actual, cabc.Iterable):
                return self.operand in actual
            return False
        if op is FieldOp.EQ or op is FieldOp.NE:
            equal = self._equal(actual, self.operand)
            return equal if op is FieldOp.EQ else not equal
        left = _as_number(actual)
        right = _as_number(self.operand)
        if left is None or right is None:
            return False
        if op is FieldOp.GE:
            return left >= right
        if op is FieldOp.GT:
            return left > right
        if op is FieldOp.LE:
            return left <= right
        return left < right

    @staticmethod
    def _equal(actual: Any, operand: Any) -> bool:
        """Equality with case-insensitive string handling, exact otherwise."""
        actual_text = _as_text(actual)
        operand_text = _as_text(operand)
        if actual_text is not None and operand_text is not None:
            return actual_text.casefold() == operand_text.casefold()
        return actual == operand


@dataclass(frozen=True)
class Query:
    """A conjunction of :class:`FieldPredicate`s (an empty query matches everything)."""

    predicates: Tuple[FieldPredicate, ...] = ()

    @classmethod
    def of(cls, *predicates: Optional[FieldPredicate]) -> "Query":
        """Build a query from predicates, dropping any ``None`` (unset filter)."""
        return cls(tuple(p for p in predicates if p is not None))

    @property
    def is_empty(self) -> bool:
        """``True`` when no predicate constrains the query."""
        return not self.predicates

    def matches(self, features: Mapping[str, Any]) -> bool:
        """``True`` when *every* predicate holds for ``features``."""
        return all(predicate.evaluate(features) for predicate in self.predicates)
