"""Domain layer — pure, framework-free core.

Value objects, entities, domain services (paging, query predicates, merge
reconciliation, crypto-constant matching, dataflow traversal, signature logic),
and the *outbound port protocols* the application programs against.

Dependency rule: this layer imports **only** the standard library and ``typing``.
It must never import ``application``, ``infrastructure``, ``interface``, or any
IDA SDK module. Enforced by ``tests/architecture/test_import_contract.py``.
"""
