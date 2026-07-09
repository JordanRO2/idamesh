"""Architectural import-contract tests.

These enforce the domain-driven dependency rule *mechanically*, so the layering
cannot silently rot as the codebase grows. They parse every module under
``src/idamesh`` with the ``ast`` module and check three invariants:

1. Inner layers never import outer layers (the dependency points strictly inward).
2. The IDA SDK (``idapro`` / ``idaapi`` / ``ida_*`` / ``idc`` / ``idautils``) is
   confined to a single place: ``infrastructure/ida/**`` and the two IDA-hosted
   composition roots. Every incidental SDK-shaped similarity to any other IDA
   tooling lives only there.
3. The orchestrator/supervisor process graph never imports ``idapro`` at all.

The whole suite runs under plain ``pytest`` with no IDA installed.
"""

from __future__ import annotations

import ast
import pathlib

SRC = pathlib.Path(__file__).resolve().parents[2] / "src"
ROOT_PKG = "idamesh"

# Which layers each layer is permitted to import (idamesh-internal targets only).
LAYER_ALLOWED: dict[str, set[str]] = {
    "domain": {"domain"},
    "application": {"domain", "application"},
    "infrastructure": {"domain", "infrastructure"},
    "interface": {"domain", "application", "interface"},
    "bootstrap": {"domain", "application", "infrastructure", "interface", "bootstrap", "cli"},
    "cli": {"domain", "application", "infrastructure", "interface", "bootstrap", "cli"},
}

# Only modules under these dotted prefixes may import the IDA SDK.
IDA_ALLOWED_PREFIXES = (
    f"{ROOT_PKG}.infrastructure.ida",
    f"{ROOT_PKG}.bootstrap.plugin_main",
    f"{ROOT_PKG}.bootstrap.worker_main",
)

# Modules that run inside the router/worker-manager process, which must never
# pull in the headless-IDA library.
IDAPRO_FREE_PREFIXES = (
    f"{ROOT_PKG}.interface",
    f"{ROOT_PKG}.infrastructure.rpc",
    f"{ROOT_PKG}.infrastructure.transport",
    f"{ROOT_PKG}.infrastructure.process",
    f"{ROOT_PKG}.infrastructure.discovery",
    f"{ROOT_PKG}.bootstrap.supervisor_main",
)


def _is_ida_import(name: str) -> bool:
    head = name.split(".")[0]
    return head in {"idapro", "idaapi", "idc", "idautils"} or head.startswith("ida_")


def _module_name(path: pathlib.Path) -> str:
    rel = path.relative_to(SRC).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _layer_of(module: str) -> str | None:
    parts = module.split(".")
    if len(parts) < 2 or parts[0] != ROOT_PKG:
        return None
    return parts[1]


def _imported_absolute_names(tree: ast.AST) -> list[tuple[str, int]]:
    """Absolute imported module names with line numbers. Relative imports are
    intra-package and never cross a layer boundary, so they are skipped."""
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if (node.level or 0) == 0 and node.module:
                out.append((node.module, node.lineno))
    return out


def _iter_modules():
    for path in sorted(SRC.rglob("*.py")):
        yield path, _module_name(path)


def test_layer_dependency_rule():
    violations: list[str] = []
    for path, module in _iter_modules():
        layer = _layer_of(module)
        if layer is None or layer not in LAYER_ALLOWED:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for name, lineno in _imported_absolute_names(tree):
            if not name.startswith(ROOT_PKG + "."):
                continue
            target = _layer_of(name)
            if target is None:
                continue
            if target not in LAYER_ALLOWED[layer]:
                violations.append(
                    f"{module} ({path.name}:{lineno}) [{layer}] imports "
                    f"{name} [{target}] — forbidden by the dependency rule"
                )
    assert not violations, "Layer dependency violations:\n" + "\n".join(violations)


def test_ida_sdk_is_confined():
    violations: list[str] = []
    for path, module in _iter_modules():
        if not module.startswith(ROOT_PKG):
            continue
        allowed = module.startswith(IDA_ALLOWED_PREFIXES)
        if allowed:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for name, lineno in _imported_absolute_names(tree):
            if _is_ida_import(name):
                violations.append(
                    f"{module} ({path.name}:{lineno}) imports IDA SDK '{name}' — "
                    f"only {IDA_ALLOWED_PREFIXES} may touch the SDK"
                )
    assert not violations, "IDA SDK confinement violations:\n" + "\n".join(violations)


def test_orchestrator_graph_is_idapro_free():
    violations: list[str] = []
    for path, module in _iter_modules():
        if not module.startswith(IDAPRO_FREE_PREFIXES):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for name, lineno in _imported_absolute_names(tree):
            if name.split(".")[0] == "idapro":
                violations.append(
                    f"{module} ({path.name}:{lineno}) imports idapro — "
                    f"the orchestrator process graph must be idapro-free"
                )
    assert not violations, "idapro-free violations:\n" + "\n".join(violations)
