"""Command-line entry point.

Dispatches to the per-process composition roots (worker / supervisor / install).
The subcommands are wired in later phases; for now this reports version and the
available runtimes so the console-script entry point is valid.
"""

from __future__ import annotations

import argparse
import sys

from idamesh import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="idamesh", description="MCP server for IDA Pro")
    parser.add_argument("--version", action="version", version=f"idamesh {__version__}")
    sub = parser.add_subparsers(dest="command")
    # Subcommands are registered as their runtimes come online (Phase 1+):
    #   worker      — headless idalib MCP worker (one database)
    #   supervisor  — the routing endpoint / N-copies orchestrator
    #   install     — install the GUI plugin and write the launch spec
    sub.add_parser("worker", help="run a headless idalib MCP worker over one database")
    sub.add_parser("supervisor", help="run the routing supervisor / N-copies orchestrator")
    sub.add_parser("install", help="install the IDA GUI plugin loader and worker launch spec")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)

    # The ``worker`` and ``supervisor`` runtimes have their own argument
    # grammars; delegate everything after the subcommand to them verbatim so
    # their flags pass straight through.
    if raw and raw[0] == "worker":
        from idamesh.bootstrap.worker_main import main as worker_main

        return worker_main(raw[1:])
    if raw and raw[0] == "supervisor":
        from idamesh.bootstrap.supervisor_main import main as supervisor_main

        return supervisor_main(raw[1:])
    if raw and raw[0] == "install":
        from idamesh.cli.install import main as install_main

        return install_main(raw[1:])

    args = build_parser().parse_args(raw)
    if not args.command:
        build_parser().print_help()
        return 0
    print(f"idamesh {__version__}: '{args.command}' is not implemented yet.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
