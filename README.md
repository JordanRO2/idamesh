# idamesh

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for
**IDA Pro**. It exposes IDA's disassembler and the Hex-Rays decompiler to MCP
clients (Claude and others) as tools and resources, with a supervisor that fronts
multiple databases behind one endpoint so several agents can work in parallel.

## What it does

- **Read** — decompile (Hex-Rays), disassemble, cross-references, call graphs, type
  and struct inspection, memory reads, and string / byte / text search.
- **Query** — structured filters over functions, instructions, xrefs, types, imports.
- **Analyze** — survey / triage, crypto and dangerous-API detection, vulnerability
  heuristics, stack-string reconstruction, and dataflow / taint tracing.
- **Mutate** — rename, comment, retype, define code and data, edit stack frames,
  patch bytes / assembly, bookmarks, and annotation export / import.
- **Parallelize** — open each database over a private copy so multiple agents can
  work the same binary at once, and merge their edits back into one database.

Read-only IDB state is also projected as `ida://…` MCP resources.

## Requirements

- Python **3.9+**
- A licensed **IDA Pro** install providing the `idapro` / `idalib` Python API. Point
  the `IDADIR` environment variable at your IDA installation directory.

## Install

```bash
pip install -e .          # runtime (zero third-party dependencies)
pip install -e .[dev]     # + pytest, to run the test suite
```

This provides the `idamesh` command with three subcommands: `worker`, `supervisor`,
and `install`.

## Usage

**Headless worker** — one database on stdio (the client launches it):

```bash
idamesh worker /path/to/target.exe
```

**Supervisor** — one HTTP endpoint fronting many databases:

```bash
idamesh supervisor                       # http://127.0.0.1:8745/mcp
```

Open and close databases behind it with the `idb_open` / `idb_list` / `idb_close`
tools; route any tool to a session with an optional `database` key (omit it when a
single database is open). Opening the same binary twice yields two independent
sessions; `idb_merge` reconciles their edits.

**GUI plugin** — serve MCP over your live, open IDA database:

```bash
idamesh install     # deploy the plugin into IDA's user directory, then restart IDA
```

Run `idamesh supervisor` (or set `IDAMESH_AUTOLAUNCH_SUPERVISOR=1` to have the
plugin start one), then open a binary in IDA — the supervisor adopts the live
session and routes to it.

Both the worker (`--transport http`) and the supervisor speak MCP **Streamable
HTTP** at a single `/mcp` endpoint, loopback-bound with `Origin` validation.

## Connect from Claude Code

```bash
claude mcp add --scope user --transport http idamesh http://127.0.0.1:8745/mcp
```

Or launch a single stdio worker directly:

```bash
claude mcp add --scope user -e IDADIR=/path/to/IDA-Pro \
  idamesh -- idamesh worker /path/to/target.exe
```

## Tests

```bash
pip install -e .[dev]
python -m pytest -q
```

The live `idalib` end-to-end tests skip cleanly when IDA is unavailable (no
`IDADIR`), so the suite is green without an IDA install.

## License

[MIT](LICENSE).

<!-- mcp-name: io.github.JordanRO2/idamesh -->

