"""Interface layer — our own MCP + JSON-RPC stack and tool catalog.

The JSON-RPC 2.0 engine, MCP protocol methods, schema compiler, output envelope,
pluggable transports (stdio / streamable-HTTP), the declarative tool catalog
(``ToolSpec`` -> schema + coercion + use-case), MCP resources, and the
supervisor/router. Written from the open MCP specification; it vendors no
third-party MCP library.

Dependency rule: imports ``application`` (use-cases) and ``domain`` (value objects
for coercion). Never ``infrastructure`` and never any IDA SDK module — the entire
interface layer, including the router, is IDA-free.
"""
