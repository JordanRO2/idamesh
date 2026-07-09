"""IDA-SDK adapters — the only package permitted to import ``ida_*``.

Holds the port implementations (``IdaDatabaseGateway``, ``IdaFunctionRepository``,
``IdaDecompilerGateway``) and the GUI main-thread executor
(``ExecuteSyncExecutor``). Every SDK import is lazy (performed inside methods), so
importing this package does not require IDA to be present. The adapter classes
are intentionally *not* re-exported here to keep a bare
``import idamesh.infrastructure`` free of any SDK-touching module.
"""

from __future__ import annotations
