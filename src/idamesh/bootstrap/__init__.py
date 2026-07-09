"""Bootstrap layer — the composition roots.

The only place permitted to import across all layers. One root per runtime:

* ``plugin_main``     — resident GUI plugin inside ``idaq`` (marshals via execute_sync).
* ``worker_main``     — headless ``idalib`` process owning one private database copy.
* ``supervisor_main`` — the routing endpoint / N-copies orchestrator (imports no idapro).

Each builds the same container/catalog, differing only in which
``MainThreadExecutor`` and transport are wired.
"""
