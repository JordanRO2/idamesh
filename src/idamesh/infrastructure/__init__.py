"""Infrastructure layer — adapters and process plumbing.

Implements the domain's outbound ports. The IDA SDK lives **only** under
``infrastructure/ida/**`` (adapters, the main-thread scheduler implementations,
version-compat seams, the strings cache). The ``rpc``, ``transport``, ``process``,
and ``discovery`` subpackages are deliberately IDA-free so the supervisor can reuse
them without loading ``idapro``.

Dependency rule: imports ``domain`` (to implement its ports) + the IDA SDK
(confined to ``infrastructure/ida/**``) + the standard library. Never
``application`` or ``interface``.
"""
