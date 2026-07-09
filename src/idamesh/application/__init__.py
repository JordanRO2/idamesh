"""Application layer — use-cases and I/O contracts.

One package per bounded context (core, analysis, modify, types, memory, stack,
security, signatures, survey, scripting, annotations, debug). Command/Result DTOs
define the tool I/O contracts; policies express profile/whitelist/output limits.

Dependency rule: imports ``domain`` only. Never ``infrastructure``, ``interface``,
or any IDA SDK module.
"""
