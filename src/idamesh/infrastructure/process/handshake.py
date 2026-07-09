"""The worker readiness/port handshake (frozen wire contract, idapro-free).

A headless worker spawned with ``--transport http --port 0`` binds an ephemeral
port, then emits **exactly one JSON line** on its reserved real stdout *before* it
starts serving::

    {"ready": true, "port": <bound_port>}

The line may carry additional informational keys (``transport``, ``host``); a
reader must tolerate them and depend only on ``ready`` and ``port``. The
supervisor reads this line to learn where to connect. This module is the single
definition of that contract, shared by the pool's spawn path and its tests.
"""

from __future__ import annotations

import json
from typing import Union

#: The two keys a reader depends on.
READY_KEY = "ready"
PORT_KEY = "port"


class HandshakeError(RuntimeError):
    """A worker's readiness line was missing, malformed, or reported not-ready."""


def parse_handshake_line(line: Union[bytes, str]) -> int:
    """Parse one readiness line and return the worker's bound port.

    Raises :class:`HandshakeError` if the line is not valid JSON, is not a
    ``ready: true`` object, or lacks an integer ``port``.
    """
    if isinstance(line, (bytes, bytearray)):
        try:
            line = bytes(line).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HandshakeError(f"handshake line was not UTF-8: {exc}") from exc
    text = line.strip()
    if not text:
        raise HandshakeError("worker produced an empty handshake line")
    try:
        obj = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise HandshakeError(f"handshake line was not JSON: {text!r}") from exc
    if not isinstance(obj, dict) or obj.get(READY_KEY) is not True:
        raise HandshakeError(f"worker did not report ready: {obj!r}")
    port = obj.get(PORT_KEY)
    if not isinstance(port, int) or isinstance(port, bool) or port <= 0:
        raise HandshakeError(f"worker handshake carried no valid port: {obj!r}")
    return port
