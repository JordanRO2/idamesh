"""Newline-delimited JSON-over-stdio transport.

One JSON value per line on a byte stream (``stdin.buffer`` / ``stdout.buffer`` by
default). Framing is sacred here: all logging goes to stderr/file, never stdout.
"""

from __future__ import annotations

import sys
import threading
from typing import BinaryIO, Optional

from idamesh.infrastructure.transport.base import Dispatcher, Transport


class StdioTransport(Transport):
    """Serves MCP over a newline-delimited byte pipe."""

    def __init__(
        self,
        dispatcher: Dispatcher,
        *,
        stdin: Optional[BinaryIO] = None,
        stdout: Optional[BinaryIO] = None,
        session_id: str = "stdio",
    ) -> None:
        super().__init__(dispatcher)
        self._stdin = stdin
        self._stdout = stdout
        self._session_id = session_id
        self._stopped = False
        self._thread: Optional[threading.Thread] = None

    def serve(self, *, block: bool = True) -> None:
        """Read lines, dispatch each, and write newline-framed replies until EOF."""
        self._stopped = False
        if block:
            self._run()
        else:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Signal the read loop to exit."""
        self._stopped = True
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # -- internals ---------------------------------------------------------

    def _run(self) -> None:
        stdin = self._stdin if self._stdin is not None else sys.stdin.buffer
        stdout = self._stdout if self._stdout is not None else sys.stdout.buffer
        while not self._stopped:
            try:
                line = stdin.readline()
            except (KeyboardInterrupt, ValueError):
                # ValueError: read from a closed stream during shutdown.
                break
            if not line:  # EOF
                break
            frame = line.strip()
            if not frame:  # blank keep-alive line
                continue
            reply = self._dispatcher.dispatch(frame, session_id=self._session_id)
            if reply is None:  # notification / response-only input
                continue
            try:
                stdout.write(reply)
                stdout.write(b"\n")
                stdout.flush()
            except BrokenPipeError:
                break
