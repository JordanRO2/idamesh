"""The supervisor front endpoint must not be exposed off-loopback without a token."""

from __future__ import annotations

from idamesh.bootstrap import supervisor_main


def test_refuses_non_loopback_host_without_token(monkeypatch, capsys):
    monkeypatch.delenv(supervisor_main.ENV_TOKEN, raising=False)
    assert supervisor_main.main(["--host", "0.0.0.0", "--port", "0"]) == 2
    assert "bearer token" in capsys.readouterr().err


def test_non_loopback_host_with_token_passes_the_guard(monkeypatch):
    monkeypatch.setenv(supervisor_main.ENV_TOKEN, "secret")
    seen = {}

    class _Transport:
        bound_port = 1

        def __init__(self, *a, **kw):
            seen.update(kw)

        def serve(self, block=False):
            raise KeyboardInterrupt  # leave main() right after construction

        def stop(self):
            pass

    monkeypatch.setattr(supervisor_main, "HttpTransport", _Transport)
    assert supervisor_main.main(["--host", "0.0.0.0", "--port", "0"]) == 0
    assert seen["bearer_token"] == "secret"


def test_loopback_needs_no_token(monkeypatch):
    monkeypatch.delenv(supervisor_main.ENV_TOKEN, raising=False)
    seen = {}

    class _Transport:
        bound_port = 1

        def __init__(self, *a, **kw):
            seen.update(kw)

        def serve(self, block=False):
            raise KeyboardInterrupt

        def stop(self):
            pass

    monkeypatch.setattr(supervisor_main, "HttpTransport", _Transport)
    assert supervisor_main.main(["--port", "0"]) == 0
    assert seen["bearer_token"] is None
