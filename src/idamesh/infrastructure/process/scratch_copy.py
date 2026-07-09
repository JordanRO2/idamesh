"""Per-session private working copies of the target (idapro-free).

N-copies parallelism is only possible because each worker opens its *own* copy of
the binary: two ``idalib`` processes that open the *same* path collide on IDA's
database lock, but two that each open a private copy run fully in parallel. This
module owns materializing that copy into a per-session scratch directory and
cleaning it up on close — it never touches the user's original file or its
neighbours.

Scratch layout (env ``IDA_MCP_WORKER_SCRATCH`` overrides the root)::

    <scratch_root>/<session_id>/<name>

where ``<name>`` is the input's basename, or a cloned ``.i64``/``.idb`` sitting
next to the input so the copy inherits prior analysis.

The signatures are stable so the pool and its tests can rely on them.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

#: Default scratch-root basename under the OS temp dir.
_DEFAULT_ROOT_NAME = "idamesh-workers"

#: Sibling database extensions preferred over the raw input (they carry prior
#: analysis, so cloning one lets the worker skip a full re-analysis).
_DATABASE_SUFFIXES = (".i64", ".idb")


def scratch_root() -> Path:
    """The root directory under which per-session scratch dirs are created.

    ``IDA_MCP_WORKER_SCRATCH`` overrides the default (a stable ``idamesh-workers``
    directory under the OS temp dir). The directory is created if absent, with
    tight permissions on POSIX (best-effort; a no-op on Windows).
    """
    override = os.environ.get("IDA_MCP_WORKER_SCRATCH")
    root = (
        Path(override)
        if override
        else Path(tempfile.gettempdir()) / _DEFAULT_ROOT_NAME
    )
    root.mkdir(parents=True, exist_ok=True)
    # Keep the tree private on multi-user hosts; harmless where mode bits do not
    # apply. Never fail creation on a permission tweak.
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _validate_segment(session_id: str) -> str:
    """Reject a ``session_id`` that is not a single, safe path segment.

    A crafted ``preferred_session_id`` becomes a scratch-dir name, so a value
    carrying a separator or ``..`` could otherwise escape the scratch root. This
    guard confines every scratch path to exactly one child of the root.
    """
    if not session_id or session_id in (".", ".."):
        raise ValueError(f"unsafe session id for a scratch dir: {session_id!r}")
    if any(sep and sep in session_id for sep in (os.sep, os.altsep, "/", "\\")):
        raise ValueError(f"session id must be a single path segment: {session_id!r}")
    return session_id


def session_dir(session_id: str) -> Path:
    """The private directory owned by ``session_id`` (``<scratch_root>/<id>``)."""
    return scratch_root() / _validate_segment(session_id)


def _preferred_source(input_path: Path) -> Path:
    """The file to clone: a sibling ``.i64``/``.idb`` if present, else the input.

    If the input is itself a database it is used directly. Otherwise a database
    sitting next to the input is preferred so the copy inherits prior analysis
    instead of forcing a fresh auto-analysis. IDA names that database by
    *appending* the suffix to the full input name (``program.exe`` ->
    ``program.exe.i64``), so the append form is tried first; the extension-replacing
    form (``program.exe`` -> ``program.i64``) is tried as a fallback for setups that
    use it.
    """
    if input_path.suffix.lower() in _DATABASE_SUFFIXES:
        return input_path
    candidates = [
        input_path.with_name(input_path.name + suffix)  # program.exe.i64 (IDA convention)
        for suffix in _DATABASE_SUFFIXES
    ] + [
        input_path.with_suffix(suffix)  # program.i64 (extension-replacing fallback)
        for suffix in _DATABASE_SUFFIXES
    ]
    for candidate in candidates:
        if candidate != input_path and candidate.is_file():
            return candidate
    return input_path


def materialize_private_copy(session_id: str, input_path: str) -> Path:
    """Copy ``input_path`` into this session's private scratch dir and return the
    path to open.

    Creates ``session_dir(session_id)``; if a sibling ``.i64``/``.idb`` exists
    next to ``input_path`` it is cloned in preference to the raw input (inherits
    analysis), else the input file itself is copied. Idempotent enough to survive
    a retry (the destination is overwritten) and never writes outside the session
    dir.
    """
    src = Path(input_path)
    if not src.is_file():
        raise FileNotFoundError(f"input to open does not exist: {input_path!r}")
    source = _preferred_source(src)
    dest_dir = session_dir(session_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / source.name
    # copyfile (not copy2) — we want only the bytes, not the source's mode/owner,
    # in a directory we already locked down.
    try:
        shutil.copyfile(source, dest)
    except OSError:
        # The preferred sibling database can be locked (e.g. it is currently open
        # in the GUI, which holds the .i64 on Windows). Fall back to copying the
        # raw input so the open still succeeds — with a fresh analysis — instead of
        # failing outright.
        if source == src:
            raise
        dest = dest_dir / src.name
        shutil.copyfile(src, dest)
    return dest


def cleanup_session_dir(session_id: str) -> None:
    """Recursively remove this session's scratch dir. Best-effort, never raising.

    Scoped to ``<scratch_root>/<session_id>`` and re-checked after resolution so
    it can never reach a sibling session's copy or the user's original file.
    """
    try:
        root = scratch_root().resolve()
        target = (root / _validate_segment(session_id)).resolve()
    except (ValueError, OSError):
        return
    # Refuse anything that is not a direct child of the scratch root.
    if target == root or target.parent != root:
        return
    shutil.rmtree(target, ignore_errors=True)
