"""Pytest bootstrap compatibility shim.

The offline-export task adds tests under ``tests/``.  In some sandboxed
macOS shells the agent is denied ``stat`` on directories above the
workspace root; pytest's conftest discovery calls
``pathlib.Path.is_file()`` on those parents and lets ``PermissionError``
escape, aborting collection for *every* test (including upstream ones).

Returning ``False`` for an inaccessible path matches the conventional
"not a regular file / cannot inspect it" behavior and lets collection
continue.  On an ordinary developer/CI machine no ``PermissionError`` is
raised, so this wrapper is inert.
"""

from __future__ import annotations

import pathlib

_original_is_file = pathlib.Path.is_file


def _permission_safe_is_file(self: pathlib.Path) -> bool:
    try:
        return _original_is_file(self)
    except PermissionError:
        return False


pathlib.Path.is_file = _permission_safe_is_file  # type: ignore[method-assign]
