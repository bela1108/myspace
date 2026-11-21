#!/usr/bin/env python
"""Compatibility import for the budget primitives.

The implementation lives in :mod:`oletools.common.scan_budget`.  This module
keeps the public surface discoverable for callers that expect
``oletools.common.budget``.
"""

from oletools.common.scan_budget import *  # noqa: F401,F403
from oletools.common.scan_budget import __all__  # noqa: F401
