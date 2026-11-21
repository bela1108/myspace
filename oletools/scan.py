#!/usr/bin/env python
"""Convenience import for the budget-aware scanning backend.

The implementation lives in :mod:`oletools.scan_backend`.  This module keeps
the public surface easy to discover for callers that expect ``oletools.scan``.
"""

from oletools.scan_backend import *  # noqa: F401,F403
