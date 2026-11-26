"""Pure audit-context formatting helpers.

Kept in a separate module so backend/UI integrations can reuse the secure
formatter without importing the interactive I/O prompt machinery.
"""
from .io import format_context
from .io import format_secret_context
from .io import format_secret_not_found
from .io import format_snippet
from .io import mask_secret
from .io import redact_secret
from .io import render_redacted_line

__all__ = [
    'format_context',
    'format_secret_context',
    'format_secret_not_found',
    'format_snippet',
    'mask_secret',
    'redact_secret',
    'render_redacted_line',
]
