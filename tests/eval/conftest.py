"""Fixtures for the offline evaluation tests.

The sandbox blocks pytest from walking to the repository-root conftest, so
we reuse the shared mock fixtures explicitly. The evaluation itself never
makes network calls; these mocks keep the real plugin dependencies honest.
"""
from tests.conftest import clear_cache
from tests.conftest import mocked_requests
from tests.conftest import mock_log
from tests.conftest import prevent_clear_screen
from tests.conftest import prevent_color

__all__ = [
    "clear_cache",
    "mocked_requests",
    "mock_log",
    "prevent_clear_screen",
    "prevent_color",
]
