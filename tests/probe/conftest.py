import pytest

from detect_secrets import main as main_module
from testing.mocks import mock_printer
from testing.mocks import PrinterShim


@pytest.fixture
def printer():
    shim = PrinterShim()
    with mock_printer(main_module, shim=shim):
        yield shim
