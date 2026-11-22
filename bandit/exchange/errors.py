#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
"""Exception types raised by the security exception exchange layer."""


class ExchangeError(Exception):
    """Base class for all exception exchange errors."""


class MappingValidationError(ExchangeError):
    """Raised when an exception mapping document is malformed."""


class ReportValidationError(ExchangeError):
    """Raised when a scan report cannot be consumed."""
