#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
"""Assemble the local and exchange views from one scan report.

Both views are produced by a single :class:`ExceptionExchange` evaluation so
they can never disagree about the underlying findings; deleting a mapping and
rebuilding only removes that mapping's own approvals.
"""
import copy

from bandit.exchange.engine import ExceptionExchange


def build_exchange(report, mappings, now=None):
    """Run the exchange engine over a loaded report and mappings."""
    return ExceptionExchange(
        report["findings"], mappings["mappings"], now=now
    )


def _envelope(report, mappings, view_name, payload):
    return {
        "document": "bandit-exception-view",
        "view": view_name,
        "source_report_generated_at": report.get("generated_at"),
        "legacy_report": bool(report.get("legacy", False)),
        "mapping_document": mappings.get("document"),
        "mapping_version": mappings.get("version"),
        "errors": copy.deepcopy(report.get("errors", [])),
        "view_data": payload,
    }


def build_views(report, mappings, now=None):
    """Build both views from one evaluation pass."""
    exchange = build_exchange(report, mappings, now=now)
    views = exchange.build_views()
    return {
        "local": _envelope(report, mappings, "local", views["local"]),
        "exchange": _envelope(
            report, mappings, "exchange", views["exchange"]
        ),
    }


def export_local_view(report, mappings, now=None):
    """Build only the Bandit-centric local view."""
    exchange = build_exchange(report, mappings, now=now)
    return _envelope(
        report, mappings, "local", exchange.local_view()
    )


def export_exchange_view(report, mappings, now=None):
    """Build only the external-rule-centric exchange view."""
    exchange = build_exchange(report, mappings, now=now)
    return _envelope(
        report, mappings, "exchange", exchange.exchange_view()
    )


def export_views(report, mappings, now=None):
    """Return both views derived from the same scan output."""
    exchange = build_exchange(report, mappings, now=now)
    views = exchange.build_views()
    return {
        "local": _envelope(report, mappings, "local", views["local"]),
        "exchange": _envelope(
            report, mappings, "exchange", views["exchange"]
        ),
    }
