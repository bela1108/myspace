"""Offline EVTX correlation toolkit.

The package is intentionally dependency-free apart from the bundled
``Evtx`` parser.  It is split into:

* :mod:`correlator.evtx_writer` - a minimal, parser-compatible EVTX writer
  used to build synthetic evidence fragments;
* :mod:`correlator.model`       - parsed event records and identity scoping;
* :mod:`correlator.engine`      - correlation, candidate and conflict logic;
* :mod:`correlator.report`      - JSON / Markdown rendering;
* :mod:`correlator.cli`         - command line entry points.
"""

__all__ = [
    "CorrelatedEvent",
    "CorrelationConfig",
    "CorrelationEngine",
    "EvidenceScope",
    "EventLink",
    "Finding",
]


def __getattr__(name):
    if name == "CorrelatedEvent" or name == "EvidenceScope":
        from . import model

        return getattr(model, name)
    if name in ("CorrelationConfig", "CorrelationEngine", "EventLink", "Finding"):
        from . import engine

        return getattr(engine, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
