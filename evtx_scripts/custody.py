#!/usr/bin/env python3
"""Alias for :mod:`evtx_scripts.evtx_custody_reconcile`."""

from evtx_scripts.evtx_custody_reconcile import main

__all__ = ["main"]

if __name__ == "__main__":
    raise SystemExit(main())
