#!/usr/bin/env python
"""Compatibility entry point for the EVTX timeline diagnostic."""

import sys

try:
    from evtx_scripts.evtx_timeline import main as _timeline_main
except ImportError:  # executed directly from the source checkout
    from evtx_timeline import main as _timeline_main


def main(argv=None):
    return _timeline_main(argv)


if __name__ == "__main__":
    sys.exit(main())
