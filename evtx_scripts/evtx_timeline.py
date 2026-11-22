#!/usr/bin/env python
"""CLI entry point for offline EVTX timeline diagnostics."""

import sys

from Evtx.Timeline import main as _timeline_main


def main(argv=None):
    return _timeline_main(argv)


if __name__ == "__main__":
    sys.exit(main())
