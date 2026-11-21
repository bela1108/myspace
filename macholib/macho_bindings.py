#!/usr/bin/env python

"""Command line wrapper for the per-slice import binding report."""

import sys

from macholib.bindings import main


if __name__ == "__main__":
    sys.exit(main())
