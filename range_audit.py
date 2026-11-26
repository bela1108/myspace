#!/usr/bin/env python3
"""Short compatibility name for the resource range audit CLI/API."""

from resource_audit import *  # noqa: F401,F403
from resource_range_audit import main

if __name__ == "__main__":
    raise SystemExit(main())
