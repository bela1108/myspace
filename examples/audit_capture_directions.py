#!/usr/bin/env python
"""Command-line wrapper for the read-only capture direction audit.

Usage:
    python examples/audit_capture_directions.py case.json
    python examples/audit_capture_directions.py --capture cap_a=a.pcap --capture cap_b=b.pcap --anchors anchors.json --claims claims.json

The underlying implementation lives in :mod:`dpkt.capture_audit`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dpkt.capture_audit import main  # noqa: E402


if __name__ == "__main__":
    sys.exit(main())
