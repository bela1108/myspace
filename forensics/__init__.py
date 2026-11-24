"""Offline cross-check of independently verifiable TUF release statements.

The package compares the signed metadata that two parties (here called
"mirrors") collected from the same release, while the network is unavailable.
Every statement is first verified against the root of trust that the
respective party itself vouches for: nothing in this package contacts a
repository or trusts a statement it cannot verify locally.
"""

from forensics.crosscheck import (
    CONFLICT,
    CONSISTENT,
    UNDECIDED,
    CrosscheckReport,
    PartyInput,
    TargetVerdict,
    run_crosscheck,
)

__all__ = [
    "CONFLICT",
    "CONSISTENT",
    "UNDECIDED",
    "CrosscheckReport",
    "PartyInput",
    "TargetVerdict",
    "run_crosscheck",
]
