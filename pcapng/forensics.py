"""
Compatibility import for the read-only forensic pairing API.

The implementation lives in :mod:`pcapng.pairing`; this module exposes the same
objects under the ``forensics`` name used by investigations.
"""

from pcapng.pairing import (  # noqa: F401
    ForensicPairer,
    IgnoredObservation,
    NearMiss,
    PacketObservation,
    PacketPair,
    PairingReport,
    TimeWindow,
    Truncation,
    UnresolvedObservation,
    common_prefix_length,
    compare_captures,
    iter_packet_observations,
    observations_from_pcapng,
    pair_captures,
    pair_observations,
    pair_packets,
    pair_pcapng,
    read_observations,
)

__all__ = [
    "ForensicPairer",
    "IgnoredObservation",
    "NearMiss",
    "PacketObservation",
    "PacketPair",
    "PairingReport",
    "TimeWindow",
    "Truncation",
    "UnresolvedObservation",
    "common_prefix_length",
    "compare_captures",
    "iter_packet_observations",
    "observations_from_pcapng",
    "pair_captures",
    "pair_observations",
    "pair_packets",
    "pair_pcapng",
    "read_observations",
]
