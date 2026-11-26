# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Compatibility re-exports for :mod:`in_toto.switch_verify`."""

from in_toto.switch_verify import (
    FALLBACK,
    NORMAL,
    QUARANTINE,
    RELEASE,
    SwitchVerdict,
    assess_junction,
    replay_switch_verification,
    verify_layout_signoffs,
    verify_offline_switch,
    verify_switch,
    verify_switch_release,
)

__all__ = [
    "FALLBACK",
    "NORMAL",
    "QUARANTINE",
    "RELEASE",
    "SwitchVerdict",
    "assess_junction",
    "replay_switch_verification",
    "verify_layout_signoffs",
    "verify_offline_switch",
    "verify_switch",
    "verify_switch_release",
]
