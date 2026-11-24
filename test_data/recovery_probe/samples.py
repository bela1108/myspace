"""
Known-answer test samples for the recovery probe.

Each marker is a custom, non-sensitive string. The probe manifest (probe.yaml)
declares which plugin(s) are expected to flag every marker, and which markers
must be ignored as negatives.
"""

ALPHA_ONLY = 'RP-ALPHA-ONLY-00010203'
SHARED = 'RP-SHARED-04050607'
BETA_ONLY = 'RP-BETA-ONLY-08090a0b'

NEGATIVE_LOOKALIKE = 'RP-NEGATIVE-LOOKALIKE-10111213'
