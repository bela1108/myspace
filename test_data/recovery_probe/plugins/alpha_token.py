import re

from detect_secrets.plugins.base import RegexBasedDetector


class AlphaTokenDetector(RegexBasedDetector):
    """Recovery probe test plugin: scans for alpha token markers."""

    secret_type = 'Recovery Probe Alpha Token'

    denylist = (
        re.compile(r'RP-(?:ALPHA-ONLY|SHARED)-[0-9a-f]{8}'),
    )
