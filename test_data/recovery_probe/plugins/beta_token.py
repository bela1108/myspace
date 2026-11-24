import re

from detect_secrets.plugins.base import RegexBasedDetector


class BetaTokenDetector(RegexBasedDetector):
    """Recovery probe test plugin: scans for beta token markers."""

    secret_type = 'Recovery Probe Beta Token'

    denylist = (
        re.compile(r'RP-(?:BETA-ONLY|SHARED)-[0-9a-f]{8}'),
    )
