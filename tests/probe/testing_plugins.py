import re

from detect_secrets.plugins.base import RegexBasedDetector


class AlphaTestDetector(RegexBasedDetector):
    """Scans for the alpha family of recovery-probe markers."""

    secret_type = 'Alpha Test Marker'
    denylist = (
        re.compile(r'alpha-marker-(one|two)'),
    )


class BetaTestDetector(RegexBasedDetector):
    """Scans for the beta family of recovery-probe markers."""

    secret_type = 'Beta Test Marker'
    denylist = (
        re.compile(r'beta-marker-(one|two)'),
    )
