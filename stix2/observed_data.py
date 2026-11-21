"""Offline import helpers for STIX 2.0 observed-data.

This module is a thin compatibility surface around stix2.migration.
"""

from .migration import *  # noqa: F401,F403
from .migration import ObservedDataConversion, ObservedDataConverter

ObservedDataImporter = ObservedDataConverter
ImportResult = ObservedDataConversion
