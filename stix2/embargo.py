"""Backward-friendly alias for :mod:`stix2.delivery`.

The delivery-preview API is embargo-oriented, so some publishing backends
import it as ``stix2.embargo``.  The implementation lives in
:mod:`stix2.delivery`.
"""

from .delivery import *  # noqa: F401,F403
from .delivery import __all__  # noqa: F401
