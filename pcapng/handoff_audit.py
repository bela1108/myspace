"""Compatibility alias for pcapng.reception."""
from . import reception as _r
globals().update({k: v for k, v in vars(_r).items() if not k.startswith("_")})
