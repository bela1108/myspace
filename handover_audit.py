"""Compatibility alias for pcapng.reception."""
from pcapng import reception as _r
globals().update({k: v for k, v in vars(_r).items() if not k.startswith("_")})
