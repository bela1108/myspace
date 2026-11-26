"""Compatibility import for the B705 response header contract plugin."""

from bandit.plugins.response_headers import (  # noqa: F401
    analyze_file,
    analyze_source,
    gen_config,
    http_response_headers,
    missing_security_headers,
    normalise_config,
    response_header_contract,
    response_headers,
    security_headers,
)
