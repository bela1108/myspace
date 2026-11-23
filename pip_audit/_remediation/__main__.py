"""
The `python -m pip_audit._remediation` entrypoint.
"""

if __name__ == "__main__":  # pragma: no cover
    from pip_audit._remediation.cli import remediation

    remediation()
