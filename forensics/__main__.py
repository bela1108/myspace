"""Allow python -m forensics to invoke the cross-check CLI."""

from forensics.cli import main

if __name__ == '__main__':
    raise SystemExit(main())
