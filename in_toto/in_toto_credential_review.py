# SPDX-License-Identifier: Apache-2.0

"""Module-name alias for the credential review CLI."""

from in_toto.in_toto_review import create_parser, main

if __name__ == "__main__":
    raise SystemExit(main())
