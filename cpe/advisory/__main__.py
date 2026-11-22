# -*- coding: utf-8 -*-

"""Allow ``python -m cpe.advisory`` to run the local query interface."""

from __future__ import unicode_literals

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
