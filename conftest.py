import os
import sys

# The package uses a src layout; make the working tree importable when tests
# are run directly from a checkout without an editable install.
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
