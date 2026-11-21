"""
Enough Mach-O to make your head spin.

See the relevant header files in /usr/include/mach-o

And also Apple's documentation.
"""

__version__ = "1.16.4"


def __getattr__(name):
    if name in ("Bindings", "Imports"):
        from macholib import bindings

        return bindings
    raise AttributeError(name)
