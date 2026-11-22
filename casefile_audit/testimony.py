"""Shared STIX custom types for the casefile audit.

``x-testimony`` models a testimony / source statement.  Every citation is
bound to a concrete observation *version* (``source_ref`` + ``version``),
and each testimony declares the number of independent evidence sources it
requires (``required_independent_sources``).
"""

import stix2.base
from stix2.properties import (
    EmbeddedObjectProperty, IntegerProperty, ListProperty, StringProperty,
    TimestampProperty,
)
from stix2.v21 import CustomObject


class Citation(stix2.base._STIXBase):
    """A reference pinned to one specific version of the cited object."""

    _properties = {
        "source_ref": StringProperty(required=True),
        "version": TimestampProperty(required=True),
    }


@CustomObject(
    "x-testimony",
    [
        ("statement", StringProperty(required=True)),
        ("required_independent_sources", IntegerProperty(required=True, min=1)),
        ("citations", ListProperty(EmbeddedObjectProperty(type=Citation), required=True)),
    ],
)
class Testimony:
    """A testimony statement with version-pinned citations."""
