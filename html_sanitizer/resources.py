"""
Optional resource constraints for sanitized HTML.

External references fall into two categories:

- ``automatic`` references (``<img src>`` and friends) are fetched by the
  client as soon as the page is rendered.
- ``interactive`` references (``<a href>`` and friends) are only opened
  when the user explicitly clicks them.

A caller-provided, read-only *resolver* confirms each automatic reference
against caller-managed data, for example a table of reviewed assets. The
resolver never has to access the network; it only maps URLs to license or
permission records.
"""

from dataclasses import dataclass
from types import MappingProxyType


__all__ = (
    "AUTOMATIC_RESOURCE_ATTRIBUTES",
    "INTERACTIVE_RESOURCE_ATTRIBUTES",
    "AssetTable",
    "ResourceDecision",
    "ResourceReference",
    "collect_references",
)


# Attributes which are fetched automatically when the page is rendered.
AUTOMATIC_RESOURCE_ATTRIBUTES = {
    "img": ("src",),
    "iframe": ("src",),
    "embed": ("src",),
    "audio": ("src",),
    "video": ("src", "poster"),
    "source": ("src",),
}

# Attributes which are only followed on explicit user interaction.
INTERACTIVE_RESOURCE_ATTRIBUTES = {
    "a": ("href",),
    "area": ("href",),
}


@dataclass(frozen=True)
class ResourceDecision:
    """Approval record tracing a resource back to its license."""

    license: str
    license_url: str | None = None


@dataclass
class ResourceReference:
    """A single external reference found in a sanitized tree."""

    url: str
    kind: str  # "automatic" or "interactive"
    tag: str
    attribute: str
    decision: ResourceDecision | None = None


def collect_references(tree, resolver=None):
    """
    Build the manifest of resource references from a final tree.

    If a resolver is given, automatic references are annotated with the
    resolver's decision. Interactive references are listed as-is; they are
    never fetched automatically and therefore do not require approval.
    """
    references = []
    tables = (
        ("automatic", AUTOMATIC_RESOURCE_ATTRIBUTES),
        ("interactive", INTERACTIVE_RESOURCE_ATTRIBUTES),
    )
    for element in tree.iter():
        for kind, table in tables:
            for attribute in table.get(element.tag, ()):
                url = element.get(attribute)
                if not url:
                    continue
                reference = ResourceReference(
                    url=url, kind=kind, tag=element.tag, attribute=attribute
                )
                if kind == "automatic" and resolver is not None:
                    reference.decision = resolver(url, reference)
                references.append(reference)
    return references


class AssetTable:
    """
    Read-only resolver backed by a local asset table.

    The mapping is copied into a read-only proxy and lookups never touch
    the network. Values may be ``ResourceDecision`` instances or plain
    license strings.
    """

    def __init__(self, assets):
        self._assets = MappingProxyType(
            {
                url: (
                    decision
                    if isinstance(decision, ResourceDecision)
                    else ResourceDecision(license=decision)
                )
                for url, decision in assets.items()
            }
        )

    def __call__(self, url, reference):
        return self._assets.get(url)

    def __contains__(self, url):
        return url in self._assets
