# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  link.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>
  Santiago Torres <santiago@nyu.edu>

<Started>
  Sep 23, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides a class for link metadata which is information gathered when a
  step of the supply chain is performed.
"""

import contextlib

import attr
import securesystemslib.formats

from in_toto.formats import _check_hash_dict
from in_toto.models.common import Signable
from in_toto.resolver.evidence import EvidenceReport, report_from_hashes

FILENAME_FORMAT = "{step_name}.{keyid:.8}.link"
FILENAME_FORMAT_SHORT = "{step_name}.link"
UNFINISHED_FILENAME_FORMAT = ".{step_name}.{keyid:.8}.link-unfinished"
UNFINISHED_FILENAME_FORMAT_GLOB = ".{step_name}.{pattern}.link-unfinished"


@attr.s(repr=False, init=False)
class Link(Signable):
    """Evidence for a performed step or inspection of the supply chain.

    A Link object is usually contained in a generic Metablock object for signing,
    serialization and I/O capabilities.

    Attributes:
      name: A unique name used to identify the related step or inspection in an
          in-toto layout.

      command: A list of command and command arguments that report how the
          corresponding step is performed.

      materials: A dictionary of the artifacts *used* by the step, i.e::

              {
                "<material path>": {
                  "<hash algorithm name>": "<hash digest of material>",
                  ...
                },
                ...
              }

      products: A dictionary of the artifacts *produced* by the step, i.e::

              {
                "<product path>": {
                  "<hash algorithm name>": "<hash digest of product>",
                  ...
                },
                ...
              }

      byproducts: An opaque dictionary that lists byproducts of the link command
          execution. It should have at least the following entries
          "stdout" (str), "stderr" (str) and "return-value" (int).

      environment: An opaque dictionary that lists information about the
          execution environment of the link command. eg.::

              {
                "variables": "<list of env var KEY=value pairs>",
                "filesystem": "<filesystem info>",
                "workdir": "<CWD when executing link command>"
              }

    """

    _type = attr.ib()
    name = attr.ib()
    materials = attr.ib()
    products = attr.ib()
    byproducts = attr.ib()
    command = attr.ib()
    environment = attr.ib()
    materials_evidence = attr.ib()

    def __init__(self, **kwargs):
        super().__init__()

        self._type = "link"
        self.name = kwargs.get("name")
        self.materials = kwargs.get("materials", {})
        self.products = kwargs.get("products", {})
        self.byproducts = kwargs.get("byproducts", {})
        self.command = kwargs.get("command", [])
        self.environment = kwargs.get("environment", {})

        evidence = kwargs.get("materials_evidence")
        if evidence is None:
            for alias in (
                "material_evidence",
                "materials_report",
                "evidence",
                "evidence_report",
            ):
                if alias in kwargs:
                    evidence = kwargs[alias]
                    break

        if isinstance(evidence, EvidenceReport) or (
            hasattr(evidence, "to_dict") and not isinstance(evidence, dict)
        ):
            evidence = evidence.to_dict()
        elif isinstance(evidence, (dict, list, tuple)):
            with contextlib.suppress(TypeError, ValueError, KeyError):
                evidence = EvidenceReport.from_dict(evidence).to_dict()

        self.materials_evidence = evidence

        self.validate()

    @property
    def type_(self):
        """The string "link" to identify the in-toto metadata type."""
        # NOTE: We expose the type_ property in the API documentation instead of
        # _type to protect it against modification.
        # NOTE: Trailing underscore is used by convention (pep8) to avoid conflict
        # with Python's type keyword.
        return self._type

    @staticmethod
    def read(data):
        """Creates a Link object from its dictionary representation.

        Arguments:
          data: A dictionary with link metadata fields.

        Raises:
          securesystemslib.exceptions.FormatError: Passed data is invalid.

        Returns:
          The created Link object.

        """
        return Link(**data)

    def _validate_type(self):
        """Private method to check that `_type` is set to "link"."""
        if self._type != "link":
            raise securesystemslib.exceptions.FormatError(
                f"Invalid Link: field `_type` must be set to 'link', got: {self._type}"
            )

    def _validate_materials(self):
        """Private method to check that `materials` is a `dict` of `HASHDICTs`."""
        if not isinstance(self.materials, dict):
            raise securesystemslib.exceptions.FormatError(
                f"Invalid Link: field `materials` must be of type dict, got: {type(self.materials)}"
            )

        for material in list(self.materials.values()):
            _check_hash_dict(material)

    def _validate_products(self):
        """Private method to check that `products` is a `dict` of `HASHDICTs`."""
        if not isinstance(self.products, dict):
            raise securesystemslib.exceptions.FormatError(
                f"Invalid Link: field `products` must be of type dict, got: {type(self.products)}"
            )

        for product in list(self.products.values()):
            _check_hash_dict(product)

    def _validate_byproducts(self):
        """Private method to check that `byproducts` is a `dict`."""
        if not isinstance(self.byproducts, dict):
            raise securesystemslib.exceptions.FormatError(
                f"Invalid Link: field `byproducts` must be of type dict, got: {type(self.byproducts)}"
            )

    def _validate_command(self):
        """Private method to check that `command` is a `list`."""
        if not isinstance(self.command, list):
            raise securesystemslib.exceptions.FormatError(
                f"Invalid Link: field `command` must be of type list, got: {type(self.command)}"
            )

    def _validate_environment(self):
        """Private method to check that `environment` is a `dict`."""
        if not isinstance(self.environment, dict):
            raise securesystemslib.exceptions.FormatError(
                f"Invalid Link: field `environment` must be of type dict, got: {type(self.environment)}"
            )

    def _validate_materials_evidence(self):
        """Check that optional material consistency evidence is well formed."""
        if self.materials_evidence is None:
            return

        if not isinstance(self.materials_evidence, (dict, list)):
            raise securesystemslib.exceptions.FormatError(
                "Invalid Link: field `materials_evidence` must be a dict or "
                f"list, got: {type(self.materials_evidence)}"
            )

        try:
            EvidenceReport.from_dict(self.materials_evidence)
        except (TypeError, ValueError, KeyError) as exc:
            raise securesystemslib.exceptions.FormatError(
                "Invalid Link: field `materials_evidence` is malformed"
            ) from exc

    def to_dict(self):
        """Return the JSON-serializable dictionary representation.

        The optional evidence field is omitted when absent so links written by
        older in-toto versions keep their exact representation.
        """
        data = attr.asdict(self)
        if data.get("materials_evidence") is None:
            data.pop("materials_evidence", None)
        return data

    @property
    def materials_report(self):
        """Return a consistency report for the recorded materials."""
        return self.get_materials_report()

    @property
    def evidence(self):
        """Alias for the serialized material evidence."""
        return self.materials_evidence

    def get_materials_evidence(self):
        """Return the raw material evidence attached to this link."""
        return self.materials_evidence

    def get_materials_report(self):
        """Return material evidence as an :class:`EvidenceReport`.

        Links created before evidence recording existed are still readable.
        Their materials are returned as ``unverified`` entries, because the
        digest alone cannot prove that the source was stable while it was read.
        """
        if self.materials_evidence:
            return EvidenceReport.from_dict(self.materials_evidence)

        return report_from_hashes(
            self.materials,
            resolver=self._infer_material_resolver,
            source=lambda name: name,
        )

    def get_evidence_report(self):
        """Alias for :meth:`get_materials_report`."""
        return self.get_materials_report()

    def check_materials_consistency(self):
        """Return whether recorded material evidence proves a stable snapshot."""
        return self.get_materials_report().consistent

    def get_affected_materials(self):
        """Return ``(name, resolver)`` pairs for mixed-snapshot materials."""
        return [
            (entry.name, entry.resolver)
            for entry in self.get_materials_report().affected_entries
        ]

    @property
    def affected_materials(self):
        """Affected material entries as ``(name, resolver)`` pairs."""
        return self.get_affected_materials()

    def verify_materials_consistency(self):
        """Raise if material evidence is missing or describes mixed snapshots."""
        report = self.get_materials_report()
        if not report.consistent:
            details = ", ".join(
                f"{entry.name} ({entry.resolver})"
                for entry in report.affected_entries
            )
            raise ValueError(
                "material evidence does not prove one consistent snapshot"
                + (f": {details}" if details else "")
            )
        return report

    @staticmethod
    def _infer_material_resolver(name):
        """Infer a resolver identifier for legacy material entries."""
        if name.startswith("ostree:"):
            return "ostree"
        if name.startswith("dir:"):
            return "dir"
        return "file"
