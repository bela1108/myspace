# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Module Name>
  in_toto/provenance.py

<Author>
  The in-toto contributors

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides provenance reconciliation for forensic review of supply chain
  evidence, to be used after in-toto verification has completed.

  The module reconstructs provable transfer relations for packages listed
  in an external evidence table by correlating:

    * materials and products recorded in verified link metadata,
    * external signed receipts (who took custody of a package), and
    * step identities (step names and the functionaries who signed links).

  Each evidence table entry is reconciled individually. Two packages that
  share the same digest (e.g. an incident package that was re-packaged
  after quarantine) are reported as two separate provenance entries, and a
  step that outputs the same file twice yields two separate build records.
  A provenance conclusion is only issued for entries whose build step is
  attested in the verified links *and* whose receipt was signed by
  authorized quarantine personnel.

"""

import attr
import securesystemslib.exceptions
import securesystemslib.formats

from in_toto.formats import _check_hash_dict, _check_list, _check_str
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock


class ProvenanceStatus:
    """String constants for the reconciliation status of an evidence table
    entry."""

    CONCLUSIVE = "conclusive"
    """Build step attested and receipt signed by quarantine personnel."""

    MISSING_RECEIPT = "missing-receipt"
    """Build step attested, but no receipt is referenced or found."""

    MISSING_BUILD_STEP = "missing-build-step"
    """A receipt exists, but no verified link attests the build step."""

    MISSING_RECEIPT_AND_BUILD_STEP = "missing-receipt-and-build-step"
    """Neither a receipt nor a build step could be found."""

    RECEIPT_NOT_QUARANTINE = "receipt-not-quarantine"
    """Receipt exists but was not signed by quarantine personnel."""

    RECEIPT_HASH_MISMATCH = "receipt-hash-mismatch"
    """Receipt exists but records different hashes than the package."""


@attr.s(repr=False, init=False)
class Receipt:
    """An external signed receipt attesting package custody.

    Attributes:
      receipt_id: A unique identifier for this receipt, referenced by
          evidence table entries.

      signer: The identity of the person who signed for the package.

      hashes: A dictionary of the form ``{"<hash algorithm>": "<digest>"}``
          identifying the received package.

    """

    receipt_id = attr.ib()
    signer = attr.ib()
    hashes = attr.ib()

    def __init__(self, **kwargs):
        self.receipt_id = kwargs.get("receipt_id")
        self.signer = kwargs.get("signer")
        self.hashes = kwargs.get("hashes", {})

        self.validate()

    def validate(self):
        """Validates attributes of the instance."""
        _check_str(self.receipt_id)
        _check_str(self.signer)
        _check_hash_dict(self.hashes)


@attr.s(repr=False, init=False)
class EvidencePackage:
    """A package entry of the external evidence table.

    Attributes:
      package_id: A unique identifier for this evidence table entry. Two
          entries may carry identical hashes (e.g. a re-packaged incident
          package); they are still reconciled as separate entries.

      hashes: A dictionary of the form ``{"<hash algorithm>": "<digest>"}``
          identifying the package contents.

      receipt_id (optional): The identifier of the external receipt under
          which this package was signed for, or None if no receipt exists.

    """

    package_id = attr.ib()
    hashes = attr.ib()
    receipt_id = attr.ib()

    def __init__(self, **kwargs):
        self.package_id = kwargs.get("package_id")
        self.hashes = kwargs.get("hashes", {})
        self.receipt_id = kwargs.get("receipt_id")

        self.validate()

    def validate(self):
        """Validates attributes of the instance."""
        _check_str(self.package_id)
        _check_hash_dict(self.hashes)
        if self.receipt_id is not None:
            _check_str(self.receipt_id)


@attr.s(repr=False, init=False)
class BuildRecord:
    """One attested origin of a package, i.e. a product recorded in a
    verified link.

    A step that outputs the same file twice (e.g. an original build and a
    re-packaging step) yields one record per occurrence, so the two
    provenances remain distinguishable.

    Attributes:
      step: The name of the step that produced the file.

      product_path: The path of the product in the link's products.

      hashes: The hash dictionary recorded for the product.

      functionaries: The keyids of the functionaries who signed the link,
          empty if only the link payload was provided.

    """

    step = attr.ib()
    product_path = attr.ib()
    hashes = attr.ib()
    functionaries = attr.ib()

    def __init__(self, **kwargs):
        self.step = kwargs.get("step")
        self.product_path = kwargs.get("product_path")
        self.hashes = kwargs.get("hashes", {})
        self.functionaries = kwargs.get("functionaries", [])

        self.validate()

    def validate(self):
        """Validates attributes of the instance."""
        _check_str(self.step)
        _check_str(self.product_path)
        _check_hash_dict(self.hashes)
        _check_list(self.functionaries)
        for keyid in self.functionaries:
            _check_str(keyid)


@attr.s(repr=False, init=False)
class TransferRecord:
    """One attested transfer of a package, i.e. the package appearing as a
    material of a subsequent verified step.

    Attributes:
      step: The name of the step that consumed the file as material.

      material_path: The path of the material in the link's materials.

      hashes: The hash dictionary recorded for the material.

    """

    step = attr.ib()
    material_path = attr.ib()
    hashes = attr.ib()

    def __init__(self, **kwargs):
        self.step = kwargs.get("step")
        self.material_path = kwargs.get("material_path")
        self.hashes = kwargs.get("hashes", {})

        self.validate()

    def validate(self):
        """Validates attributes of the instance."""
        _check_str(self.step)
        _check_str(self.material_path)
        _check_hash_dict(self.hashes)


@attr.s(repr=False, init=False)
class PackageProvenance:
    """The reconciliation result for one evidence table entry.

    Attributes:
      package_id: The identifier of the evidence table entry.

      hashes: The hash dictionary of the package.

      builds: A list of BuildRecord objects attesting where the package was
          produced. Empty if no verified link records a matching product.

      transfers: A list of TransferRecord objects attesting which steps
          received the package as material.

      receipt: The Receipt referenced by the evidence table entry, or None.

      status: One of the ProvenanceStatus constants. A provenance
          conclusion may only be issued if the status is
          ProvenanceStatus.CONCLUSIVE.

      conclusion: A human-readable provenance conclusion, or None if the
          status is not ProvenanceStatus.CONCLUSIVE.

    """

    package_id = attr.ib()
    hashes = attr.ib()
    builds = attr.ib()
    transfers = attr.ib()
    receipt = attr.ib()
    status = attr.ib()
    conclusion = attr.ib()

    def __init__(self, **kwargs):
        self.package_id = kwargs.get("package_id")
        self.hashes = kwargs.get("hashes", {})
        self.builds = kwargs.get("builds", [])
        self.transfers = kwargs.get("transfers", [])
        self.receipt = kwargs.get("receipt")
        self.status = kwargs.get("status")
        self.conclusion = kwargs.get("conclusion")

    @property
    def is_conclusive(self):
        """True if a provenance conclusion may be issued for this entry."""
        return self.status == ProvenanceStatus.CONCLUSIVE


def _hashes_match(hashes_a, hashes_b):
    """Returns True if two hash dictionaries share at least one algorithm
    and all shared digests are equal."""
    common_algorithms = set(hashes_a) & set(hashes_b)
    return bool(common_algorithms) and all(
        hashes_a[algorithm] == hashes_b[algorithm]
        for algorithm in common_algorithms
    )


def _extract_link_and_functionaries(link_metadata):
    """Returns a (Link, functionary keyids) tuple for a Link or Metablock.

    Arguments:
      link_metadata: A Link object, or a Metablock carrying a Link. In the
          latter case the keyids of the signatures on the Metablock are
          returned as the functionaries who performed the step.

    Raises:
      securesystemslib.exceptions.FormatError: The argument is neither a
          Link nor a Metablock carrying a Link.

    """
    if isinstance(link_metadata, Metablock):
        link = link_metadata.signed
        functionaries = [
            signature["keyid"]
            for signature in link_metadata.signatures
            if "keyid" in signature
        ]
    else:
        link = link_metadata
        functionaries = []

    if not isinstance(link, Link):
        raise securesystemslib.exceptions.FormatError(
            "Expected Link or Metablock carrying a Link, got: "
            f"{type(link_metadata)}"
        )

    return link, functionaries


def _index_links(links):
    """Builds (build records, transfer records) indexes from verified links.

    Every product of every link yields one BuildRecord and every material
    yields one TransferRecord, so identical files output by different steps
    (or twice by the same step under different paths) remain separate
    provenance entries.

    """
    builds = []
    transfers = []

    for link_metadata in links:
        link, functionaries = _extract_link_and_functionaries(link_metadata)

        for product_path, product_hashes in link.products.items():
            builds.append(
                BuildRecord(
                    step=link.name,
                    product_path=product_path,
                    hashes=product_hashes,
                    functionaries=functionaries,
                )
            )

        for material_path, material_hashes in link.materials.items():
            transfers.append(
                TransferRecord(
                    step=link.name,
                    material_path=material_path,
                    hashes=material_hashes,
                )
            )

    return builds, transfers


def _render_conclusion(package, builds, transfers, receipt):
    """Renders a human-readable provenance conclusion for a conclusive
    evidence table entry."""
    digests = ", ".join(
        f"{algorithm}={digest}" for algorithm, digest in package.hashes.items()
    )
    origins = "; ".join(
        f"step '{build.step}' (product '{build.product_path}'"
        + (
            ", signed by " + ", ".join(build.functionaries)
            if build.functionaries
            else ""
        )
        + ")"
        for build in builds
    )
    destinations = "; ".join(
        f"step '{transfer.step}' (material '{transfer.material_path}')"
        for transfer in transfers
    )

    conclusion = (
        f"Package '{package.package_id}' ({digests}) was produced by "
        f"{origins} and custody was signed for by quarantine personnel "
        f"'{receipt.signer}' under receipt '{receipt.receipt_id}'."
    )
    if destinations:
        conclusion += f" It was subsequently consumed by {destinations}."

    return conclusion


def review_packages(packages, links, receipts, quarantine_personnel):
    """Reconciles evidence table packages against verified in-toto links and
    external receipts (forensic review entry point).

    This function is intended to be called after in-toto verification (see
    in_toto.verifylib.in_toto_verify) has completed successfully, using the
    verified chain links (e.g. as loaded by
    in_toto.verifylib.load_links_for_layout).

    Arguments:
      packages: A list of EvidencePackage objects, one per evidence table
          entry. Entries with identical hashes are reconciled individually
          and each yields its own PackageProvenance.

      links: An iterable of Link objects (or Metablock objects carrying a
          Link) that passed in-toto verification. Products and materials
          recorded in these links provide the attested build steps and
          transfer relations.

      receipts: A list of Receipt objects representing external signed
          receipts. A receipt is associated with a package via the
          package's receipt_id, never via hashes alone, so that two
          packages with identical hashes keep separate provenances.

      quarantine_personnel: A list of identities authorized to sign for
          quarantined evidence. Only receipts signed by one of these
          identities allow a provenance conclusion.

    Raises:
      securesystemslib.exceptions.FormatError: An argument is malformed.

    Returns:
      A list of PackageProvenance objects, one per evidence table entry, in
      the order the packages were passed. Packages with identical hashes
      yield one entry each.

    """
    _check_list(packages)
    _check_list(receipts)
    _check_list(quarantine_personnel)

    for package in packages:
        if not isinstance(package, EvidencePackage):
            raise securesystemslib.exceptions.FormatError(
                f"Expected EvidencePackage, got: {type(package)}"
            )

    receipts_by_id = {}
    for receipt in receipts:
        if not isinstance(receipt, Receipt):
            raise securesystemslib.exceptions.FormatError(
                f"Expected Receipt, got: {type(receipt)}"
            )
        receipts_by_id[receipt.receipt_id] = receipt

    for person in quarantine_personnel:
        _check_str(person)

    all_builds, all_transfers = _index_links(links)

    results = []
    for package in packages:
        builds = [
            build
            for build in all_builds
            if _hashes_match(build.hashes, package.hashes)
        ]
        transfers = [
            transfer
            for transfer in all_transfers
            if _hashes_match(transfer.hashes, package.hashes)
        ]

        receipt = None
        if package.receipt_id is not None:
            receipt = receipts_by_id.get(package.receipt_id)

        has_build = bool(builds)
        receipt_ok = (
            receipt is not None
            and _hashes_match(receipt.hashes, package.hashes)
            and receipt.signer in quarantine_personnel
        )

        if has_build and receipt_ok:
            status = ProvenanceStatus.CONCLUSIVE
        elif not has_build and receipt is None:
            status = ProvenanceStatus.MISSING_RECEIPT_AND_BUILD_STEP
        elif not has_build:
            status = ProvenanceStatus.MISSING_BUILD_STEP
        elif receipt is None:
            status = ProvenanceStatus.MISSING_RECEIPT
        elif not _hashes_match(receipt.hashes, package.hashes):
            status = ProvenanceStatus.RECEIPT_HASH_MISMATCH
        else:
            status = ProvenanceStatus.RECEIPT_NOT_QUARANTINE

        conclusion = None
        if status == ProvenanceStatus.CONCLUSIVE:
            conclusion = _render_conclusion(
                package, builds, transfers, receipt
            )

        results.append(
            PackageProvenance(
                package_id=package.package_id,
                hashes=package.hashes,
                builds=builds,
                transfers=transfers,
                receipt=receipt,
                status=status,
                conclusion=conclusion,
            )
        )

    return results
