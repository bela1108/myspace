"""Verification helpers for location-bound in-toto handoffs."""

from dataclasses import dataclass
from datetime import timezone
from hashlib import sha256
from typing import Optional, Tuple  # noqa: UP035

from dateutil.parser import parse
from securesystemslib.exceptions import Error, FormatError

from in_toto.models.layout import Layout, Step
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock

EAST_ASSEMBLY = "east-assembly"
CENTRAL_STAGING = "central-staging"
WEST_DELIVERY = "west-delivery"

HANDOFF = "local-handoff.json"
CONTRACT = "location-contract.json"
RECEIPT = "sealed-receipt.json"
SUMMARY = "product-summary.json"

REQUIRED_DOCUMENTS = (HANDOFF, CONTRACT, RECEIPT)


class RegionalPolicyError(Error):
    """Raised when a location-bound policy cannot be represented."""


@dataclass(frozen=True)
class LocationObligation:
    """Location and evidence required at one supply-chain step."""

    step: str
    region: str
    site: str
    requires: Tuple[str, ...]  # noqa: UP006
    predecessor: Optional[str] = None


@dataclass(frozen=True)
class RegionalLayout:
    """Standard in-toto layout and the per-step location obligations."""

    layout: Layout
    obligations: Tuple[LocationObligation, ...]  # noqa: UP006

    def __post_init__(self):
        step_names = {step.name for step in self.layout.steps}
        obligation_steps = {obligation.step for obligation in self.obligations}

        if step_names != obligation_steps:
            raise RegionalPolicyError(
                "Location obligations must cover exactly the layout steps"
            )

        if len(obligation_steps) != len(self.obligations):
            raise RegionalPolicyError("Duplicate location obligations")


@dataclass(frozen=True)
class RegionalConclusion:
    """Verification result for one region and its step."""

    step: str
    region: str
    site: str
    valid: bool
    failures: Tuple[str, ...]  # noqa: UP006


def create_two_transfer_layout(keys):
    """Create the small east-to-central-to-west two-handoff layout."""

    steps = []
    for name, key in (
        (EAST_ASSEMBLY, keys["east"]),
        (CENTRAL_STAGING, keys["central"]),
        (WEST_DELIVERY, keys["west"]),
    ):
        step = Step(name=name, pubkeys=[key["keyid"]])
        steps.append(step)

    layout = Layout(
        steps=steps,
        keys={key["keyid"]: key for key in keys.values()},
    )

    layout.get_step_by_name(EAST_ASSEMBLY).add_product_rule_from_string(
        f"CREATE {SUMMARY}"
    )
    for document in REQUIRED_DOCUMENTS:
        layout.get_step_by_name(EAST_ASSEMBLY).add_product_rule_from_string(
            f"CREATE {document}"
        )

    central = layout.get_step_by_name(CENTRAL_STAGING)
    for document in (SUMMARY, *REQUIRED_DOCUMENTS):
        central.add_material_rule_from_string(
            f"MATCH {document} WITH PRODUCTS FROM {EAST_ASSEMBLY}"
        )
        central.add_product_rule_from_string(f"CREATE {document}")

    west = layout.get_step_by_name(WEST_DELIVERY)
    west.add_material_rule_from_string(
        f"MATCH {SUMMARY} WITH PRODUCTS FROM {EAST_ASSEMBLY}"
    )
    for document in REQUIRED_DOCUMENTS:
        west.add_material_rule_from_string(
            f"MATCH {document} WITH PRODUCTS FROM {CENTRAL_STAGING}"
        )
        west.add_product_rule_from_string(f"CREATE {document}")
    west.add_product_rule_from_string(f"CREATE {SUMMARY}")

    obligations = (
        LocationObligation(
            step=EAST_ASSEMBLY,
            region="east",
            site="east-assembly-plant",
            requires=(HANDOFF, CONTRACT, RECEIPT),
        ),
        LocationObligation(
            step=CENTRAL_STAGING,
            region="central",
            site="central-bonded-warehouse",
            requires=(HANDOFF, CONTRACT, RECEIPT),
            predecessor=EAST_ASSEMBLY,
        ),
        LocationObligation(
            step=WEST_DELIVERY,
            region="west",
            site="west-delivery-gate",
            requires=(HANDOFF, CONTRACT, RECEIPT),
            predecessor=CENTRAL_STAGING,
        ),
    )
    return RegionalLayout(layout=layout, obligations=obligations)


def make_regional_link(  # noqa: PLR0913
    *,
    step,
    region,
    site,
    production_id,
    authorization,
    signer,
    materials=None,
    products=None,
    documents,
    receipt_valid_until,
    override_authorization=None,
):
    """Create and sign a link carrying local handoff evidence."""

    byproducts = {
        "return-value": 0,
        "location": {"region": region, "site": site},
        "production_id": production_id,
        "authorization": override_authorization
        or {
            **authorization,
            "production_id": production_id,
            "step": step,
            "region": region,
            "site": site,
        },
        "documents": {
            name: _hash_document(document)
            for name, document in documents.items()
        },
        "sealed_receipt": {
            "sealed": True,
            "valid_until": receipt_valid_until,
            "sha256": _hash_document(documents[RECEIPT]),
        },
    }
    link = Link(
        name=step,
        materials=materials or {},
        products=products or {},
        byproducts=byproducts,
        environment={"workdir": site},
    )
    metadata = Metablock(signed=link)
    metadata.create_signature(signer)
    return metadata


def verify_regional_layout(regional_layout, links, *, as_of):
    """Verify per-step signatures, locations, receipts, and authorizations."""

    verification_time = _parse_time(as_of)
    layout = regional_layout.layout
    conclusions = []
    authorizations = {}
    production_steps = {}

    for obligation in regional_layout.obligations:
        failures = []
        metadata = links.get(obligation.step)
        link = metadata.signed if isinstance(metadata, Metablock) else None

        if metadata is None or not isinstance(link, Link):
            conclusions.append(
                _conclusion(obligation, ("missing signed link",))
            )
            continue

        if link.name != obligation.step:
            failures.append("link is bound to a different step")

        failures.extend(_verify_signature(layout, obligation, metadata))
        failures.extend(_verify_location(obligation, link))
        failures.extend(_verify_documents(obligation, link, verification_time))
        failures.extend(_verify_authorization(link, authorizations))

        production_id = link.byproducts.get("production_id")
        if production_id and not failures:
            authorizations.setdefault(production_id, set()).add(obligation.step)
            production_steps.setdefault(production_id, set()).add(
                obligation.step
            )

        if obligation.predecessor:
            previous_steps = production_steps.get(production_id, set())
            if obligation.predecessor not in previous_steps:
                failures.append(
                    "missing authorization from predecessor "
                    f"'{obligation.predecessor}'"
                )

        conclusions.append(_conclusion(obligation, tuple(failures)))

    return tuple(conclusions)


def replace_receipt(metadata, signer, receipt, valid_until):
    """Replace only one region's receipt and return a newly signed link."""

    link = metadata.signed
    documents = dict(link.byproducts["documents"])
    documents[RECEIPT] = _hash_document(receipt)
    byproducts = dict(link.byproducts)
    byproducts["documents"] = documents
    byproducts["sealed_receipt"] = {
        "sealed": True,
        "valid_until": valid_until,
        "sha256": _hash_document(receipt),
    }
    products = dict(link.products)
    products[RECEIPT] = {"sha256": _hash_document(receipt)}
    replacement_link = Link(
        name=link.name,
        materials=link.materials,
        products=products,
        byproducts=byproducts,
        command=link.command,
        environment=link.environment,
    )
    replacement = Metablock(signed=replacement_link)
    replacement.create_signature(signer)
    return replacement


def _verify_signature(layout, obligation, metadata):
    step = layout.get_step_by_name(obligation.step)
    for keyid in step.pubkeys:
        try:
            metadata.verify_signature(layout.keys[keyid])
            return ()
        except Error:
            continue
    return ("link signature is not valid for this step's functionary",)


def _verify_location(obligation, link):
    location = link.byproducts.get("location", {})
    if location.get("region") != obligation.region:
        return ("link was not produced in the required region",)
    if location.get("site") != obligation.site:
        return ("link was not produced at the required site",)
    return ()


def _verify_documents(obligation, link, verification_time):
    failures = []
    documents = link.byproducts.get("documents", {})
    for document in obligation.requires:
        if document not in documents:
            failures.append(f"missing document '{document}'")
            continue
        if document not in link.products:
            failures.append(f"document '{document}' is not a signed product")
            continue
        if link.products[document].get("sha256") != documents[document]:
            failures.append(f"document hash mismatch for '{document}'")

    receipt = link.byproducts.get("sealed_receipt", {})
    if not receipt.get("sealed"):
        failures.append("receipt is not sealed")
    if receipt.get("sha256") != documents.get(RECEIPT):
        failures.append("sealed receipt does not match the receipt product")
    try:
        if _parse_time(receipt.get("valid_until")) < verification_time:
            failures.append("sealed receipt has expired")
    except (TypeError, ValueError):
        failures.append("sealed receipt has an invalid expiration")
    return tuple(failures)


def _verify_authorization(link, authorizations):
    authorization = link.byproducts.get("authorization", {})
    production_id = link.byproducts.get("production_id")
    required = (
        "authorization_id",
        "production_id",
        "step",
        "region",
        "site",
        "summary_digest",
    )
    failures = [
        f"missing authorization field '{field}'"
        for field in required
        if authorization.get(field) is None
    ]
    if not failures and authorization["production_id"] != production_id:
        failures.append("authorization belongs to a different production")
    if authorization.get("step") != link.name:
        failures.append("authorization cannot be reused on another step")
    if authorization.get("region") != link.byproducts.get("location", {}).get(
        "region"
    ):
        failures.append("authorization cannot be reused in another region")
    if authorization.get("site") != link.byproducts.get("location", {}).get(
        "site"
    ):
        failures.append("authorization cannot be reused at another site")
    if authorization.get("summary_digest") != _summary_digest(link):
        failures.append("authorization cannot be reused for another summary")

    prior_steps = authorizations.get(production_id, set())
    if link.name in prior_steps:
        failures.append("authorization was already consumed by this step")
    return tuple(failures)


def _summary_digest(link):
    summary = link.products.get(SUMMARY)
    return summary.get("sha256") if isinstance(summary, dict) else None


def _conclusion(obligation, failures):
    return RegionalConclusion(
        step=obligation.step,
        region=obligation.region,
        site=obligation.site,
        valid=not failures,
        failures=failures,
    )


def _hash_document(document):
    if not isinstance(document, (str, bytes)):
        raise FormatError("handoff documents must be strings or bytes")
    if isinstance(document, str):
        document = document.encode()
    return sha256(document).hexdigest()


def _parse_time(value):
    parsed = parse(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
