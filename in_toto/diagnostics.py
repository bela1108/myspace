# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  diagnostics.py

<Purpose>
  Offline diagnostics for in-toto release review.

  A release step may receive more signed link metadata than its threshold
  requires, potentially from different batches of functionaries, which do not
  report the same materials and products. The regular verification workflow
  (see ``verifylib.verify_threshold_constraints``) only reports that the
  artifacts differ, without explaining which signers agree on what.

  This module provides an offline, read-only diagnostic that, for each step:

  1. Classifies every passed link signature according to the existing
     authorization rules and signature checks:

     - ``valid``: signer is authorized for the step and the signature
       verifies (these are the only entries that may join a product view
       group),
     - ``unauthorized``: the signing keyid is not authorized for the step,
     - ``invalid_signature``: the signer is authorized but the signature
       does not verify,
     - ``expired_key``: signature verification failed because the signing
       key expired.

     Invalid or unauthorized signatures explain missing evidence but never
     participate in a valid group.

  2. Groups the valid links by their *provably consistent artifact view*,
     i.e. links reporting identical materials and products. Every group is
     counted towards the step threshold using distinct authorized main
     functionaries, mirroring the counting rules of
     ``verifylib.verify_link_signature_thresholds``.

  3. If at least two groups independently meet the threshold, reports the
     minimal conflicting fields (the artifact paths and hash algorithms that
     differ) together with the signers on each side of the conflict.

  The returned report is a plain JSON-serializable dictionary, suitable for
  embedding into in-toto review tooling. All results are deterministic:
  reordering the input links yields the exact same groups and conflicts.
"""

import hashlib
import json
import logging

from securesystemslib._gpg.exceptions import KeyExpirationError

from in_toto.exceptions import SignatureVerificationError
from in_toto.models.link import Link
from in_toto.verifylib import _get_authorized_verification_key

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)

DIAGNOSTIC_TYPE = "in-toto-threshold-diagnostic"
DIAGNOSTIC_VERSION = 1

STATUS_VALID = "valid"
STATUS_UNAUTHORIZED = "unauthorized"
STATUS_INVALID_SIGNATURE = "invalid_signature"
STATUS_EXPIRED_KEY = "expired_key"

VERDICT_CONSISTENT = "consistent"
VERDICT_CONFLICT = "conflicting_views"
VERDICT_INSUFFICIENT = "insufficient_evidence"


def _build_main_keys_for_subkeys(layout):
    """Map subkey keyids to the main key that delegates trust to them."""
    main_keys_for_subkeys = {}
    for main_key in list(layout.keys.values()):
        for sub_keyid in main_key.get("subkeys", []):
            main_keys_for_subkeys[sub_keyid] = main_key
    return main_keys_for_subkeys


def _get_step(layout, step_name):
    """Return the layout step with the given name."""
    for step in layout.steps:
        if step.name == step_name:
            return step
    raise KeyError(f"layout has no step named '{step_name}'")


def _artifact_view_id(link):
    """Return a stable identifier for a link's materials/products view.

    Two links get the same identifier if and only if their materials and
    products, including all recorded hashes, are provably identical.
    """
    view = {"materials": link.materials, "products": link.products}
    canonical = json.dumps(view, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(canonical).hexdigest()


def _diff_artifact_views(view_a, view_b):
    """Return the minimal fields in which two artifact views disagree.

    A conflicting field is either:

    - an artifact path present in only one of the views
      (``kind`` is ``only_in_group``), or
    - an artifact path present in both views whose recorded hash digests
      differ (``kind`` is ``hash_mismatch``), together with the minimal set
      of hash algorithms whose digests do not match.
    """
    diffs = []
    for section in ("materials", "products"):
        artifacts_a = view_a[section]
        artifacts_b = view_b[section]

        only_in_a = sorted(set(artifacts_a) - set(artifacts_b))
        only_in_b = sorted(set(artifacts_b) - set(artifacts_a))
        diffs.extend(
            {
                "section": section,
                "field": field,
                "kind": "only_in_group",
            }
            for field in [*only_in_a, *only_in_b]
        )

        for field in sorted(set(artifacts_a) & set(artifacts_b)):
            hashes_a = artifacts_a[field]
            hashes_b = artifacts_b[field]
            algorithms = sorted(
                algorithm
                for algorithm in set(hashes_a) | set(hashes_b)
                if hashes_a.get(algorithm) != hashes_b.get(algorithm)
            )
            if algorithms:
                diffs.append(
                    {
                        "section": section,
                        "field": field,
                        "kind": "hash_mismatch",
                        "algorithms": algorithms,
                    }
                )

    return diffs


def classify_step_links(layout, step_name, links_metadata):
    """Classify the passed link signatures for one layout step.

    <Purpose>
      Apply the same authorization and signature checks as
      ``verifylib.verify_link_signature_thresholds``, but without raising on
      threshold failure. Every link gets an explanatory status instead.

    <Arguments>
      layout:
        A ``Layout`` object defining the step and its authorized keys.
      step_name:
        The name of the layout step the links belong to.
      links_metadata:
        A dictionary of ``{<signer keyid>: <Metadata containing a Link>}``.

    <Returns>
      A list of classification dictionaries, sorted by signer keyid, each
      with ``keyid``, ``main_keyid`` (the authorized functionary the signer
      counts towards), ``status`` and ``reason`` entries. Valid entries also
      carry the link's ``view_id``. Invalid or unauthorized entries never
      carry a ``view_id`` and cannot participate in a valid group.
    """
    step = _get_step(layout, step_name)
    main_keys_for_subkeys = _build_main_keys_for_subkeys(layout)
    classifications = []

    # Sort signers so the report does not depend on input ordering.
    for link_keyid in sorted(links_metadata):
        link_metadata = links_metadata[link_keyid]
        entry = {
            "keyid": link_keyid,
            "main_keyid": None,
            "status": None,
            "reason": None,
            "view_id": None,
        }

        link = link_metadata.get_payload()
        if not isinstance(link, Link):
            entry["status"] = STATUS_INVALID_SIGNATURE
            entry["reason"] = "metadata payload is not a link"
            classifications.append(entry)
            continue

        verification_key = _get_authorized_verification_key(
            layout, step, main_keys_for_subkeys, link_keyid
        )
        if verification_key is None:
            entry["status"] = STATUS_UNAUTHORIZED
            entry["reason"] = (
                f"keyid '{link_keyid}' is not authorized to sign links for"
                f" step '{step_name}'"
            )
            classifications.append(entry)
            continue

        entry["main_keyid"] = verification_key["keyid"]

        try:
            link_metadata.verify_signature(verification_key)
        except KeyExpirationError as exc:
            entry["status"] = STATUS_EXPIRED_KEY
            entry["reason"] = str(exc)
            classifications.append(entry)
            continue
        except SignatureVerificationError:
            entry["status"] = STATUS_INVALID_SIGNATURE
            entry["reason"] = (
                f"signature does not verify for keyid '{link_keyid}'"
            )
            classifications.append(entry)
            continue

        entry["status"] = STATUS_VALID
        entry["view_id"] = _artifact_view_id(link)
        classifications.append(entry)

    return classifications


def diagnose_step_links(layout, step_name, links_metadata):
    """Produce the full offline diagnostic report for one layout step.

    <Arguments>
      layout:
        A ``Layout`` object defining the step and its authorized keys.
      step_name:
        The name of the layout step the links belong to.
      links_metadata:
        A dictionary of ``{<signer keyid>: <Metadata containing a Link>}``.

    <Returns>
      A JSON-serializable dictionary with:

      - ``threshold``: the step threshold,
      - ``classifications``: the result of ``classify_step_links``,
      - ``groups``: artifact view groups of valid links, sorted by
        ``view_id``, each with the signers and distinct functionary count,
        and a ``threshold_met`` flag,
      - ``conflicts``: minimal field conflicts between every pair of groups
        that independently meet the threshold (empty if fewer than two
        groups qualify),
      - ``verdict``: one of ``consistent`` (a single view meets the
        threshold), ``conflicting_views`` (at least two views meet the
        threshold) or ``insufficient_evidence`` (no view meets the
        threshold, with invalid/unauthorized signatures explaining why).
    """
    step = _get_step(layout, step_name)
    classifications = classify_step_links(layout, step_name, links_metadata)

    # Group valid links by provably consistent artifact view.
    groups = {}
    for entry in classifications:
        if entry["status"] != STATUS_VALID:
            continue

        view_id = entry["view_id"]
        group = groups.setdefault(
            view_id,
            {"signers": [], "main_keyids": set()},
        )
        group["signers"].append(entry["keyid"])
        group["main_keyids"].add(entry["main_keyid"])

    group_reports = []
    views_by_id = {}
    for view_id in sorted(groups):
        group = groups[view_id]
        signers = sorted(group["signers"])
        main_keyids = sorted(group["main_keyids"])
        functionary_count = len(main_keyids)

        # Re-derive the view from any member link for conflict diffing.
        member_link = links_metadata[signers[0]].get_payload()
        views_by_id[view_id] = {
            "materials": member_link.materials,
            "products": member_link.products,
        }

        group_reports.append(
            {
                "view_id": view_id,
                "signers": signers,
                "main_keyids": main_keyids,
                "functionary_count": functionary_count,
                "threshold_met": functionary_count >= step.threshold,
            }
        )

    qualifying = [group for group in group_reports if group["threshold_met"]]

    conflicts = [
        {
            "group_a": group_a["view_id"],
            "group_b": group_b["view_id"],
            "fields": _diff_artifact_views(
                views_by_id[group_a["view_id"]],
                views_by_id[group_b["view_id"]],
            ),
            "signers": {
                group_a["view_id"]: group_a["signers"],
                group_b["view_id"]: group_b["signers"],
            },
        }
        for index, group_a in enumerate(qualifying)
        for group_b in qualifying[index + 1 :]
    ]

    if not qualifying:
        verdict = VERDICT_INSUFFICIENT
    elif len(qualifying) > 1:
        verdict = VERDICT_CONFLICT
    else:
        verdict = VERDICT_CONSISTENT

    return {
        "threshold": step.threshold,
        "classifications": classifications,
        "groups": group_reports,
        "conflicts": conflicts,
        "verdict": verdict,
    }


def diagnose_layout_links(layout, steps_metadata):
    """Run :func:`diagnose_step_links` for every step of the layout.

    <Arguments>
      layout:
        A ``Layout`` object whose steps are diagnosed.
      steps_metadata:
        A dictionary of link metadata per step and signer, as returned by
        ``verifylib.load_links_for_layout``::

          {<step name>: {<signer keyid>: <Metadata>, ...}, ...}

    <Returns>
      A JSON-serializable diagnostic report. Steps missing from
      ``steps_metadata`` are reported with an empty evidence set.
    """
    step_reports = {}
    for step in sorted(layout.steps, key=lambda item: item.name):
        step_reports[step.name] = diagnose_step_links(
            layout, step.name, steps_metadata.get(step.name, {})
        )

    return {
        "diagnostic": DIAGNOSTIC_TYPE,
        "version": DIAGNOSTIC_VERSION,
        "steps": step_reports,
    }
