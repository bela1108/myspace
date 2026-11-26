# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  switch_verify.py

<Purpose>
  Provides offline, replayable verification for a release that switches
  between two signed layouts: a fallback (incident) layout and a normal
  (recovered) layout.

  A fallback build is allowed to ship during an incident.  The first normal
  product after recovery must additionally prove that artifacts produced by
  the fallback build did not survive in the shared build cache without a
  human review.  The decision is derived exclusively from signed layout
  metadata, signed link metadata (materials and products are the signed bill
  of materials and production statement), and optional signed cache/review
  manifests.  No network, wall clock, file modification time, or
  last-writer-wins ``mode`` marker influences the result.

  Concurrent jobs are evaluated conservatively.  If several links coexist for
  a step, every trusted link is considered; links that disagree on artifacts
  are rejected instead of selecting the one that was written last.

  Artifacts are taken from signed link statements.  The working tree is never
  inspected, so a writer that races with verification cannot change the
  verdict by replacing a file or flipping a permission mode.
"""

import hashlib
import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Optional

import securesystemslib.exceptions
from securesystemslib._gpg.exceptions import KeyExpirationError

import in_toto.exceptions
import in_toto.verifylib
from in_toto.exceptions import SignatureVerificationError
from in_toto.models.link import Link
from in_toto.models.metadata import Metadata

LOG = logging.getLogger(__name__)

FALLBACK = "fallback"
NORMAL = "normal"
RELEASE = "release"
QUARANTINE = "quarantine"

_MODE_KEYS = ("switch-mode", "switch_mode", "mode")


def _check_keys(keys, name):
    """Validate a public key dictionary passed to this module."""
    if not isinstance(keys, Mapping):
        raise securesystemslib.exceptions.FormatError(
            f"'{name}' must be a public key dictionary."
        )

    for key in keys.values():
        if not isinstance(key, Mapping) or "keyid" not in key:
            raise securesystemslib.exceptions.FormatError(
                f"'{name}' contains a malformed public key."
            )


def _keyids(keys):
    """Return all keyids, including subkey ids, for a key dictionary."""
    keyids = set()
    for keyid, key in keys.items():
        keyids.add(key.get("keyid", keyid))
        keyids.update(key.get("subkeys", {}).keys())

    return keyids


def _signature_keyids(metadata):
    """Return signature keyids for Metablock and Envelope metadata."""
    signatures = getattr(metadata, "signatures", [])

    if isinstance(signatures, Mapping):
        return set(signatures.keys())

    keyids = set()
    for signature in signatures:
        if isinstance(signature, Mapping) and "keyid" in signature:
            keyids.add(signature["keyid"])

    return keyids


def _payload(metadata):
    """Return the signed Layout or Link from a Metadata object."""
    if not isinstance(metadata, Metadata):
        raise securesystemslib.exceptions.FormatError(
            "Expected an in-toto Metadata object."
        )

    return metadata.get_payload()


def _as_layout(metadata, label):
    """Return a Layout payload or raise a format error."""
    payload = _payload(metadata)
    if payload.type_ != "layout":
        raise securesystemslib.exceptions.FormatError(
            f"Expected a layout in '{label}' metadata."
        )

    return payload


def _as_link(metadata, label="link"):
    """Return a Link payload or raise a format error."""
    payload = _payload(metadata)
    if payload.type_ != "link":
        raise securesystemslib.exceptions.FormatError(
            f"Expected a link in '{label}' metadata."
        )

    return payload


def _verified_keyids(metadata, keys):
    """Return the keyids from ``keys`` that verify a signature."""
    verified = []
    for keyid in sorted(keys):
        try:
            metadata.verify_signature(keys[keyid])

        except (SignatureVerificationError, KeyExpirationError):
            continue

        verified.append(keyid)

    return verified


def _verify_layout_signoff(metadata, keys, label, strict_attribution):
    """Verify one layout's designated manual sign-offs.

    Returns the sorted list of designated keyids that signed the layout.  If
    ``strict_attribution`` is set, signatures from keys that do not belong to
    this layout are rejected instead of silently ignored.
    """
    _as_layout(metadata, label)
    _check_keys(keys, f"{label} layout keys")

    if not keys:
        raise SignatureVerificationError(
            f"Layout '{label}' requires at least one sign-off key."
        )

    in_toto.verifylib.verify_metadata_signatures(metadata, keys)

    designated = _keyids(keys)
    present = _signature_keyids(metadata)
    foreign = present - designated
    if strict_attribution and foreign:
        raise in_toto.exceptions.SwitchVerificationError(
            f"Layout '{label}' carries sign-off(s) from key(s) that do not"
            f" belong to this layout: {', '.join(sorted(foreign))}."
        )

    return sorted(designated & present)


def verify_layout_signoffs(  # noqa: PLR0913
    fallback_layout,
    fallback_layout_keys,
    normal_layout=None,
    normal_layout_keys=None,
    require_distinct_signers=False,
    strict_attribution=True,
):
    """Verify that each layout is signed by its own sign-off keys.

    Sign-offs are attributed per layout.  A signature made for one layout is
    not allowed to stand in for the other layout.  If
    ``require_distinct_signers`` is set, the two designated key sets must be
    disjoint.

    Arguments:
      fallback_layout: Metadata containing the fallback Layout.
      fallback_layout_keys: Public keys that must sign the fallback layout.
      normal_layout (optional): Metadata containing the normal Layout.
      normal_layout_keys (optional): Public keys that must sign the normal
          layout.  Required if ``normal_layout`` is passed.
      require_distinct_signers (optional): Reject layouts that share signers.
      strict_attribution (optional): Reject foreign signatures on a layout.

    Raises:
      SignatureVerificationError: A designated key did not sign its layout.
      SwitchVerificationError: Sign-off attribution is ambiguous.

    Returns:
      A dictionary mapping ``"fallback"`` and optionally ``"normal"`` to the
      sorted keyids that signed the respective layout.
    """
    signoffs = {
        FALLBACK: _verify_layout_signoff(
            fallback_layout,
            fallback_layout_keys,
            FALLBACK,
            strict_attribution,
        )
    }

    if normal_layout is None:
        return signoffs

    if normal_layout_keys is None:
        raise in_toto.exceptions.SwitchVerificationError(
            "Normal layout sign-off keys are required for a normal release."
        )

    signoffs[NORMAL] = _verify_layout_signoff(
        normal_layout,
        normal_layout_keys,
        NORMAL,
        strict_attribution,
    )

    if require_distinct_signers:
        shared = _keyids(fallback_layout_keys) & _keyids(normal_layout_keys)
        if shared:
            raise in_toto.exceptions.SwitchVerificationError(
                "Layout sign-off keys must be distinct, but these keys belong"
                f" to both layouts: {', '.join(sorted(shared))}."
            )

    return signoffs


def _normalize_artifacts(artifacts):
    """Validate and copy an artifact dictionary (path -> hash dict)."""
    if artifacts is None:
        return {}

    if not isinstance(artifacts, Mapping):
        raise securesystemslib.exceptions.FormatError(
            "Artifacts must be a dictionary of paths to hash dictionaries."
        )

    normalized = {}
    for path in sorted(artifacts):
        hashes = artifacts[path]
        if not isinstance(path, str) or not isinstance(hashes, Mapping):
            raise securesystemslib.exceptions.FormatError(
                "Artifacts must be a dictionary of paths to hash dictionaries."
            )

        normalized[path] = dict(sorted(hashes.items()))

    return normalized


def _intersection(left, right):
    """Return artifacts whose path and all recorded hashes match."""
    return {
        path: hashes
        for path, hashes in left.items()
        if path in right and right[path] == hashes
    }


def _difference(left, right):
    """Return artifacts that are not present with identical hashes in right."""
    return {
        path: hashes
        for path, hashes in left.items()
        if not (path in right and right[path] == hashes)
    }


def _merge_artifacts(sources):
    """Merge artifact maps and report paths with divergent hashes.

    ``sources`` is an iterable of ``(origin, artifacts)`` tuples.

    Returns:
      A tuple ``(merged, divergences)`` where divergences is a list of
      dictionaries describing a path that was observed with different hashes
      in different sources.
    """
    merged = {}
    observed_by = {}
    divergences = []

    for origin, artifacts in sources:
        for path, hashes in _normalize_artifacts(artifacts).items():
            if path in merged and merged[path] != hashes:
                divergences.append(
                    {
                        "path": path,
                        "first_origin": observed_by[path],
                        "first_hashes": merged[path],
                        "conflicting_origin": origin,
                        "conflicting_hashes": hashes,
                    }
                )
                continue

            if path not in merged:
                merged[path] = hashes
                observed_by[path] = origin

    return merged, divergences


def assess_junction(
    fallback_products,
    normal_materials,
    cache_entries=None,
    reviewed_materials=None,
):
    """Assess material risk at a fallback-to-normal build boundary.

    The junction is risky when an artifact produced by the fallback build is
    still present in the cache when the normal build starts, and that exact
    path and digest pair has not been approved by a signed review manifest.
    The check is intentionally independent of any ``mode`` marker.

    Arguments:
      fallback_products: Artifacts produced by the fallback build.
      normal_materials: Artifacts consumed by the first normal build.
      cache_entries (optional): Signed snapshot of the cache at the junction.
          If omitted, all fallback products are assumed to remain cached.
      reviewed_materials (optional): Artifacts explicitly approved by a signed
          review manifest.

    Returns:
      A dictionary with ``fallback_products``, ``normal_materials``,
      ``cache_entries``, ``residue``, ``reviewed``, ``unreviewed``,
      ``consumed``, ``divergences`` and ``relocated`` entries.
    """
    fallback = _normalize_artifacts(fallback_products)
    normal = _normalize_artifacts(normal_materials)
    cache = (
        fallback
        if cache_entries is None
        else _normalize_artifacts(cache_entries)
    )
    reviewed = _normalize_artifacts(reviewed_materials)

    # Material consumed by the normal build must have been in the cache, even
    # if the cache snapshot omitted it.  Merge it in conservatively and flag
    # hash conflicts instead of letting the snapshot win.
    effective_cache, divergences = _merge_artifacts(
        [("cache", cache), ("normal-materials", normal)]
    )

    residue = _intersection(fallback, effective_cache)
    consumed = _intersection(fallback, normal)

    # A fallback artifact may have been renamed in the cache.  Match content
    # by hash as well, so a moved artifact still needs an explicit review of
    # its new path and digest.
    fallback_by_hash = {}
    for path, hashes in fallback.items():
        fallback_by_hash.setdefault(_canonical_json(hashes), []).append(path)

    relocated = []
    for origin, artifacts in (
        ("cache", effective_cache),
        ("normal-materials", normal),
    ):
        for path, hashes in artifacts.items():
            if path in fallback:
                continue

            original_paths = fallback_by_hash.get(_canonical_json(hashes))
            if not original_paths:
                continue

            residue.setdefault(path, hashes)
            if origin == "normal-materials":
                consumed.setdefault(path, hashes)

            entry = {
                "path": path,
                "hashes": hashes,
                "original_paths": sorted(original_paths),
                "origin": origin,
            }
            if entry not in relocated:
                relocated.append(entry)

    # Include consumed fallback products even if a malformed/partial cache
    # snapshot did not list them.
    for path, hashes in consumed.items():
        residue.setdefault(path, hashes)

    reviewed_residue = _intersection(residue, reviewed)
    unreviewed_residue = _difference(residue, reviewed)

    return {
        "fallback_products": fallback,
        "normal_materials": normal,
        "cache_entries": cache,
        "residue": residue,
        "reviewed": reviewed_residue,
        "unreviewed": unreviewed_residue,
        "consumed": consumed,
        "divergences": divergences,
        "relocated": relocated,
    }


def _link_mode(payload):  # noqa: C901
    """Read an optional, signed mode claim from a Link.

    Mode claims are informational only.  They are never used to choose between
    co-existing links.
    """
    for container_name in ("byproducts", "environment"):
        container = getattr(payload, container_name, {}) or {}
        if not isinstance(container, Mapping):
            continue

        for key in _MODE_KEYS:
            value = container.get(key)
            if isinstance(value, str):
                return value

        switch_data = container.get("switch")
        if isinstance(switch_data, Mapping):
            value = switch_data.get("mode")
            if isinstance(value, str):
                return value

        variables = container.get("variables")
        if isinstance(variables, (list, tuple)):
            for variable in variables:
                if not isinstance(variable, str):
                    continue
                name, separator, value = variable.partition("=")
                if separator and name.upper() in {
                    "MODE",
                    "SWITCH_MODE",
                    "IN_TOTO_SWITCH_MODE",
                }:
                    return value

    return None


def _iter_link_metadata(value):
    """Yield Metadata objects from nested mappings and sequences."""
    if isinstance(value, Metadata):
        yield value

    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _iter_link_metadata(item)

    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_link_metadata(item)

    elif value is not None:
        raise securesystemslib.exceptions.FormatError(
            "Expected link Metadata, a mapping of link Metadata, or a list."
        )


def _load_link_file(path):
    """Load one link metadata file, ignoring non-link payloads."""
    try:
        metadata = Metadata.load(path)
        _as_link(metadata, path)
        return metadata

    except (OSError, ValueError, securesystemslib.exceptions.FormatError) as e:
        LOG.warning("Ignoring link file '%s': %s", path, e)
        return None


def _load_links_from_dir(path):
    """Load all ``*.link`` files in deterministic filename order.

    File modification time is deliberately not consulted.  Unfinished link
    files are not evidence and are ignored.
    """
    if not os.path.isdir(path):
        raise in_toto.exceptions.SwitchVerificationError(
            f"Link directory does not exist: {path}"
        )

    links = []
    for name in sorted(os.listdir(path)):
        if not name.endswith(".link"):
            continue

        metadata = _load_link_file(os.path.join(path, name))
        if metadata is not None:
            links.append(metadata)

    return links


def _coerce_links(value):
    """Turn a link path, mapping or sequence into a list of Metadata."""
    if isinstance(value, (str, os.PathLike)):
        return _load_links_from_dir(os.fspath(value))

    return list(_iter_link_metadata(value))


@dataclass
class _LinkRecord:
    """A trusted link plus the keyids that verified its signature."""

    metadata: Metadata
    payload: Link
    signers: list[str]
    modes: list[str] = field(default_factory=list)


def _records_for_links(links, trusted_keys, label):
    """Verify signatures on all links and return trusted records."""
    records = []
    for metadata in links:
        payload = _as_link(metadata, label)
        signers = _verified_keyids(metadata, trusted_keys)
        if not signers:
            LOG.warning(
                "Ignoring '%s' link for step '%s': no trusted signature.",
                label,
                payload.name,
            )
            continue

        mode = _link_mode(payload)
        records.append(
            _LinkRecord(
                metadata=metadata,
                payload=payload,
                signers=signers,
                modes=[mode] if mode else [],
            )
        )

    return records


def _step_authorized_keyids(layout, step):
    """Return keyids that may legitimately sign a step's link."""
    authorized = set(step.pubkeys)
    main_keys_for_subkeys = {}
    for main_keyid, main_key in layout.keys.items():
        for subkeyid in main_key.get("subkeys", {}):
            main_keys_for_subkeys[subkeyid] = main_keyid

    for keyid in step.pubkeys:
        key = layout.keys.get(keyid)
        if key:
            authorized.update(key.get("subkeys", {}))
        if keyid in main_keys_for_subkeys:
            authorized.add(main_keys_for_subkeys[keyid])

    return authorized


def _steps_metadata(layout, records):
    """Build in-toto's step -> keyid -> Metadata mapping.

    Duplicate links for the same step and signing key are only accepted if
    they describe identical artifacts.  Otherwise they are concurrent
    leftovers and the verification fails instead of using whichever file was
    written last.
    """
    steps = {step.name: {} for step in layout.steps}
    steps_by_name = {step.name: step for step in layout.steps}

    for record in records:
        step_name = record.payload.name
        if step_name not in steps:
            continue

        # A single link must not count more than once towards a threshold,
        # even if it carries several signatures.
        authorized = _step_authorized_keyids(layout, steps_by_name[step_name])
        keyid = next(
            (signer for signer in record.signers if signer in authorized),
            record.signers[0],
        )

        existing = steps[step_name].get(keyid)
        if existing is None:
            steps[step_name][keyid] = record.metadata
            continue

        existing_payload = _as_link(existing)
        if (
            existing_payload.materials != record.payload.materials
            or existing_payload.products != record.payload.products
        ):
            raise in_toto.exceptions.ConcurrentModeError(
                f"Conflicting links for step '{step_name}' signed by"
                f" '{keyid}'.  Refusing to select the last-written file."
            )

    return steps


def _enforce_link_agreement(layout, verified_links):
    """Require all trusted links of a step to agree on artifacts.

    This applies even when the layout threshold is one.  Otherwise a
    double-signed or concurrently produced link could be selected merely by
    iteration order.
    """
    for step in layout.steps:
        key_links = verified_links.get(step.name, {})
        reference_keyid = None
        reference_payload = None

        for keyid, payload in key_links.items():
            if reference_payload is None:
                reference_keyid = keyid
                reference_payload = payload
                continue

            if (
                payload.materials != reference_payload.materials
                or payload.products != reference_payload.products
            ):
                raise in_toto.exceptions.ConcurrentModeError(
                    f"Step '{step.name}' has co-existing links signed by"
                    f" '{reference_keyid}' and '{keyid}' that disagree on"
                    " artifacts.  A mode marker cannot resolve this; replay is"
                    " refusing to choose."
                )


def _replay_layout(layout, records):
    """Replay in-toto signature, threshold and artifact-rule verification."""
    steps_metadata = _steps_metadata(layout, records)

    verified_metadata = in_toto.verifylib.verify_link_signature_thresholds(
        layout, steps_metadata
    )

    # Resolve Metadata to Link payloads.  This feature verifies plain links;
    # sublayout delegation is intentionally not replayed here.
    verified = {
        step_name: {
            keyid: _as_link(metadata)
            for keyid, metadata in key_metadata.items()
        }
        for step_name, key_metadata in verified_metadata.items()
    }

    _enforce_link_agreement(layout, verified)
    in_toto.verifylib.verify_all_steps_command_alignment(layout, verified)
    in_toto.verifylib.verify_threshold_constraints(layout, verified)
    reduced = in_toto.verifylib.reduce_chain_links(verified)
    in_toto.verifylib.verify_all_item_rules(layout.steps, reduced)

    return verified, reduced


def _coerce_bom(bom, keys, threshold, label, allow_unsigned):
    """Return a verified signed material manifest as path -> hashes."""
    if bom is None:
        return {}

    if isinstance(bom, Metadata):
        payload = _as_link(bom, label)
        if not allow_unsigned:
            _check_keys(keys, f"{label} keys")
            verified = _verified_keyids(bom, keys)
            if len(verified) < threshold:
                raise in_toto.exceptions.SwitchVerificationError(
                    f"'{label}' requires at least {threshold} valid"
                    f" signature(s), found {len(verified)}."
                )

        return _normalize_artifacts(payload.materials)

    if isinstance(bom, Link):
        if not allow_unsigned:
            raise in_toto.exceptions.SwitchVerificationError(
                f"'{label}' must be signed metadata, not a bare Link."
            )
        return _normalize_artifacts(bom.materials)

    if isinstance(bom, Mapping):
        if not allow_unsigned:
            raise in_toto.exceptions.SwitchVerificationError(
                f"'{label}' must be signed metadata, not a plain mapping."
            )
        return _normalize_artifacts(bom)

    raise securesystemslib.exceptions.FormatError(
        f"Unsupported '{label}' manifest type."
    )


def _read_mode_marker(mode_marker):  # noqa: PLR0911
    """Read a legacy mode marker for diagnostics only.

    The returned value is recorded in the verdict but never used to decide
    whether artifacts are safe or which concurrent link wins.
    """
    if mode_marker is None:
        return None

    if isinstance(mode_marker, Mapping):
        value = mode_marker.get("mode")
        return str(value) if value is not None else None

    if isinstance(mode_marker, (str, os.PathLike)):
        path = os.fspath(mode_marker)
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf8") as file_object:
                    data = file_object.read().strip()

                try:
                    parsed = json.loads(data)
                    if isinstance(parsed, Mapping):
                        value = parsed.get("mode")
                        return str(value) if value is not None else None
                    return str(parsed)

                except ValueError:
                    return data or None

            except OSError:
                return None

        return path

    return str(mode_marker)


def _canonical_json(value):
    """Deterministic JSON for hashing and sorting."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _replay_digest(elements):
    """Compute a deterministic digest over every verification input."""
    canonical = _canonical_json(elements).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _metadata_dicts(records):
    """Return sorted JSON dictionaries for a list of link records."""
    dicts = [record.metadata.to_dict() for record in records]
    return sorted(dicts, key=_canonical_json)


def _side_of(record, side_keyids):
    """Return True if any signer belongs to the given side's key set."""
    return any(keyid in side_keyids for keyid in record.signers)


def _concurrent_modes(records, fallback_keyids, normal_keyids):
    """Report co-existing mode/side observations per step."""
    observed = {}
    for record in records:
        modes = observed.setdefault(record.payload.name, set())
        modes.update(record.modes)
        if _side_of(record, fallback_keyids):
            modes.add(FALLBACK)
        if _side_of(record, normal_keyids):
            modes.add(NORMAL)

    return {
        step: sorted(modes)
        for step, modes in sorted(observed.items())
        if len(modes) > 1
    }


@dataclass
class SwitchVerdict:
    """Result of offline switch verification.

    ``status`` is ``"release"`` or ``"quarantine"``.  ``to_dict`` produces a
    JSON-serializable audit record that can be replayed and compared.
    """

    status: str
    phase: str
    layout_signoffs: dict[str, list[str]]
    concurrent_modes: dict[str, list[str]] = field(default_factory=dict)
    untrusted_mode_hint: Optional[str] = None
    junction: dict[str, Any] = field(default_factory=dict)
    violations: list[dict[str, Any]] = field(default_factory=list)
    replay_digest: str = ""

    @property
    def is_release(self):
        """Whether the release may ship."""
        return self.status == RELEASE

    @property
    def is_quarantined(self):
        """Whether the release must remain quarantined."""
        return not self.is_release

    def raise_for_status(self):
        """Raise if the verdict is not a release."""
        if self.is_quarantined:
            raise in_toto.exceptions.SwitchVerificationError(
                "Release quarantined: "
                + ", ".join(violation["type"] for violation in self.violations)
            )

    def to_dict(self):
        """Return a JSON-serializable representation of the verdict."""
        return {
            "status": self.status,
            "release": self.is_release,
            "allowed": self.is_release,
            "quarantined": not self.is_release,
            "verdict": self.status,
            "phase": self.phase,
            "layout_signoffs": self.layout_signoffs,
            "concurrent_modes": self.concurrent_modes,
            "untrusted_mode_hint": self.untrusted_mode_hint,
            "junction": self.junction,
            "violations": self.violations,
            "replay_digest": self.replay_digest,
        }

    def __getitem__(self, key):
        """Allow dictionary-style access to verdict fields."""
        return self.to_dict()[key]

    def get(self, key, default=None):
        """Return a verdict field or a default, like a dictionary."""
        return self.to_dict().get(key, default)

    def keys(self):
        """Return verdict field names, like a dictionary."""
        return self.to_dict().keys()


def _violations_from_junction(junction):
    """Build human- and machine-readable junction violations."""
    violations = []

    for path, hashes in sorted(junction["unreviewed"].items()):
        violations.append(
            {
                "type": "unreviewed_cache_residue",
                "path": path,
                "hashes": hashes,
                "consumed": path in junction["consumed"],
            }
        )

    violations.extend(
        [
            {
                "type": "divergent_cache_entry",
                "path": divergence["path"],
                "first_origin": divergence["first_origin"],
                "first_hashes": divergence["first_hashes"],
                "conflicting_origin": divergence["conflicting_origin"],
                "conflicting_hashes": divergence["conflicting_hashes"],
            }
            for divergence in junction["divergences"]
        ]
    )

    return violations


def verify_switch_release(  # noqa: PLR0913
    fallback_layout,
    fallback_layout_keys,
    fallback_links=None,
    normal_layout=None,
    normal_layout_keys=None,
    normal_links=None,
    review_bom=None,
    review_keys=None,
    cache_bom=None,
    cache_keys=None,
    review_threshold=1,
    cache_threshold=1,
    require_distinct_layout_signers=False,
    strict_signoff_attribution=True,
    mode_marker=None,
    allow_unsigned_bom=False,
):
    """Verify a fallback release or a post-recovery normal release offline.

    The function replays signed layout and link metadata.  It does not read
    the network, the clock, file modification times, or a last-written mode
    marker.  All inputs are treated as immutable evidence.

    For a fallback-only release, omit ``normal_layout``.  For the first normal
    release after recovery, pass both layouts.  Normal releases are then
    checked at the junction between fallback products and normal materials:

    * a fallback product still in the cache or consumed by the normal build
      must be covered by ``review_bom`` with the exact same path and hashes,
    * a path observed with conflicting hashes is quarantined,
    * co-existing concurrent links are all evaluated; disagreement is an
      error rather than a last-writer-wins choice.

    Arguments:
      fallback_layout: Metadata containing the signed fallback Layout.
      fallback_layout_keys: Public keys required for the fallback sign-off.
      fallback_links (optional): Link directory, link metadata mapping, or
          sequence for the fallback layout.  Required if the layout has steps.
      normal_layout (optional): Metadata containing the signed normal Layout.
      normal_layout_keys (optional): Public keys required for the normal
          sign-off.  Required with ``normal_layout``.
      normal_links (optional): Link directory, mapping, or sequence for the
          normal layout.  Required if the normal layout has steps.
      review_bom (optional): Signed Metadata containing a Link whose
          ``materials`` list artifacts explicitly approved at the junction.
      review_keys (optional): Public keys for the review manifest.
      cache_bom (optional): Signed Metadata containing a Link whose
          ``materials`` list the cache contents at the junction.  If omitted,
          all fallback products are assumed to remain cached.
      cache_keys (optional): Public keys for the cache manifest.
      review_threshold (optional): Number of valid review signatures needed.
      cache_threshold (optional): Number of valid cache signatures needed.
      require_distinct_layout_signers (optional): Require disjoint layout
          sign-off key sets.
      strict_signoff_attribution (optional): Reject foreign signatures on a
          layout.
      mode_marker (optional): Legacy path/mapping/string recorded for audit
          only.  It never affects the verdict.
      allow_unsigned_bom (optional): Accept an unsigned Link or mapping as a
          BOM.  Intended only for local experiments; never enable it for a
          real release check.

    Raises:
      FormatError: Input metadata or keys are malformed.
      SignatureVerificationError: Layout signatures are missing or invalid.
      ThresholdVerificationError: Link threshold requirements are not met.
      ConcurrentModeError: Co-existing links disagree on artifacts.
      RuleVerificationError: A signed artifact rule fails.
      SwitchVerificationError: A BOM is invalid or sign-off is ambiguous.

    Returns:
      A :class:`SwitchVerdict`.  A junction violation yields
      ``status="quarantine"``; structural verification failures raise.
    """
    if not isinstance(review_threshold, int) or review_threshold < 1:
        raise securesystemslib.exceptions.FormatError(
            "review_threshold must be a positive integer."
        )
    if not isinstance(cache_threshold, int) or cache_threshold < 1:
        raise securesystemslib.exceptions.FormatError(
            "cache_threshold must be a positive integer."
        )

    signoffs = verify_layout_signoffs(
        fallback_layout,
        fallback_layout_keys,
        normal_layout,
        normal_layout_keys,
        require_distinct_signers=require_distinct_layout_signers,
        strict_attribution=strict_signoff_attribution,
    )

    fallback_payload = _as_layout(fallback_layout, FALLBACK)
    fallback_keyids = _keyids(fallback_payload.keys)
    normal_payload = None
    normal_keyids = set()
    if normal_layout is not None:
        normal_payload = _as_layout(normal_layout, NORMAL)
        normal_keyids = _keyids(normal_payload.keys)

    trusted_keys = {}
    trusted_keys.update(fallback_payload.keys)
    if normal_payload is not None:
        trusted_keys.update(normal_payload.keys)

    fallback_records = _records_for_links(
        _coerce_links(fallback_links), trusted_keys, FALLBACK
    )
    _, fallback_reduced = _replay_layout(fallback_payload, fallback_records)

    phase = FALLBACK
    junction = {
        "fallback_products": {},
        "normal_materials": {},
        "cache_entries": {},
        "residue": {},
        "reviewed": {},
        "unreviewed": {},
        "consumed": {},
        "divergences": [],
        "relocated": [],
    }
    normal_records = []
    normal_reduced = {}

    if normal_payload is not None:
        phase = NORMAL
        normal_records = _records_for_links(
            _coerce_links(normal_links), trusted_keys, NORMAL
        )
        _, normal_reduced = _replay_layout(normal_payload, normal_records)

        all_records = fallback_records + normal_records
        concurrent_modes = _concurrent_modes(
            all_records, fallback_keyids, normal_keyids
        )

        # Products from the fallback chain.  Also include fallback-signed or
        # fallback-named links that coexist in the normal link set; this is
        # how a short-lived concurrent fallback job becomes visible even if a
        # mode marker was later overwritten with "normal".
        fallback_steps = set(fallback_payload.get_step_name_list())
        fallback_product_sources = [
            (f"{FALLBACK}:{step}", link.products)
            for step, link in sorted(fallback_reduced.items())
        ]
        fallback_product_sources.extend(
            (f"{FALLBACK}-link:{record.payload.name}", record.payload.products)
            for record in fallback_records
            if _side_of(record, fallback_keyids)
        )
        fallback_product_sources.extend(
            (
                f"{NORMAL}-link-dir:{record.payload.name}",
                record.payload.products,
            )
            for record in normal_records
            if (
                record.payload.name in fallback_steps
                or _side_of(record, fallback_keyids)
            )
        )

        fallback_products, fallback_divergences = _merge_artifacts(
            fallback_product_sources
        )

        normal_steps = set(normal_payload.get_step_name_list())
        normal_material_sources = [
            (f"{NORMAL}:{step}", link.materials)
            for step, link in sorted(normal_reduced.items())
        ]
        normal_material_sources.extend(
            (f"{NORMAL}-link:{record.payload.name}", record.payload.materials)
            for record in normal_records
        )
        normal_material_sources.extend(
            (
                f"{FALLBACK}-link-dir:{record.payload.name}",
                record.payload.materials,
            )
            for record in fallback_records
            if (
                record.payload.name in normal_steps
                or _side_of(record, normal_keyids)
            )
        )

        normal_materials, normal_divergences = _merge_artifacts(
            normal_material_sources
        )

        reviewed = _coerce_bom(
            review_bom,
            review_keys,
            review_threshold,
            "review manifest",
            allow_unsigned_bom,
        )
        cache_entries = (
            None
            if cache_bom is None
            else _coerce_bom(
                cache_bom,
                cache_keys,
                cache_threshold,
                "cache manifest",
                allow_unsigned_bom,
            )
        )

        junction = assess_junction(
            fallback_products,
            normal_materials,
            cache_entries=cache_entries,
            reviewed_materials=reviewed,
        )
        junction["divergences"].extend(fallback_divergences)
        junction["divergences"].extend(normal_divergences)

    else:
        concurrent_modes = _concurrent_modes(
            fallback_records, fallback_keyids, normal_keyids
        )

    violations = _violations_from_junction(junction)
    status = QUARANTINE if violations else RELEASE

    replay_inputs = {
        "fallback_layout": fallback_layout.to_dict(),
        "normal_layout": (
            normal_layout.to_dict() if normal_layout is not None else None
        ),
        "fallback_links": _metadata_dicts(fallback_records),
        "normal_links": _metadata_dicts(normal_records),
        "review_bom": (
            review_bom.to_dict() if isinstance(review_bom, Metadata) else None
        ),
        "cache_bom": (
            cache_bom.to_dict() if isinstance(cache_bom, Metadata) else None
        ),
        "review_threshold": review_threshold,
        "cache_threshold": cache_threshold,
    }

    return SwitchVerdict(
        status=status,
        phase=phase,
        layout_signoffs=signoffs,
        concurrent_modes=concurrent_modes,
        untrusted_mode_hint=_read_mode_marker(mode_marker),
        junction=junction,
        violations=violations,
        replay_digest=_replay_digest(replay_inputs),
    )


# Descriptive aliases for callers that use the wording from the design notes.
verify_offline_switch = verify_switch_release
replay_switch_verification = verify_switch_release
verify_switch = verify_switch_release
