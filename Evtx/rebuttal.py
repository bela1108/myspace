#!/usr/bin/env python
#    This file is part of python-evtx.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
Offline rebuttal of a documented case claim against raw EVTX material.

The incident summary asserts that a record is only generated *after* a device
withdrawal request.  A reviewer found an EVTX file that may support an earlier
event, while the template version can only be established on one side of the
claim.  This module reduces the narrative claim to a small, finite set of
machine-checkable assertions and evaluates each one strictly:

  - event identity assertions  (Channel / EventID / Provider, see EventSpec)
  - ordering assertions         (one named event must precede / follow another)
  - field assertions            (an EventData/System field has a given value)

Every assertion receives exactly one verdict:

  - ``rebutted``       a concrete, internally consistent record contradicts it
  - ``unconfirmable``  the material needed to decide is absent or unrenderable
  - ``supported``      the surviving material is consistent with the assertion

The distinction is deliberate: a missing or corrupt record can never rebut a
claim, it can only make the claim unconfirmable from the material at hand.

Only the Python standard library and the :mod:`Evtx` package are used, so the
analysis runs fully offline.
"""
from __future__ import absolute_import

import json
import os.path
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import Evtx.Evtx as evtx

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

#: A concrete record contradicts the assertion.
REBUTTED = "rebutted"
#: No contradictory record exists, but the assertion cannot be settled.
UNCONFIRMABLE = "unconfirmable"
#: The available material is consistent with the assertion.
SUPPORTED = "supported"

# Exit codes used by the command line entry point.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_UNCONFIRMABLE = 2
EXIT_REBUTTED = 3


class RebuttalError(Exception):
    """Raised when a claim or template proof cannot be interpreted."""


def localname(tag: str) -> str:
    """Return the local name of a possibly namespace-qualified XML tag."""
    return tag.split("}", 1)[-1]


def event_time(record: Any) -> datetime:
    """
    Return the authoritative event time for a record.

    The record header FILETIME is part of the binary record structure and is
    therefore available even when the rendered XML payload cannot be decoded.
    """
    timestamp = record.timestamp()
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


@dataclass(frozen=True)
class EventSpec:
    """
    A finite event identity: the attributes that name a class of events.

    Any populated attribute must match; attributes left as ``None`` are not
    constrained.  Matching is intentionally limited to stable System-node
    fields so that a claim never hinges on a vendor-specific payload field.
    """

    name: str
    channel: Optional[str] = None
    event_id: Optional[int] = None
    provider: Optional[str] = None

    @staticmethod
    def from_dict(name: str, data: Dict[str, Any]) -> "EventSpec":
        if not isinstance(data, dict):
            raise RebuttalError("event identity %r must be an object" % name)
        try:
            event_id = data.get("event_id")
            if event_id is not None:
                event_id = int(event_id)
            return EventSpec(
                name=name,
                channel=data.get("channel"),
                event_id=event_id,
                provider=data.get("provider"),
            )
        except (TypeError, ValueError) as exc:
            raise RebuttalError("invalid event identity %r: %s" % (name, exc))



@dataclass(frozen=True)
class OrderingRequirement:
    """
    A required chronological relationship between two named event identities.

    ``relation`` is one of ``before`` / ``after``; for ``before`` every event
    named by ``first`` must occur before every event named by ``second``.
    """

    first: str
    relation: str
    second: str

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "OrderingRequirement":
        try:
            relation = data["relation"]
            if relation not in ("before", "after"):
                raise RebuttalError("relation must be 'before' or 'after'")
            return OrderingRequirement(first=data["first"], relation=relation, second=data["second"])
        except KeyError as exc:
            raise RebuttalError("ordering requirement missing field %s" % exc)


@dataclass(frozen=True)
class FieldRequirement:
    """
    A required interpretation of a payload field on a named event identity.

    ``field`` is the ``Name`` attribute of an EventData ``Data`` element, or a
    System child element name.  Supported operators: ``equals``,
    ``not_equals``, ``contains``, ``starts_with``, ``ends_with``, ``exists``
    and ``absent``.
    """

    event: str
    field: str
    op: str
    value: Optional[str] = None

    _OPS = ("equals", "not_equals", "contains", "starts_with", "ends_with", "exists", "absent")

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "FieldRequirement":
        try:
            op = data["op"]
            if op not in FieldRequirement._OPS:
                raise RebuttalError("unsupported field op %r" % op)
            value = data.get("value")
            if op not in ("exists", "absent") and value is None:
                raise RebuttalError("field op %r requires a value" % op)
            return FieldRequirement(event=data["event"], field=data["field"], op=op, value=value)
        except KeyError as exc:
            raise RebuttalError("field requirement missing field %s" % exc)


@dataclass
class CaseClaim:
    """The user-documented claim reduced to finite, checkable assertions."""

    title: str
    events: Dict[str, EventSpec]
    orderings: List[OrderingRequirement] = field(default_factory=list)
    fields: List[FieldRequirement] = field(default_factory=list)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "CaseClaim":
        if "events" not in data or not isinstance(data["events"], dict) or not data["events"]:
            raise RebuttalError("claim must define at least one event identity")
        events = {name: EventSpec.from_dict(name, spec) for name, spec in data["events"].items()}
        orderings = [OrderingRequirement.from_dict(item) for item in data.get("orderings", [])]
        fields = [FieldRequirement.from_dict(item) for item in data.get("fields", [])]
        for requirement in orderings:
            for reference in (requirement.first, requirement.second):
                if reference not in events:
                    raise RebuttalError("ordering references unknown event %r" % reference)
        for requirement in fields:
            if requirement.event not in events:
                raise RebuttalError("field requirement references unknown event %r" % requirement.event)
        return CaseClaim(
            title=data.get("title", "untitled claim"),
            events=events,
            orderings=orderings,
            fields=fields,
        )

    @staticmethod
    def from_file(path: str) -> "CaseClaim":
        with open(path, "r", encoding="utf-8") as handle:
            return CaseClaim.from_dict(json.load(handle))


@dataclass(frozen=True)
class TemplateProof:
    """
    A documented mapping from event identity to authoritative template GUIDs.

    When a template proof covers an event identity, a renderable record whose
    resident template GUID is not one of the authoritative GUIDs contradicts
    that identity rather than merely failing to match it.  Records whose
    template cannot be resolved stay unconfirmable: an unknown template version
    signals incompleteness of the material, not contradiction.
    """

    event_guids: Dict[str, frozenset]

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "TemplateProof":
        raw = data.get("event_template_guids", {})
        if not isinstance(raw, dict):
            raise RebuttalError("template proof field 'event_template_guids' must be an object")
        event_guids = {}
        for event_name, guids in raw.items():
            if not isinstance(guids, list) or not guids:
                raise RebuttalError("template proof for %r must list at least one GUID" % event_name)
            normalized = set()
            for guid in guids:
                if not isinstance(guid, str) or not guid:
                    raise RebuttalError("invalid template GUID for %r" % event_name)
                normalized.add(guid.lower())
            event_guids[event_name] = frozenset(normalized)
        return TemplateProof(event_guids=event_guids)

    @staticmethod
    def from_file(path: str) -> "TemplateProof":
        with open(path, "r", encoding="utf-8") as handle:
            return TemplateProof.from_dict(json.load(handle))

    def covers(self, event_name: str) -> bool:
        return event_name in self.event_guids

    def accepts(self, event_name: str, template_guid: str) -> bool:
        return template_guid.lower() in self.event_guids[event_name]


@dataclass(frozen=True)
class Witness:
    """
    The smallest independently checkable unit of EVTX material.

    A witness is one physical record described by the stable attributes that
    the evaluation relies on.  Records whose binary XML cannot be rendered are
    still collected with ``renderable=False`` so that they can drive an
    ``unconfirmable`` outcome instead of being silently dropped.
    """

    source: str
    chunk_index: int
    record_num: int
    timestamp: datetime
    template_guid: Optional[str]
    renderable: bool
    event_id: Optional[int] = None
    channel: Optional[str] = None
    provider: Optional[str] = None
    fields: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def location(self) -> str:
        return "%s!chunk%d/record%d" % (self.source, self.chunk_index, self.record_num)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "location": self.location(),
            "source": self.source,
            "chunk": self.chunk_index,
            "record": self.record_num,
            "timestamp": self.timestamp.isoformat(),
            "template_guid": self.template_guid,
            "renderable": self.renderable,
            "event_id": self.event_id,
            "channel": self.channel,
            "provider": self.provider,
            "fields": dict(self.fields),
            "error": self.error,
        }


def _extract_fields(root: ET.Element) -> Dict[str, str]:
    """Collect named ``Data`` values plus the direct System child text values."""
    values: Dict[str, str] = {}
    event_data = root.find(EVENT_NS + "EventData")
    if event_data is not None:
        for data_node in event_data.findall(EVENT_NS + "Data"):
            name = data_node.get("Name")
            if name:
                values[name] = data_node.text if data_node.text is not None else ""
    user_data = root.find(EVENT_NS + "UserData")
    if user_data is not None:
        for element in user_data.iter():
            name = element.get("Name")
            if name and element.text:
                values.setdefault(name, element.text)
    system = root.find(EVENT_NS + "System")
    if system is not None:
        for child in system:
            name = localname(child.tag)
            if child.text and name not in values:
                values[name] = child.text
    return values


def scan_log(path: str) -> List[Witness]:
    """
    Parse one EVTX file offline into a list of witnesses.

    Rendering failures are captured on the witness rather than raised, because
    an unrenderable record is precisely the "cannot confirm" condition the
    rebuttal report must distinguish from an actual contradiction.
    """
    source = os.path.basename(path)
    witnesses: List[Witness] = []
    with evtx.Evtx(path) as log:
        for chunk_index, chunk in enumerate(log.chunks()):
            for record in chunk.records():
                template_guid = None
                try:
                    template_guid = str(record.root().template().guid())
                except Exception as exc:  # noqa: BLE001 - template is optional evidence
                    template_error = type(exc).__name__
                else:
                    template_error = None

                timestamp = event_time(record)
                try:
                    document = ET.fromstring(record.xml())
                except Exception as exc:  # noqa: BLE001 - corrupt payload, keep the witness
                    witnesses.append(
                        Witness(
                            source=source,
                            chunk_index=chunk_index,
                            record_num=record.record_num(),
                            timestamp=timestamp,
                            template_guid=template_guid,
                            renderable=False,
                            error=type(exc).__name__,
                        )
                    )
                    continue

                system = document.find(EVENT_NS + "System")
                event_id = None
                if system is not None:
                    eid_node = system.find(EVENT_NS + "EventID")
                    if eid_node is not None and eid_node.text is not None:
                        event_id = int(eid_node.text)
                channel = _system_text(system, "Channel")
                provider = None
                if system is not None:
                    provider_node = system.find(EVENT_NS + "Provider")
                    if provider_node is not None:
                        provider = provider_node.get("Name")

                witnesses.append(
                    Witness(
                        source=source,
                        chunk_index=chunk_index,
                        record_num=record.record_num(),
                        timestamp=timestamp,
                        template_guid=template_guid,
                        renderable=True,
                        event_id=event_id,
                        channel=channel,
                        provider=provider,
                        fields=_extract_fields(document),
                        error=template_error,
                    )
                )
    return witnesses


def _system_text(system: Optional[ET.Element], name: str) -> Optional[str]:
    if system is None:
        return None
    node = system.find(EVENT_NS + name)
    if node is None or node.text is None:
        return None
    return node.text

def _identity_matches(spec, witness):
    """True when a renderable witness carries the claimed event identity."""
    if not witness.renderable:
        return False
    if spec.event_id is not None and witness.event_id != spec.event_id:
        return False
    if spec.channel is not None and witness.channel != spec.channel:
        return False
    if spec.provider is not None and witness.provider != spec.provider:
        return False
    return True


def evaluate_identity(spec, witnesses, proof=None):
    """
    Evaluate one event identity against the scanned material.

    Returns a tuple ``(verdict, evidence, note)`` where ``evidence`` is the
    shortest contradicting witness when the identity is rebutted, otherwise
    the most relevant single witness (or ``None``).
    """
    proof = proof or TemplateProof(event_guids={})
    unresolved = []
    for witness in witnesses:
        if not witness.renderable:
            # An unrenderable record is only treated as relevant when a template
            # proof ties its resident template to this identity; otherwise it
            # cannot be attributed and must not block an absence conclusion.
            if (
                proof.covers(spec.name)
                and witness.template_guid is not None
                and proof.accepts(spec.name, witness.template_guid)
            ):
                unresolved.append((witness, "payload cannot be rendered"))
            continue
        if not _identity_matches(spec, witness):
            continue
        if proof.covers(spec.name):
            if witness.template_guid is None:
                unresolved.append((witness, "template version cannot be resolved"))
                continue
            if not proof.accepts(spec.name, witness.template_guid):
                unresolved.append(
                    (witness, "resident template %s is not an authoritative version" % witness.template_guid)
                )
                continue
        return SUPPORTED, witness, "identity present with an accepted template version"
    if unresolved:
        witness, reason = unresolved[0]
        return UNCONFIRMABLE, witness, "relevant material exists but %s" % reason
    return UNCONFIRMABLE, None, "no record carries the claimed event identity"


def _field_satisfies(requirement, actual):
    if requirement.op == "exists":
        return actual is not None
    if requirement.op == "absent":
        return actual is None
    if actual is None:
        return False
    if requirement.op == "equals":
        return actual == requirement.value
    if requirement.op == "not_equals":
        return actual != requirement.value
    if requirement.op == "contains":
        return requirement.value in actual
    if requirement.op == "starts_with":
        return actual.startswith(requirement.value)
    if requirement.op == "ends_with":
        return actual.endswith(requirement.value)
    raise RebuttalError("unsupported field op %r" % requirement.op)


def evaluate_field(requirement, spec, witnesses, proof=None):
    """
    Evaluate a field interpretation on every record carrying the event identity.

    One record whose field contradicts the required interpretation is enough
    to rebut the claim.  Records that cannot be rendered, or whose template
    version is unresolved under a covering proof, make the result unconfirmable.
    """
    proof = proof or TemplateProof(event_guids={})
    candidate = None
    blocked = 0
    for witness in witnesses:
        if not witness.renderable or not _identity_matches(spec, witness):
            continue
        if proof.covers(spec.name):
            if witness.template_guid is None:
                blocked += 1
                continue
            if not proof.accepts(spec.name, witness.template_guid):
                continue
        candidate = witness
        actual = witness.fields.get(requirement.field)
        if not _field_satisfies(requirement, actual):
            return (
                REBUTTED,
                witness,
                "field %r=%r does not satisfy %s %r"
                % (requirement.field, actual, requirement.op, requirement.value),
            )
    if candidate is not None:
        return SUPPORTED, candidate, "every readable matching record satisfies the field interpretation"
    if blocked:
        return UNCONFIRMABLE, None, "matching records exist but their template version is unresolved"
    return UNCONFIRMABLE, None, "no readable record carries the referenced event identity"


def _matching_witnesses(spec, witnesses, proof=None):
    """Renderable witnesses carrying the identity, filtered by template proof."""
    proof = proof or TemplateProof(event_guids={})
    matches = []
    for witness in witnesses:
        if not witness.renderable or not _identity_matches(spec, witness):
            continue
        if proof.covers(spec.name):
            if witness.template_guid is None or not proof.accepts(spec.name, witness.template_guid):
                continue
        matches.append(witness)
    return matches


def evaluate_ordering(requirement, claim, witnesses, proof=None):
    """
    Evaluate a required chronological relationship.

    For ``before``, the claim requires every ``first`` event to predate every
    ``second`` event.  The shortest contradiction is the single earliest
    ``second`` event that is not preceded by a ``first`` event (or, for
    ``after``, the analogous pair).  Unresolved templates or unrenderable
    records never rebut; they yield an unconfirmable outcome.
    """
    proof = proof or TemplateProof(event_guids={})
    first_spec = claim.events[requirement.first]
    second_spec = claim.events[requirement.second]
    first_witnesses = _matching_witnesses(first_spec, witnesses, proof)
    second_witnesses = _matching_witnesses(second_spec, witnesses, proof)

    if not first_witnesses or not second_witnesses:
        note = "one side of the ordering has no template-confirmed record"
        return UNCONFIRMABLE, None, note

    if requirement.relation == "before":
        earliest_first = min(first_witnesses, key=lambda item: item.timestamp)
        earliest_second = min(second_witnesses, key=lambda item: item.timestamp)
        if earliest_second.timestamp < earliest_first.timestamp:
            return (
                REBUTTED,
                earliest_second,
                "earliest %s at %s predates the earliest %s at %s"
                % (
                    requirement.second,
                    earliest_second.timestamp.isoformat(),
                    requirement.first,
                    earliest_first.timestamp.isoformat(),
                ),
            )
        return SUPPORTED, earliest_second, "every %s event is preceded by a %s event" % (
            requirement.second,
            requirement.first,
        )

    latest_first = max(first_witnesses, key=lambda item: item.timestamp)
    latest_second = max(second_witnesses, key=lambda item: item.timestamp)
    if latest_first.timestamp > latest_second.timestamp:
        return (
            REBUTTED,
            latest_first,
            "latest %s at %s follows the latest %s at %s"
            % (
                requirement.first,
                latest_first.timestamp.isoformat(),
                requirement.second,
                latest_second.timestamp.isoformat(),
            ),
        )
    return SUPPORTED, latest_first, "every %s event follows a %s event" % (requirement.first, requirement.second)


def _finding(kind, name, verdict, witness, note):
    finding = {"kind": kind, "name": name, "verdict": verdict, "note": note}
    finding["evidence"] = witness.as_dict() if witness is not None else None
    return finding


def overall_verdict(findings):
    """Aggregate per-assertion verdicts into one case-level verdict."""
    verdicts = {finding["verdict"] for finding in findings}
    if REBUTTED in verdicts:
        return REBUTTED
    if UNCONFIRMABLE in verdicts:
        return UNCONFIRMABLE
    return SUPPORTED


def evaluate_claim(claim, witnesses, proof=None):
    """
    Evaluate every assertion of a case claim against scanned witnesses.

    The report lists the shortest credible material behind each verdict and
    never promotes an unconfirmable condition into a rebuttal.
    """
    proof = proof or TemplateProof(event_guids={})
    findings = []
    for name, spec in claim.events.items():
        verdict, witness, note = evaluate_identity(spec, witnesses, proof)
        findings.append(_finding("identity", name, verdict, witness, note))
    for requirement in claim.orderings:
        verdict, witness, note = evaluate_ordering(requirement, claim, witnesses, proof)
        label = "%s %s %s" % (requirement.first, requirement.relation, requirement.second)
        findings.append(_finding("ordering", label, verdict, witness, note))
    for requirement in claim.fields:
        spec = claim.events[requirement.event]
        verdict, witness, note = evaluate_field(requirement, spec, witnesses, proof)
        label = "%s.%s %s" % (requirement.event, requirement.field, requirement.op)
        findings.append(_finding("field", label, verdict, witness, note))
    return {
        "title": claim.title,
        "overall": overall_verdict(findings),
        "template_proof_used": bool(proof.event_guids),
        "witness_count": len(witnesses),
        "renderable_count": sum(1 for witness in witnesses if witness.renderable),
        "findings": findings,
    }


def analyze_paths(evtx_paths, claim, proof=None):
    """Scan each EVTX path and evaluate the claim over the combined material."""
    witnesses = []
    sources = []
    for path in evtx_paths:
        witnesses.extend(scan_log(path))
        sources.append(os.path.basename(path))
    report = evaluate_claim(claim, witnesses, proof)
    report["sources"] = sources
    return report


def render_text_report(report):
    """Render a human-readable, grep-friendly rebuttal report."""
    lines = []
    lines.append("Case claim: %s" % report["title"])
    lines.append("Sources: %s" % ", ".join(report.get("sources", ["<in-memory>"])))
    lines.append(
        "Material: %d records (%d renderable); template proof: %s"
        % (
            report["witness_count"],
            report["renderable_count"],
            "applied" if report["template_proof_used"] else "not provided",
        )
    )
    lines.append("Overall verdict: %s" % report["overall"].upper())
    lines.append("")
    for finding in report["findings"]:
        lines.append(
            "[%s] %s %s" % (finding["verdict"].upper(), finding["kind"], finding["name"])
        )
        lines.append("    %s" % finding["note"])
        if finding["evidence"] is not None:
            evidence = finding["evidence"]
            lines.append(
                "    shortest material: %s @ %s (template %s)"
                % (
                    evidence["location"],
                    evidence["timestamp"],
                    evidence["template_guid"] if evidence["template_guid"] else "unresolved",
                )
            )
        else:
            lines.append("    shortest material: none available")
    return "\n".join(lines)

