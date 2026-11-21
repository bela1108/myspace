# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


"""
CycloneDX downgrade loss analysis.

The analysis is purely semantic and operates on the in-memory
:class:`~cyclonedx.model.bom.Bom` model only. It never serializes anything and
therefore does not depend on the :class:`~cyclonedx.schema.OutputFormat` -- the
exact same :class:`~cyclonedx.downgrade.report.DowngradeLossReport` is produced
for JSON and XML.

The minimum schema version from which a piece of security information is
emitted mirrors the ``@serializable.view(...)`` declarations on the models, so
the report stays in sync with what the serializers actually write.
"""

from typing import TYPE_CHECKING

from ..model.crypto import CryptoPrimitive, ProtocolPropertiesType
from ..schema import SchemaVersion
from .report import DowngradeLoss, DowngradeLossReport, LossCategory, LossKind

if TYPE_CHECKING:  # pragma: no cover
    from ..model.bom import Bom
    from ..model.component import Component
    from ..model.crypto import CryptoProperties
    from ..model.vulnerability import Vulnerability, VulnerabilityAnalysis


# Minimum schema version that emits a given piece of information.
# Keep aligned with the @serializable.view(...) decorators on the models.
_VULNERABILITIES_MIN_VERSION = SchemaVersion.V1_4
_CRYPTO_PROPERTIES_MIN_VERSION = SchemaVersion.V1_6
_ANALYSIS_TIMESTAMPS_MIN_VERSION = SchemaVersion.V1_5
_WORKAROUND_MIN_VERSION = SchemaVersion.V1_5

# Enum cases that only exist from CycloneDX v1.7 onwards; the serializers
# transparently rewrite them to a generic "other" case for older schemas.
_PROTOCOL_TYPES_SINCE_1_7 = frozenset({
    ProtocolPropertiesType.DTLS,
    ProtocolPropertiesType.EAP_AKA,
    ProtocolPropertiesType.EAP_AKA_PRIME,
    ProtocolPropertiesType.FIVEG_AKA,
    ProtocolPropertiesType.PRINS,
    ProtocolPropertiesType.QUIC,
})


def analyze_downgrade(bom: "Bom", target_version: SchemaVersion) -> DowngradeLossReport:
    """Analyze which security information is lost when downgrading ``bom``.

    The analysis is purely semantic: it walks the in-memory model and never
    serializes it. As a result the returned report is identical regardless of
    whether the BOM is later emitted as JSON or XML.

    :param bom: the in-memory BOM that would be serialized. It is never mutated.
    :param target_version: the CycloneDX schema version to downgrade to.
    :return: a :class:`DowngradeLossReport` describing every detected loss.
    """
    losses: list[DowngradeLoss] = []
    _analyze_components(bom, target_version, losses)
    _analyze_vulnerabilities(bom, target_version, losses)
    return DowngradeLossReport.collect(target_version, losses)


def _component_location(component: "Component") -> str:
    bom_ref = component.bom_ref.value
    return f"components[{bom_ref or component.name}]"


def _vulnerability_location(vulnerability: "Vulnerability") -> str:
    bom_ref = vulnerability.bom_ref.value
    return f"vulnerabilities[{bom_ref or vulnerability.id or "?"}]"


def _analyze_components(bom: "Bom", target: SchemaVersion,
                        losses: list[DowngradeLoss]) -> None:
    seen: set[int] = set()

    def walk(component: "Component") -> None:
        if id(component) in seen:
            return
        seen.add(id(component))
        crypto_properties = component.crypto_properties
        if crypto_properties is not None:
            _analyze_crypto(component, crypto_properties, target, losses)
        for nested in component.components:
            walk(nested)

    root = bom.metadata.component
    if root is not None:
        walk(root)
    for component in bom.components:
        walk(component)


def _analyze_crypto(component: "Component", crypto_properties: "CryptoProperties",
                    target: SchemaVersion, losses: list[DowngradeLoss]) -> None:
    location = _component_location(component)
    if target < _CRYPTO_PROPERTIES_MIN_VERSION:
        asset_type = crypto_properties.asset_type
        label = asset_type.value if asset_type is not None else "untyped"
        losses.append(DowngradeLoss(
            category=LossCategory.CRYPTO_ASSET,
            kind=LossKind.DROPPED,
            source=f"Component.cryptoProperties ({label})",
            introduced_in=_CRYPTO_PROPERTIES_MIN_VERSION,
            location=f"{location}.crypto_properties",
            detail=(
                "Cryptographic asset " + (asset_type.value + " " if asset_type is not None else "")
                + "on component " + repr(component.name) + " is not representable before "
                "CycloneDX v1.6; the entire cryptoProperties block is omitted"
            ),
        ))
        # The whole cryptoProperties block disappears, so finer-grained enum
        # normalizations are moot and would contradict the DROPPED item.
        return
    _analyze_crypto_normalizations(crypto_properties, location, target, losses)


def _analyze_crypto_normalizations(crypto_properties: "CryptoProperties",
                                   location: str, target: SchemaVersion,
                                   losses: list[DowngradeLoss]) -> None:
    algorithm_properties = crypto_properties.algorithm_properties
    if algorithm_properties is not None:
        primitive = algorithm_properties.primitive
        if primitive is CryptoPrimitive.KEY_WRAP and target < SchemaVersion.V1_7:
            losses.append(DowngradeLoss(
                category=LossCategory.CRYPTO_ASSET,
                kind=LossKind.NORMALIZED,
                source="AlgorithmProperties.primitive = key-wrap",
                introduced_in=SchemaVersion.V1_7,
                location=f"{location}.crypto_properties.algorithm_properties.primitive",
                detail=(
                    "Crypto primitive key-wrap was introduced in CycloneDX v1.7; serializing to an "
                    "older schema rewrites it to primitive other, so the exact primitive distinction "
                    "is lost while the algorithm asset itself remains"
                ),
                equivalent="CryptoPrimitive.OTHER (other)",
            ))
    protocol_properties = crypto_properties.protocol_properties
    if protocol_properties is None:
        return
    protocol_type = protocol_properties.type
    if protocol_type is not None and protocol_type in _PROTOCOL_TYPES_SINCE_1_7 \
            and target < SchemaVersion.V1_7:
        losses.append(DowngradeLoss(
            category=LossCategory.CRYPTO_ASSET,
            kind=LossKind.NORMALIZED,
            source=f"ProtocolProperties.type = {protocol_type.value}",
            introduced_in=SchemaVersion.V1_7,
            location=f"{location}.crypto_properties.protocol_properties.type",
            detail=(
                "Protocol type " + repr(protocol_type.value) + " was introduced in CycloneDX v1.7; "
                "serializing to an older schema rewrites it to other, so the concrete protocol type "
                "is lost while the protocol asset itself remains"
            ),
            equivalent="ProtocolPropertiesType.OTHER (other)",
        ))


def _analyze_vulnerabilities(bom: "Bom", target: SchemaVersion,
                             losses: list[DowngradeLoss]) -> None:
    if target < _VULNERABILITIES_MIN_VERSION:
        for vulnerability in bom.vulnerabilities:
            location = _vulnerability_location(vulnerability)
            losses.append(DowngradeLoss(
                category=LossCategory.VULNERABILITY_ANALYSIS,
                kind=LossKind.DROPPED,
                source=f"Vulnerability({vulnerability.id or "no-id"})",
                introduced_in=_VULNERABILITIES_MIN_VERSION,
                location=location,
                detail=(
                    "Native vulnerability support (including its impact analysis and references) was "
                    "introduced in CycloneDX v1.4; the whole vulnerability record is omitted"
                ),
            ))
            if len(vulnerability.references) > 0:
                losses.append(DowngradeLoss(
                    category=LossCategory.REFERENCE,
                    kind=LossKind.DROPPED,
                    source=f"Vulnerability.references x{len(vulnerability.references)}",
                    introduced_in=_VULNERABILITIES_MIN_VERSION,
                    location=f"{location}.references",
                    detail=(
                        "Cross-source vulnerability references that correlate the same finding across "
                        "vulnerability-intelligence sources are not representable before CycloneDX v1.4"
                    ),
                ))
        return
    for vulnerability in bom.vulnerabilities:
        _analyze_vulnerability(vulnerability, target, losses)


def _analyze_vulnerability(vulnerability: "Vulnerability", target: SchemaVersion,
                           losses: list[DowngradeLoss]) -> None:
    location = _vulnerability_location(vulnerability)
    if vulnerability.analysis is not None:
        _analyze_impact_analysis(vulnerability.analysis, location, target, losses)
    if target < _WORKAROUND_MIN_VERSION and vulnerability.workaround is not None:
        losses.append(DowngradeLoss(
            category=LossCategory.VULNERABILITY_ANALYSIS,
            kind=LossKind.DROPPED,
            source="Vulnerability.workaround",
            introduced_in=_WORKAROUND_MIN_VERSION,
            location=f"{location}.workaround",
            detail="Vulnerability workaround is not representable before CycloneDX v1.5 and is omitted",
        ))


def _analyze_impact_analysis(analysis: "VulnerabilityAnalysis", location: str,
                             target: SchemaVersion, losses: list[DowngradeLoss]) -> None:
    analysis_location = f"{location}.analysis"
    if target < _ANALYSIS_TIMESTAMPS_MIN_VERSION:
        if analysis.first_issued is not None:
            losses.append(DowngradeLoss(
                category=LossCategory.VULNERABILITY_ANALYSIS,
                kind=LossKind.DROPPED,
                source="VulnerabilityAnalysis.first_issued",
                introduced_in=_ANALYSIS_TIMESTAMPS_MIN_VERSION,
                location=f"{analysis_location}.first_issued",
                detail=(
                    "Impact-analysis firstIssued timestamp is not representable before CycloneDX "
                    "v1.5 and is omitted; state/justification/responses/detail remain"
                ),
            ))
        if analysis.last_updated is not None:
            losses.append(DowngradeLoss(
                category=LossCategory.VULNERABILITY_ANALYSIS,
                kind=LossKind.DROPPED,
                source="VulnerabilityAnalysis.last_updated",
                introduced_in=_ANALYSIS_TIMESTAMPS_MIN_VERSION,
                location=f"{analysis_location}.last_updated",
                detail=(
                    "Impact-analysis lastUpdated timestamp is not representable before CycloneDX "
                    "v1.5 and is omitted; state/justification/responses/detail remain"
                ),
            ))
