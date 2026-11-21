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
Downgrade loss analysis and release gating.

This package lets a release pipeline inspect what security information would
disappear (or be mapped to a lossy equivalent) when a :class:`~cyclonedx.model.bom.Bom`
that was authored against a recent CycloneDX schema is serialized to an older
schema version. The analysis is format-agnostic, so the very same report is
produced for JSON and XML output::

    from cyclonedx.downgrade import (
        DowngradePolicy,
        LossCategory,
        LossKind,
        analyze_downgrade,
        enforce,
    )

    report = analyze_downgrade(bom, SchemaVersion.V1_4)
    print(report.render_text())

    # callers choose which losses block the release
    policy = DowngradePolicy(blocked_categories={LossCategory.CRYPTO_ASSET})
    enforce(policy, report)  # raises DowngradeRejectedError when blocking

The analyzed BOM is never mutated, so the same instance can still be serialized
against the current/newer schema version.
"""

from .analyzer import analyze_downgrade
from .policy import (
    BaseDowngradePolicy,
    DowngradePolicy,
    DowngradeRejectedError,
    enforce,
)
from .report import (
    DowngradeLoss,
    DowngradeLossReport,
    LossCategory,
    LossKind,
)

__all__ = [
    "BaseDowngradePolicy",
    "DowngradeLoss",
    "DowngradeLossReport",
    "DowngradePolicy",
    "DowngradeRejectedError",
    "LossCategory",
    "LossKind",
    "analyze_downgrade",
    "enforce",
]
