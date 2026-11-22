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
Split succession checking.

When a large component is split into several smaller packages, vulnerability
dispositions that were signed off against the original component do not
automatically transfer to every successor package. This namespace provides the
domain objects and checks needed to answer one question for every successor
package:

* can an existing disposition be carried over as-is,
* is the new responsibility not yet assigned, or
* is the submitted evidence only covering part of the package's materials.

The check operates on three inputs handed in by the caller:

#. the split declarations describing the successor packages,
#. the BOM references that link the declarations to both BOM versions, and
#. the original disposition scope that was signed off before the split.
"""

from .check import (
    ResponsibilitySuccessionMatrix,
    check_split_succession,
    recheck_merge,
)
from .exception import SplitSuccessionException
from .model import (
    DispositionRecord,
    DispositionScope,
    Material,
    MergeDeclaration,
    SplitPackageDeclaration,
    SplitSuccessionStatus,
    SuccessionResult,
)

__all__ = [
    'DispositionRecord',
    'DispositionScope',
    'Material',
    'MergeDeclaration',
    'ResponsibilitySuccessionMatrix',
    'SplitPackageDeclaration',
    'SplitSuccessionException',
    'SplitSuccessionStatus',
    'SuccessionResult',
    'check_split_succession',
    'recheck_merge',
]
