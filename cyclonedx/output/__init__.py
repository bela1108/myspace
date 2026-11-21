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
Set of classes and methods for outputting our libraries internal Bom model to CycloneDX documents in varying formats
and according to different versions of the CycloneDX schema standard.
"""

import os
import sys
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal, Optional, Union, overload

if sys.version_info >= (3, 13):
    from warnings import deprecated
else:
    from typing_extensions import deprecated

from ..contrib.bom.utils import BomRefDiscriminator as _BomRefDiscriminator
from ..downgrade import analyze_downgrade as _analyze_downgrade
from ..downgrade import enforce as _enforce_downgrade
from ..downgrade.report import DowngradeLossReport as _DowngradeLossReport
from ..schema import OutputFormat, SchemaVersion

if TYPE_CHECKING:  # pragma: no cover
    from ..downgrade.policy import BaseDowngradePolicy
    from ..model.bom import Bom
    from .json import Json as JsonOutputter
    from .xml import Xml as XmlOutputter


class BaseOutput(ABC):

    def __init__(self, bom: 'Bom', *,
                 downgrade_policy: Optional['BaseDowngradePolicy'] = None,
                 **kwargs: int) -> None:
        super().__init__(**kwargs)
        self._bom = bom
        self._generated: bool = False
        self._downgrade_policy = downgrade_policy
        self._downgrade_report: Optional[_DowngradeLossReport] = None

    @property
    def downgrade_policy(self) -> Optional['BaseDowngradePolicy']:
        """Policy that decides which downgrade losses abort generation."""
        return self._downgrade_policy

    def set_downgrade_policy(self, policy: Optional['BaseDowngradePolicy']) -> None:
        """Configure which downgrade losses block output after construction."""
        self._downgrade_policy = policy

    @property
    def downgrade_report(self) -> Optional[_DowngradeLossReport]:
        """The loss report computed during the last generate run, if any."""
        return self._downgrade_report

    def get_downgrade_report(self) -> _DowngradeLossReport:
        """Compute (or return the cached) format-agnostic downgrade loss report.

        The BOM is only read, never mutated, so the same instance can still be
        serialized against a newer schema version.
        """
        if self._downgrade_report is None or self._downgrade_report.target_version is not self.schema_version:
            self._downgrade_report = _analyze_downgrade(self._bom, self.schema_version)
        return self._downgrade_report

    def _check_downgrade_policy(self) -> None:
        report = self.get_downgrade_report()
        _enforce_downgrade(self._downgrade_policy, report)

    @property
    @abstractmethod
    def schema_version(self) -> SchemaVersion:
        ...  # pragma: no cover

    @property
    @abstractmethod
    def output_format(self) -> OutputFormat:
        ...  # pragma: no cover

    @property
    def generated(self) -> bool:
        return self._generated

    @generated.setter
    def generated(self, generated: bool) -> None:
        self._generated = generated

    def get_bom(self) -> 'Bom':
        return self._bom

    def set_bom(self, bom: 'Bom') -> None:
        self._bom = bom

    @abstractmethod
    def generate(self, force_regeneration: bool = False) -> None:
        ...  # pragma: no cover

    @abstractmethod
    def output_as_string(self, *,
                         indent: Optional[Union[int, str]] = None,
                         **kwargs: Any) -> str:
        ...  # pragma: no cover

    def output_to_file(self, filename: str, allow_overwrite: bool = False, *,
                       indent: Optional[Union[int, str]] = None,
                       **kwargs: Any) -> None:
        # Check directory writable
        output_filename = os.path.realpath(filename)
        output_directory = os.path.dirname(output_filename)
        if not os.access(output_directory, os.W_OK):
            raise PermissionError(output_directory)
        if os.path.exists(output_filename) and not allow_overwrite:
            raise FileExistsError(output_filename)
        with open(output_filename, mode='wb') as f_out:
            f_out.write(self.output_as_string(indent=indent).encode('utf-8'))


@overload
def make_outputter(bom: 'Bom', output_format: Literal[OutputFormat.JSON],
                   schema_version: SchemaVersion, *,
                   downgrade_policy: Optional['BaseDowngradePolicy'] = None) -> 'JsonOutputter':
    ...  # pragma: no cover


@overload
def make_outputter(bom: 'Bom', output_format: Literal[OutputFormat.XML],
                   schema_version: SchemaVersion, *,
                   downgrade_policy: Optional['BaseDowngradePolicy'] = None) -> 'XmlOutputter':
    ...  # pragma: no cover


@overload
def make_outputter(bom: 'Bom', output_format: OutputFormat,
                   schema_version: SchemaVersion, *,
                   downgrade_policy: Optional['BaseDowngradePolicy'] = None
                   ) -> Union['XmlOutputter', 'JsonOutputter']:
    ...  # pragma: no cover


def make_outputter(bom: 'Bom', output_format: OutputFormat, schema_version: SchemaVersion, *,
                   downgrade_policy: Optional['BaseDowngradePolicy'] = None) -> BaseOutput:
    """
    Helper method to quickly get the correct output class/formatter.

    Pass in your BOM and optionally an output format and schema version (defaults to XML and latest schema version).


    Raises error when no instance could be made.

    :param bom: Bom
    :param output_format: OutputFormat
    :param schema_version: SchemaVersion
    :param downgrade_policy: optional policy that blocks generation when the downgrade
        would lose security information the caller considers unacceptable
    :return: BaseOutput
    """
    if TYPE_CHECKING:  # pragma: no cover
        BY_SCHEMA_VERSION: Mapping[SchemaVersion, type[BaseOutput]]  # noqa:N806
    if OutputFormat.JSON is output_format:
        from .json import BY_SCHEMA_VERSION
    elif OutputFormat.XML is output_format:
        from .xml import BY_SCHEMA_VERSION
    else:
        raise ValueError(f'Unexpected output_format: {output_format!r}')

    klass = BY_SCHEMA_VERSION.get(schema_version, None)
    if klass is None:
        raise ValueError(f'Unknown {output_format.name}/schema_version: {schema_version!r}')
    return klass(bom, downgrade_policy=downgrade_policy)

# region deprecated re-export


@deprecated('Deprecated re-export location - see docstring of "BomRefDiscriminator" for details.')
class BomRefDiscriminator(_BomRefDiscriminator):
    """Deprecated — Alias of :class:`cyclonedx.contrib.bom.utils.BomRefDiscriminator`.

    .. deprecated:: next
        This re-export location is deprecated.
        Use ``from cyclonedx.contrib.bom.utils import BomRefDiscriminator`` instead.
        The exported symbol itself is NOT deprecated — only this import path.
    """
    pass


# endregion deprecated re-export
