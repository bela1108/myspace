.. # Licensed under the Apache License, Version 2.0 (the "License");
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

Outputting
==========

Once you have an instance of a :py:mod:`cyclonedx.model.bom.Bom` you can produce output in either **JSON** or **XML**
against any of the supported CycloneDX schema versions.

We provide two helper methods:

* Output to string (for you to do with as you require)
* Output directly to a filename you provide

By default output will be in XML at latest supported schema version - see :py:mod:`cyclonedx.output.LATEST_SUPPORTED_SCHEMA_VERSION`.

Supported CycloneDX Schema Versions
-----------------------------------

This library supports the following schema versions:

* 1.7 (XML, JSON) - the latest supported schema version
* 1.6 (XML, JSON)
* 1.5 (XML, JSON)
* 1.4 (XML, JSON)
* 1.3 (XML, JSON)
* 1.2 (XML, JSON)
* 1.0 (XML) - `(note, 1.1 schema version has no support for JSON)`
* 1.1 (XML) - `(note, 1.1 schema version has no support for JSON)`

Outputting to JSON
------------------

The below example relies on the latest schema version, but sets the output format to JSON. Output is returned
as a ``str``.

.. code-block:: python

    from cyclonedx.output import make_outputter, BaseOutput, OutputFormat, SchemaVersion

    outputter: BaseOutput = make_outputter(bom=bom, output_format=OutputFormat.JSON, schema_version=SchemaVersion.V1_7)
    bom_json: str = outputter.output_as_string()

Alternatively, if the output format and schema version are constants, you can use the predefined format+schema combined outputs:

.. code-block:: python

    from cyclonedx.output.json import JsonV1Dot7

    outputter = JsonV1Dot7(bom=bom)
    bom_json: str = outputter.output_as_string()


Outputting to XML
------------------

The below example relies on the default output format being XML, but overrides the schema version to 1.2. Output is
written to the supplied filename.

.. code-block:: python

    from cyclonedx.output import make_outputter, BaseOutput, OutputFormat, SchemaVersion

    outputter: BaseOutput = make_outputter(bom=bom, output_format=OutputFormat.XML, schema_version=SchemaVersion.V1_2)
    outputter.output_to_file(filename='/tmp/sbom-v1.2.xml')

Alternatively, if the output format and schema version are constants, you can use the predefined format+schema combined outputs:

.. code-block:: python

    from cyclonedx.output.xml import XmlV1Dot2

    outputter = XmlV1Dot2(bom=bom)
    outputter.output_to_file(filename='/tmp/sbom-v1.2.xml')


Downgrade loss report and release gating
----------------------------------------

When a BOM authored against a recent CycloneDX schema is serialized to an older schema version, some security
information can no longer be represented. The :py:mod:`cyclonedx.downgrade` package computes a loss report
*before* the document is generated. The judgment is purely based on the in-memory model, so the exact same report
is produced for JSON and XML output, and the BOM instance itself is never mutated and can still be serialized to
the newest schema version.

Each :py:class:`~cyclonedx.downgrade.DowngradeLoss` is classified by a ``LossCategory`` (vulnerability analysis,
crypto asset or reference) and a ``LossKind``:

* ``DROPPED`` - the information has no representation in the target schema and disappears.
* ``NORMALIZED`` - the information remains through a coarser, lossy equivalent (for example an enum value that only
  exists in newer schemas is rewritten to ``other``); the surviving representation is exposed via ``equivalent``.

Inspect the report without blocking anything:

.. code-block:: python

    from cyclonedx.downgrade import analyze_downgrade
    from cyclonedx.schema import SchemaVersion

    report = analyze_downgrade(bom, SchemaVersion.V1_4)
    print(report.render_text())

Configure which losses abort a release via a :py:class:`~cyclonedx.downgrade.DowngradePolicy`, and pass it to the
outputter. When a configured loss would occur, ``output_as_string`` raises
:py:class:`~cyclonedx.downgrade.DowngradeRejectedError` carrying the full report; otherwise generation proceeds.

.. code-block:: python

    from cyclonedx.downgrade import DowngradePolicy, LossCategory
    from cyclonedx.output import make_outputter, OutputFormat, SchemaVersion

    # block only dropped crypto assets, tolerate everything else
    policy = DowngradePolicy(blocked_categories={LossCategory.CRYPTO_ASSET})
    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_4, downgrade_policy=policy)
    bom_json = outputter.output_as_string()

Convenience presets are available as :py:meth:`DowngradePolicy.report_only`,
:py:meth:`DowngradePolicy.block_dropped` and :py:meth:`DowngradePolicy.block_any`. A report is also always reachable
through ``outputter.get_downgrade_report()`` regardless of whether a policy is configured.
