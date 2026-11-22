"""Processing pipeline that models the new, merged log source.

The new log source collapses several formerly independent Sigma fields into a
single output field (e.g. every IP address ends up in ``newlog.ip`` and every
file path in ``newlog.path``). The processing items therefore contain both
reversible one-to-one mappings and many-to-one merges. One transformation is
gated by a detection-item condition on purpose so it only runs on a subset of
the rule paths even when the log source matches - this is exactly what the
audit has to make visible.
"""

from sigma.processing.conditions import (
    LogsourceCondition,
    ContainsWildcardCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation


def merged_logsource_pipeline() -> ProcessingPipeline:
    def newlog():
        return [LogsourceCondition(product="newlog")]
    return ProcessingPipeline(
        name="merged_logsource",
        items=[
            ProcessingItem(
                identifier="merge-ip-fields",
                transformation=FieldMappingTransformation({
                    "SourceIp": "newlog.ip",
                    "DestinationIp": "newlog.ip",
                    "ClientIp": "newlog.ip",
                }),
                rule_conditions=newlog(),
            ),
            ProcessingItem(
                identifier="merge-path-fields",
                transformation=FieldMappingTransformation({
                    "Image": "newlog.path",
                    "TargetFilename": "newlog.path",
                }),
                rule_conditions=newlog(),
            ),
            ProcessingItem(
                identifier="rename-user",
                transformation=FieldMappingTransformation({
                    "UserName": "newlog.user"
                }),
                rule_conditions=newlog(),
            ),
            ProcessingItem(
                identifier="fanout-commandline",
                transformation=FieldMappingTransformation({
                    "CommandLine": ["newlog.cmd", "newlog.cmd_raw"]
                }),
                rule_conditions=newlog(),
            ),
            # Conditional transformation: only ComputerName detection items whose
            # value carries a wildcard are normalised. A rule can hold both a
            # wildcard and an exact ComputerName condition, so within the same
            # rule one path is remapped while the other keeps its field name.
            ProcessingItem(
                identifier="conditional-computername-tag",
                transformation=FieldMappingTransformation({
                    "ComputerName": "newlog.host"
                }),
                rule_conditions=newlog(),
                detection_item_conditions=[
                    ContainsWildcardCondition(cond="any"),
                ],
            ),
        ],
    )
