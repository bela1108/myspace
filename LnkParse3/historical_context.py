"""
Historical environment context resolution.

LNK files frequently store paths with environment variable placeholders
(for example ``C:\\Users\\%USERNAME%\\...``) both in their StringData and in
the EnvironmentVariableDataBlock. Expanding such placeholders against the
environment of the machine doing the forensic examination silently rewrites
the evidence: several unrelated shortcuts then appear to point at the
examiner's own home directory.

This module resolves placeholders exclusively against variable snapshots
captured from the source machine at acquisition time. The live process
environment (``os.environ``) is never consulted, so the interpretation of an
exhibit stays reproducible regardless of where the parser runs.
"""

import re


# Windows variable references are ``%NAME%``. Variable names themselves cannot
# contain a percent sign, so a non-greedy match up to the next percent sign is
# unambiguous.
PLACEHOLDER_PATTERN = re.compile(r"%([^%]+)%")

# Resolution confidence levels, ordered from strongest to weakest.
CERTAINTY_RESOLVED = "resolved"
CERTAINTY_PARTIAL = "partially_resolved"
CERTAINTY_UNRESOLVED = "unresolved"
CERTAINTY_NO_PLACEHOLDERS = "no_placeholders"

# Declared precedence rules when the system and the user snapshot disagree.
PRECEDENCE_SYSTEM_FIRST = "system_first"
PRECEDENCE_USER_FIRST = "user_first"
SUPPORTED_PRECEDENCE = (PRECEDENCE_SYSTEM_FIRST, PRECEDENCE_USER_FIRST)

# Provenance labels recorded for every individual placeholder.
SOURCE_SYSTEM = "system"
SOURCE_USER = "user"
SOURCE_UNRESOLVED = "unresolved"


class HistoricalContext:
    """Resolves variable placeholders using acquisition-time snapshots only.

    Args:
        system_variables: mapping captured from the machine-wide environment
            (typically the registry ``HKLM`` hive / system context).
        user_variables: mapping captured from the user-specific environment
            (typically the ``HKCU`` hive / user profile context).
        precedence: which snapshot wins when both define the same variable
            with different values. ``"system_first"`` (the default) mirrors
            the Windows environment block ordering where machine variables are
            applied before user variables; ``"user_first"`` inverts it.

    The mappings are copied and normalised to uppercase keys because Windows
    environment variable names are case-insensitive. Original casing is
    irrelevant for lookups but the captured *values* are kept verbatim.
    """

    def __init__(
        self, system_variables=None, user_variables=None, precedence=PRECEDENCE_SYSTEM_FIRST
    ):
        if precedence not in SUPPORTED_PRECEDENCE:
            raise ValueError(
                f"Unsupported precedence {precedence!r}, expected one of {SUPPORTED_PRECEDENCE}"
            )

        self.system_variables = self._normalise(system_variables)
        self.user_variables = self._normalise(user_variables)
        self.precedence = precedence

        # Effective merged view, materialised according to the declared rule so
        # that every lookup is explainable and deterministic.
        self._effective = {}
        self._provenance = {}
        # The first mapping inserted wins, because later insertions are skipped.
        if precedence == PRECEDENCE_SYSTEM_FIRST:
            ordered = (
                (SOURCE_SYSTEM, self.system_variables),
                (SOURCE_USER, self.user_variables),
            )
        else:
            ordered = (
                (SOURCE_USER, self.user_variables),
                (SOURCE_SYSTEM, self.system_variables),
            )
        for source, mapping in ordered:
            for name, value in mapping.items():
                if name not in self._effective:
                    self._effective[name] = value
                    self._provenance[name] = source

    @staticmethod
    def _normalise(mapping):
        if not mapping:
            return {}
        return {str(name).upper(): str(value) for name, value in mapping.items()}

    def conflict_report(self):
        """Return every variable defined differently by the two snapshots."""
        conflicts = []
        for name in sorted(set(self.system_variables) & set(self.user_variables)):
            system_value = self.system_variables[name]
            user_value = self.user_variables[name]
            if system_value != user_value:
                conflicts.append(
                    {
                        "variable": name,
                        "system_value": system_value,
                        "user_value": user_value,
                        "selected_source": self._provenance[name],
                        "selected_value": self._effective[name],
                        "precedence": self.precedence,
                    }
                )
        return conflicts

    def resolve(self, raw_text):
        """Resolve a single piece of evidence text.

        Returns a structured record describing the original text, the expanded
        candidate, the confidence level and the provenance of every
        placeholder. When a variable is missing from both snapshots the raw
        placeholder is preserved verbatim and the match is reported as
        unresolved instead of being guessed from the local machine.
        """
        if raw_text is None:
            return None

        placeholders = []
        unresolved = 0

        def _replace(match):
            nonlocal unresolved
            reference = match.group(0)
            name = match.group(1).upper()
            if name in self._effective:
                placeholders.append(
                    {
                        "reference": reference,
                        "variable": name,
                        "value": self._effective[name],
                        "source": self._provenance[name],
                    }
                )
                return self._effective[name]

            unresolved += 1
            placeholders.append(
                {
                    "reference": reference,
                    "variable": name,
                    "value": None,
                    "source": SOURCE_UNRESOLVED,
                }
            )
            return reference

        expanded = PLACEHOLDER_PATTERN.sub(_replace, raw_text)

        if not placeholders:
            certainty = CERTAINTY_NO_PLACEHOLDERS
        elif unresolved == 0:
            certainty = CERTAINTY_RESOLVED
        elif unresolved == len(placeholders):
            certainty = CERTAINTY_UNRESOLVED
        else:
            certainty = CERTAINTY_PARTIAL

        return {
            "raw": raw_text,
            "expanded": expanded,
            "certainty": certainty,
            "placeholders": placeholders,
        }


# StringData fields that may carry environment variable placeholders.
STRING_DATA_FIELDS = (
    ("description", "NAME_STRING"),
    ("relative_path", "RELATIVE_PATH"),
    ("working_directory", "WORKING_DIR"),
    ("command_line_arguments", "COMMAND_LINE_ARGUMENTS"),
    ("icon_location", "ICON_LOCATION"),
)


def build_historical_report(lnk_file, context):
    """Build a full historical-context report for a parsed LNK file.

    Three sections are recorded separately:

    * ``string_data`` - every populated StringData field and its resolution;
    * ``environment_variable_data_block`` - the ANSI and Unicode targets of the
      EnvironmentVariableDataBlock and their resolution;
    * ``candidates`` - the concrete path candidates a consumer would use,
      namely the relative path / command line from StringData and the
      EnvironmentVariableDataBlock targets, each annotated with the context
      actually applied.

    Only snapshots handed in by the caller are used; the live machine
    environment is never read.
    """
    report = {
        "precedence": context.precedence,
        "snapshot_sources": {
            "system": sorted(context.system_variables),
            "user": sorted(context.user_variables),
        },
        "conflicts": context.conflict_report(),
        "string_data": [],
        "environment_variable_data_block": [],
        "candidates": [],
    }

    string_values = lnk_file.string_data.as_dict()
    for field, label in STRING_DATA_FIELDS:
        value = string_values.get(field)
        if value is None:
            continue
        record = context.resolve(value)
        record["field"] = field
        record["structure"] = label
        report["string_data"].append(record)
        if field in ("relative_path", "command_line_arguments", "working_directory"):
            report["candidates"].append(_candidate("StringData", field, record))

    environment_block = _find_environment_block(lnk_file)
    if environment_block is not None:
        for field, label in (
            ("target_ansi", "TARGET_ANSI"),
            ("target_unicode", "TARGET_UNICODE"),
        ):
            value = environment_block[field]
            if not value:
                continue
            record = context.resolve(value)
            record["field"] = field
            record["structure"] = label
            report["environment_variable_data_block"].append(record)
            report["candidates"].append(_candidate("EnvironmentVariableDataBlock", field, record))

    return report


def _candidate(structure, field, record):
    return {
        "source_structure": structure,
        "field": field,
        "raw": record["raw"],
        "expanded": record["expanded"],
        "certainty": record["certainty"],
        "placeholder_sources": [placeholder["source"] for placeholder in record["placeholders"]],
        "placeholders": record["placeholders"],
    }


def _find_environment_block(lnk_file):
    if not getattr(lnk_file, "extras", None):
        return None
    return lnk_file.extras.as_dict().get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK")
