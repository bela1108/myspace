#
# SPDX-License-Identifier: Apache-2.0
r"""
===========
Source maps
===========

A source map lets an upper layer (a code generator, a template engine or a
build system) tell Bandit how the files it actually scanned relate back to
the templates or hand-written sources they were produced from.

Bandit never rewrites a finding.  The real scan evidence (the generated
filename and its ``line_number`` / ``line_range`` / column offsets) is always
preserved.  For every finding the map produces an additional list of
:class:`SourceReference` candidates describing where the scanned code may
live in the original sources.

Three cases are represented explicitly instead of being guessed at:

* a generated range may map to several source locations (one-to-many);
* a finding whose line range crosses a mapping boundary contributes one
  candidate *per overlapping segment*, including any uncovered gap;
* a stale entry whose source file no longer matches is kept and marked
  invalid together with the reason it failed.

The map file is JSON, keyed by the path of the generated file::

    {
      "version": 1,
      "generated_files": {
        "build/out.py": [
          {
            "generated_start": 10,
            "generated_end": 12,
            "source_file": "templates/job.tmpl",
            "source_start": 3,
            "source_end": 5
          },
          {
            "generated_start": 13,
            "generated_end": 13,
            "source_file": "templates/job.tmpl",
            "source_line": 7
          }
        ]
      }
    }

Only line numbers supplied by the map are ever emitted for a source
location.  A range-only source segment is reported with ``source_line`` set
to ``None``; Bandit never invents a unique line number.
"""
import json
import logging
import os

LOG = logging.getLogger(__name__)

MAP_VERSION = 1

# Failure reasons.  They are stable strings so external reports and tests
# can rely on them.
REASON_SOURCE_FILE_MISSING = "source_file_missing"
REASON_SOURCE_RANGE_INVALID = "source_range_out_of_bounds"
REASON_GENERATED_RANGE_INVALID = "generated_range_out_of_bounds"
REASON_MALFORMED_SEGMENT = "malformed_segment"
REASON_NO_MAPPING = "no_mapping"
REASON_UNMAPPED_GAP = "unmapped_generated_gap"


class SourceMapError(Exception):
    """Raised when a source map document cannot be parsed or validated."""


class SourceSegment:
    """A single generated range and its corresponding source range.

    All boundaries are inclusive line numbers.  ``source_end`` may be
    ``None`` for a single-line mapping expressed with ``source_line``.
    """

    def __init__(
        self,
        generated_start,
        generated_end,
        source_file,
        source_start,
        source_end=None,
    ):
        self.generated_start = generated_start
        self.generated_end = generated_end
        self.source_file = source_file
        self.source_start = source_start
        self.source_end = (
            source_end if source_end is not None else source_start
        )

    @property
    def is_point(self):
        return self.source_start == self.source_end

    def as_dict(self):
        data = {
            "generated_start": self.generated_start,
            "generated_end": self.generated_end,
            "source_file": self.source_file,
        }
        if self.is_point:
            data["source_line"] = self.source_start
        else:
            data["source_start"] = self.source_start
            data["source_end"] = self.source_end
        return data

    @classmethod
    def from_dict(cls, data):
        try:
            generated_start = int(data["generated_start"])
            generated_end = int(data["generated_end"])
            source_file = str(data["source_file"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SourceMapError(
                f"segment is missing a required field: {exc}"
            ) from exc

        if "source_line" in data:
            source_start = data["source_line"]
            source_end = None
        else:
            source_start = data.get("source_start")
            source_end = data.get("source_end")

        if source_start is None:
            raise SourceMapError(
                "segment must provide source_line or source_start"
            )

        try:
            source_start = int(source_start)
            if source_end is not None:
                source_end = int(source_end)
        except (TypeError, ValueError) as exc:
            raise SourceMapError(
                f"segment source line numbers must be integers: {exc}"
            ) from exc

        return cls(
            generated_start,
            generated_end,
            source_file,
            source_start,
            source_end,
        )


class SourceReference:
    """A projected location for a finding, or an explicit failure record.

    ``valid`` references carry a concrete (possibly multi-line) source
    location.  Invalid references keep the candidate segment that failed and
    explain why in ``reason`` so nothing is silently dropped.
    """

    def __init__(
        self,
        valid,
        source_file=None,
        source_line=None,
        source_start=None,
        source_end=None,
        reason=None,
        generated_start=None,
        generated_end=None,
    ):
        self.valid = valid
        self.source_file = source_file
        self.source_line = source_line
        self.source_start = source_start
        self.source_end = source_end
        self.reason = reason
        self.generated_start = generated_start
        self.generated_end = generated_end

    def as_dict(self):
        if self.valid:
            data = {
                "status": "mapped",
                "source_file": self.source_file,
                "source_line": self.source_line,
                "source_start": self.source_start,
                "source_end": self.source_end,
            }
            data["generated_start"] = self.generated_start
            data["generated_end"] = self.generated_end
            return data
        return {
            "status": "invalid",
            "source_file": self.source_file,
            "reason": self.reason,
            "generated_start": self.generated_start,
            "generated_end": self.generated_end,
        }


class SourceMap:
    """Source mapping data for a set of generated files."""

    def __init__(self, files=None, verify_files=True):
        # filename -> list of SourceSegment, unsorted until load
        self.files = files or {}
        self.verify_files = verify_files

    @classmethod
    def from_dict(cls, data, verify_files=True):
        if not isinstance(data, dict):
            raise SourceMapError("source map must be a JSON object")

        version = data.get("version", MAP_VERSION)
        if version != MAP_VERSION:
            raise SourceMapError(
                f"unsupported source map version: {version!r}"
            )

        raw_files = data.get("generated_files", {})
        if not isinstance(raw_files, dict):
            raise SourceMapError("'generated_files' must be an object")

        files = {}
        for generated_file, segments in raw_files.items():
            if not isinstance(segments, list):
                raise SourceMapError(
                    f"segments for {generated_file!r} must be a list"
                )
            parsed = [SourceSegment.from_dict(seg) for seg in segments]
            files[str(generated_file)] = parsed

        return cls(files=files, verify_files=verify_files)

    @classmethod
    def load(cls, filename, verify_files=True):
        """Load a source map from a JSON file."""
        try:
            with open(filename, encoding="utf-8") as fh:
                data = json.load(fh)
        except OSError as exc:
            raise SourceMapError(
                f"could not open source map {filename!r}: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise SourceMapError(
                f"source map {filename!r} is not valid JSON: {exc}"
            ) from exc
        return cls.from_dict(data, verify_files=verify_files)

    def as_dict(self):
        return {
            "version": MAP_VERSION,
            "generated_files": {
                generated_file: [seg.as_dict() for seg in segments]
                for generated_file, segments in self.files.items()
            },
        }

    def _candidate_names(self, filename):
        """Return the map keys that may refer to ``filename``.

        Generated paths arrive with a variety of prefixes (``./``, absolute
        paths), so both the raw key and a normalised form are considered.
        """
        names = set()
        normalized = os.path.normpath(filename)
        for key in self.files:
            if key == filename or os.path.normpath(key) == normalized:
                names.add(key)
        return names

    def has_mapping(self, filename):
        return bool(self._candidate_names(filename))

    def _validate_segment(self, segment, line_count):
        if (
            segment.generated_start > segment.generated_end
            or segment.generated_start < 1
            or segment.source_start < 1
            or segment.source_end < segment.source_start
        ):
            return REASON_MALFORMED_SEGMENT

        if line_count is not None and (
            segment.generated_end > line_count
            or segment.generated_start > line_count
        ):
            return REASON_GENERATED_RANGE_INVALID

        if self.verify_files:
            try:
                with open(segment.source_file, encoding="utf-8") as fh:
                    source_line_count = sum(1 for _ in fh)
            except OSError:
                return REASON_SOURCE_FILE_MISSING
            if segment.source_end > source_line_count:
                return REASON_SOURCE_RANGE_INVALID
        return None

    def project(self, filename, lineno, linerange=None, line_count=None):
        """Project a finding back to its source location candidates.

        Every overlapping segment yields a candidate.  A finding that straddles
        a mapping boundary therefore returns one candidate per segment plus,
        when part of its range is uncovered, an explicit unmapped-gap record.
        Findings in a generated file the map knows nothing about get a single
        ``no_mapping`` record.

        :param filename: generated file that was actually scanned
        :param lineno: the finding's real ``line_number``
        :param linerange: the finding's real ``line_range``
        :param line_count: total lines of the scanned file, used for
            boundary validation (optional)
        :return: list of :class:`SourceReference`
        """
        range_lines = list(linerange) if linerange else [lineno]
        range_start = min(range_lines)
        range_end = max(range_lines)

        keys = self._candidate_names(filename)
        if not keys:
            return [
                SourceReference(
                    False,
                    source_file=None,
                    reason=REASON_NO_MAPPING,
                    generated_start=range_start,
                    generated_end=range_end,
                )
            ]

        segments = []
        for key in keys:
            segments.extend(self.files[key])
        segments.sort(key=lambda seg: seg.generated_start)

        references = []
        # rightmost generated line explained by a *valid* segment
        covered_until = range_start - 1
        # rightmost generated line touched by any segment (valid or not)
        touched_until = range_start - 1

        for segment in segments:
            failure = self._validate_segment(segment, line_count)
            if failure is not None:
                # keep the stale/malformed candidate with the generated span
                # it claims, intersected with the finding range where sane
                low = max(min(segment.generated_start,
                              segment.generated_end), range_start)
                high = min(max(segment.generated_start,
                               segment.generated_end), range_end)
                if low > high:
                    continue
                references.append(
                    SourceReference(
                        False,
                        source_file=segment.source_file,
                        reason=failure,
                        generated_start=low,
                        generated_end=high,
                    )
                )
                touched_until = max(touched_until, high)
                continue

            overlap_start = max(segment.generated_start, range_start)
            overlap_end = min(segment.generated_end, range_end)
            if overlap_start > overlap_end:
                continue

            # a gap is only reported between two valid segments; a region
            # merely covered by stale/invalid segments is already explained
            if overlap_start > covered_until + 1:
                references.append(
                    SourceReference(
                        False,
                        source_file=None,
                        reason=REASON_UNMAPPED_GAP,
                        generated_start=covered_until + 1,
                        generated_end=overlap_start - 1,
                    )
                )

            references.append(
                self._project_segment(segment, overlap_start, overlap_end)
            )
            covered_until = max(covered_until, overlap_end)
            touched_until = max(touched_until, overlap_end)

        if covered_until < range_end and touched_until < range_end:
            references.append(
                SourceReference(
                    False,
                    source_file=None,
                    reason=REASON_UNMAPPED_GAP,
                    generated_start=touched_until + 1,
                    generated_end=range_end,
                )
            )

        if not references:
            references.append(
                SourceReference(
                    False,
                    source_file=None,
                    reason=REASON_NO_MAPPING,
                    generated_start=range_start,
                    generated_end=range_end,
                )
            )
        return references

    @staticmethod
    def _project_segment(segment, overlap_start, overlap_end):
        """Translate an overlapping generated range through one segment.

        Line numbers are only carried over when the overlap is a single
        generated line inside a single-line source segment.  Multi-line or
        partial overlaps are returned as ranges with ``source_line=None`` so
        that no unique line number is fabricated.
        """
        if segment.is_point:
            return SourceReference(
                True,
                source_file=segment.source_file,
                source_line=segment.source_start,
                source_start=segment.source_start,
                source_end=segment.source_start,
                generated_start=overlap_start,
                generated_end=overlap_end,
            )

        offset_start = overlap_start - segment.generated_start
        offset_end = overlap_end - segment.generated_start
        source_start = segment.source_start + offset_start
        source_end = segment.source_start + offset_end
        single_line = (
            source_start == source_end
            and overlap_start == overlap_end
        )
        return SourceReference(
            True,
            source_file=segment.source_file,
            source_line=source_start if single_line else None,
            source_start=source_start,
            source_end=source_end,
            generated_start=overlap_start,
            generated_end=overlap_end,
        )
