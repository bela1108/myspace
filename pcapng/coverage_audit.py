"""
Audit capture coverage boundaries, by provenance.

Two captures taken over the same time window may contain identical
packets while having very different coverage: one may have captured
everything and been filtered at export time, while the other may have
captured only part of the traffic at the source. Packet payloads alone
cannot tell the two apart -- only the declared metadata (interface
filter options, sampling/drop statistics, and the caller-provided
export description) can.

This module audits that declared evidence and records, for every
section and every interface in a pcapng stream:

* the explicit limitations (declared capture/export restrictions),
* the aspects for which nothing was declared,
* the settings that cannot be explained.

Conclusions are derived exclusively from that declared evidence; they
are never inferred from packet content, so a capture whose packets
happen to be identical to another capture's never "inherits" the other
capture's conclusion.
"""

from pcapng import blocks
from pcapng._compat import namedtuple
from pcapng.scanner import FileScanner

#: Conclusion: every coverage-relevant aspect is declared and no
#: limitation was found.
FULL_COVERAGE = "full_coverage"

#: Conclusion: at least one explicit limitation restricts coverage.
LIMITED_COVERAGE = "limited_coverage"

#: Conclusion: evidence is missing or unexplainable, so no statement
#: about coverage can be made.
INSUFFICIENT_EVIDENCE = "insufficient_evidence"

#: Origin of a limitation: the capture source itself (capture filters,
#: packet drops, ...).
ORIGIN_CAPTURE_SOURCE = "capture_source"

#: Origin of a limitation: export-time processing, as described by the
#: caller.
ORIGIN_EXPORT = "export"

#: An explicit, declared restriction of the capture coverage.
Limitation = namedtuple("Limitation", ["origin", "detail"])

#: A coverage-relevant aspect for which no declaration was found.
UndeclaredAspect = namedtuple("UndeclaredAspect", ["aspect", "detail"])

#: A setting that is present but cannot be interpreted.
UnexplainedSetting = namedtuple("UnexplainedSetting", ["setting", "detail"])

#: Known ``if_filter`` type codes (first byte of the option data).
IF_FILTER_TYPE_LIBPCAP = 0
IF_FILTER_TYPE_BPF_BYTECODE = 1


class ExportDescription(object):
    """
    Caller-provided description of export-time processing.

    The pcapng format has no standard way to record whether a file was
    filtered *after* capture (e.g. a full capture later reduced to a
    subset of flows), so this information has to come from the caller.

    :param description:
        Free-form text describing the export-time processing.
    :param limited:
        Whether the export-time processing restricted the coverage
        with respect to what was captured. Pass ``limited=False`` to
        explicitly declare that the export is unfiltered.
    """

    __slots__ = ["description", "limited"]

    def __init__(self, description, limited=True):
        self.description = description
        self.limited = bool(limited)

    def __eq__(self, other):
        return (
            isinstance(other, ExportDescription)
            and self.description == other.description
            and self.limited == other.limited
        )

    def __repr__(self):
        return "ExportDescription({0!r}, limited={1!r})".format(
            self.description, self.limited
        )


class InterfaceCoverage(object):
    """Coverage audit findings for a single interface of a section."""

    __slots__ = [
        "section_index",
        "interface_id",
        "link_type",
        "packet_count",
        "limitations",
        "undeclared",
        "unexplained",
        "conclusion",
    ]

    def __init__(self, section_index, interface_id, link_type, packet_count):
        self.section_index = section_index
        self.interface_id = interface_id
        self.link_type = link_type
        self.packet_count = packet_count
        self.limitations = []
        self.undeclared = []
        self.unexplained = []
        self.conclusion = INSUFFICIENT_EVIDENCE

    def __repr__(self):
        return (
            "<InterfaceCoverage section={0} interface={1} "
            "conclusion={2} limitations={3} undeclared={4} "
            "unexplained={5}>"
        ).format(
            self.section_index,
            self.interface_id,
            self.conclusion,
            len(self.limitations),
            len(self.undeclared),
            len(self.unexplained),
        )


class SectionCoverage(object):
    """Coverage audit findings for a single section."""

    __slots__ = ["index", "interfaces", "unexplained", "conclusion"]

    def __init__(self, index):
        self.index = index
        self.interfaces = {}
        self.unexplained = []
        self.conclusion = INSUFFICIENT_EVIDENCE

    def __repr__(self):
        return "<SectionCoverage index={0} conclusion={1} interfaces={2}>".format(
            self.index, self.conclusion, sorted(self.interfaces)
        )


class CaptureCoverageReport(object):
    """Coverage audit findings for a whole pcapng stream."""

    __slots__ = ["sections", "conclusion"]

    def __init__(self):
        self.sections = []
        self.conclusion = INSUFFICIENT_EVIDENCE

    def __repr__(self):
        return "<CaptureCoverageReport conclusion={0} sections={1}>".format(
            self.conclusion, len(self.sections)
        )


def audit_capture_coverage(stream, export_description=None):
    """
    Audit the capture coverage boundaries of a pcapng stream.

    :param stream:
        a file-like object to read pcapng data from (anything accepted
        by :py:class:`pcapng.FileScanner`).
    :param export_description:
        Optional caller-provided description of export-time processing.
        May be a string or an :py:class:`ExportDescription` (applied to
        every interface), or a dict mapping ``interface_id`` or
        ``(section_index, interface_id)`` keys to strings /
        :py:class:`ExportDescription` values. If omitted, export-time
        filtering is reported as undeclared for every interface.
    :return:
        a :py:class:`CaptureCoverageReport` with conclusions stored per
        section and per interface.
    """

    scanner = FileScanner(stream)
    sections = []
    packet_counts = []

    for block in scanner:
        if isinstance(block, blocks.SectionHeader):
            sections.append(block)
            packet_counts.append({})
        elif isinstance(block, blocks.BasePacketBlock):
            counts = packet_counts[-1]
            interface_id = getattr(block, "interface_id", 0)
            counts[interface_id] = counts.get(interface_id, 0) + 1

    report = CaptureCoverageReport()

    for section_index, section in enumerate(sections):
        section_coverage = SectionCoverage(index=section_index)

        for interface_id, interface in sorted(section.interfaces.items()):
            section_coverage.interfaces[interface_id] = _audit_interface(
                section_index=section_index,
                interface_id=interface_id,
                interface=interface,
                stats=section.interface_stats.get(interface_id),
                export_description=_resolve_export_description(
                    export_description, section_index, interface_id
                ),
                packet_count=packet_counts[section_index].get(interface_id, 0),
            )

        for stats_id in sorted(section.interface_stats):
            if stats_id not in section.interfaces:
                section_coverage.unexplained.append(
                    UnexplainedSetting(
                        "isb_interface_id",
                        "statistics block refers to unknown interface "
                        "id {0}".format(stats_id),
                    )
                )

        section_coverage.conclusion = _combine_conclusions(
            [cov.conclusion for cov in section_coverage.interfaces.values()]
        )
        report.sections.append(section_coverage)

    report.conclusion = _combine_conclusions(
        [sec.conclusion for sec in report.sections]
    )
    return report


def _combine_conclusions(conclusions):
    """
    Combine per-interface (or per-section) conclusions.

    A declared limitation is a fact and wins; missing or unexplainable
    evidence outranks a clean "full coverage" statement.
    """
    conclusions = list(conclusions)
    if not conclusions:
        return INSUFFICIENT_EVIDENCE
    if LIMITED_COVERAGE in conclusions:
        return LIMITED_COVERAGE
    if INSUFFICIENT_EVIDENCE in conclusions:
        return INSUFFICIENT_EVIDENCE
    return FULL_COVERAGE


def _resolve_export_description(export_description, section_index, interface_id):
    if export_description is None:
        return None
    if isinstance(export_description, dict):
        if (section_index, interface_id) in export_description:
            value = export_description[(section_index, interface_id)]
        else:
            value = export_description.get(interface_id)
    else:
        value = export_description
    if value is None:
        return None
    if isinstance(value, ExportDescription):
        return value
    return ExportDescription(str(value), limited=True)


def _audit_interface(
    section_index,
    interface_id,
    interface,
    stats,
    export_description,
    packet_count,
):
    coverage = InterfaceCoverage(
        section_index=section_index,
        interface_id=interface_id,
        link_type=interface.link_type,
        packet_count=packet_count,
    )
    _audit_capture_filter(interface, coverage)
    _audit_sampling_statistics(stats, coverage)
    _audit_export_description(export_description, coverage)
    _audit_unknown_options(interface, coverage)

    if coverage.limitations:
        coverage.conclusion = LIMITED_COVERAGE
    elif coverage.undeclared or coverage.unexplained:
        coverage.conclusion = INSUFFICIENT_EVIDENCE
    else:
        coverage.conclusion = FULL_COVERAGE
    return coverage


def _audit_capture_filter(interface, coverage):
    if "if_filter" not in interface.options:
        coverage.undeclared.append(
            UndeclaredAspect(
                "capture_filter",
                "interface declares no if_filter option; whether traffic "
                "was filtered at the source is unknown",
            )
        )
        return

    filter_type, filter_data = interface.options["if_filter"]
    if filter_type == IF_FILTER_TYPE_LIBPCAP:
        filter_text = filter_data.decode("utf-8", "replace").strip()
        if filter_text:
            coverage.limitations.append(
                Limitation(
                    ORIGIN_CAPTURE_SOURCE,
                    "capture filter (libpcap syntax): {0!r}".format(filter_text),
                )
            )
        # An empty filter string explicitly declares "no filter".
    elif filter_type == IF_FILTER_TYPE_BPF_BYTECODE:
        coverage.limitations.append(
            Limitation(
                ORIGIN_CAPTURE_SOURCE,
                "capture filter (BPF bytecode, {0} bytes)".format(
                    len(filter_data)
                ),
            )
        )
    else:
        coverage.unexplained.append(
            UnexplainedSetting(
                "if_filter",
                "unknown filter type code {0}".format(filter_type),
            )
        )


def _audit_sampling_statistics(stats, coverage):
    if stats is None:
        coverage.undeclared.append(
            UndeclaredAspect(
                "sampling_statistics",
                "no Interface Statistics Block; packet drops and "
                "sampling at the source are unknown",
            )
        )
        return

    options = stats.options
    counters = {}
    for name in (
        "isb_ifrecv",
        "isb_ifdrop",
        "isb_filteraccept",
        "isb_osdrop",
        "isb_usrdeliv",
    ):
        if name in options:
            counters[name] = options[name]

    if not counters:
        coverage.undeclared.append(
            UndeclaredAspect(
                "sampling_statistics",
                "Interface Statistics Block carries no packet counters",
            )
        )
        return

    received = counters.get("isb_ifrecv")
    dropped = counters.get("isb_ifdrop")
    accepted = counters.get("isb_filteraccept")
    os_dropped = counters.get("isb_osdrop")
    delivered = counters.get("isb_usrdeliv")

    if dropped:
        coverage.limitations.append(
            Limitation(
                ORIGIN_CAPTURE_SOURCE,
                "{0} packets dropped by the interface".format(dropped),
            )
        )
    if os_dropped:
        coverage.limitations.append(
            Limitation(
                ORIGIN_CAPTURE_SOURCE,
                "{0} packets dropped by the operating system".format(os_dropped),
            )
        )
    if received is not None and accepted is not None and accepted < received:
        coverage.limitations.append(
            Limitation(
                ORIGIN_CAPTURE_SOURCE,
                "capture filter accepted {0} of {1} received "
                "packets".format(accepted, received),
            )
        )
    if delivered is not None and accepted is not None and delivered < accepted:
        coverage.limitations.append(
            Limitation(
                ORIGIN_CAPTURE_SOURCE,
                "only {0} of {1} filtered packets were delivered to "
                "the capture".format(delivered, accepted),
            )
        )

    if received is not None and dropped is not None and dropped > received:
        coverage.unexplained.append(
            UnexplainedSetting(
                "isb_ifdrop",
                "dropped packets ({0}) exceed received packets "
                "({1})".format(dropped, received),
            )
        )
    if received is not None and accepted is not None and accepted > received:
        coverage.unexplained.append(
            UnexplainedSetting(
                "isb_filteraccept",
                "filter-accepted packets ({0}) exceed received packets "
                "({1})".format(accepted, received),
            )
        )
    if delivered is not None and accepted is not None and delivered > accepted:
        coverage.unexplained.append(
            UnexplainedSetting(
                "isb_usrdeliv",
                "delivered packets ({0}) exceed filter-accepted packets "
                "({1})".format(delivered, accepted),
            )
        )


def _audit_export_description(export_description, coverage):
    if export_description is None:
        coverage.undeclared.append(
            UndeclaredAspect(
                "export_filtering",
                "caller provided no export description; whether the "
                "capture was filtered after recording is unknown",
            )
        )
    elif export_description.limited:
        coverage.limitations.append(
            Limitation(ORIGIN_EXPORT, export_description.description)
        )
    # A non-limited export description explicitly declares "no
    # export-time filtering", so nothing more to record.


def _audit_unknown_options(interface, coverage):
    for key in interface.options:
        if isinstance(key, int):
            coverage.unexplained.append(
                UnexplainedSetting(
                    "if_option_{0}".format(key),
                    "unknown interface option code {0} cannot be "
                    "interpreted".format(key),
                )
            )
