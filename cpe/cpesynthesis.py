#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This file is part of cpe package.

This module implements testimony synthesis of CPE Names for downstream
vulnerability management.

Two (or more) sources, for example a product inventory and a device
measurement, may each report a CPE Name for the same device. One source
can know the exact version while another only confirms the product but
contributes concrete platform attributes. This module merges such
testimonies attribute by attribute:

- When the sources complement each other, the synthesized record adopts
  every attested value and keeps the provenance of each field (which
  sources asserted it).
- When the sources are mutually exclusive on an attribute, the record
  keeps the conflicting values as pending candidates instead of picking
  a winner, so a risk system can precisely point out which conclusion
  needs an additional device record.
"""

from collections import OrderedDict

from .cpe import CPE
from .comp.cpecomp import CPEComponent
from .comp.cpecomp2_3_fs import CPEComponent2_3_FS


#: Logical value of an attribute about which a source makes no claim
VALUE_ANY = CPEComponent2_3_FS.VALUE_ANY

#: Logical value of an attribute that a source marks as not applicable
VALUE_NA = CPEComponent2_3_FS.VALUE_NA

#: Characters that may appear unquoted in a formatted string value
_FS_UNRESERVED = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")


def _fs_quote(value):
    """
    Quote a raw attribute value for use in a CPE 2.3 formatted string.

    :param string value: raw (unquoted) attribute value
    :returns: value with every reserved character escaped
    :rtype: string
    """

    quoted = []
    for char in value:
        if char in _FS_UNRESERVED:
            quoted.append(char)
        else:
            quoted.append("\\{0}".format(char))
    return "".join(quoted)


class Testimony(object):
    """
    A CPE Name reported by a single source about a device.

    The reported name is normalized to the version 2.3 formatted string
    style so testimonies expressed in different CPE versions or styles
    can be synthesized together.
    """

    def __init__(self, source, cpe_str):
        """
        Store a testimony of source "source" expressed as CPE Name.

        :param string source: name of the reporting source
            (e.g. "inventory", "measurement")
        :param string cpe_str: CPE Name reported by the source
        :returns: None
        """

        self.source = source

        cpe = CPE(cpe_str)
        if cpe.VERSION != CPE.VERSION_2_3:
            # Normalize to a common style before synthesizing
            cpe = CPE(cpe.as_fs(), CPE.VERSION_2_3)
        self.cpe = cpe

    def value_of(self, att_name):
        """
        Returns the value this testimony asserts for attribute att_name,
        or the logical value ANY if the source makes no claim about it.

        :param string att_name: attribute name to look up
        :returns: attribute value asserted by this testimony
        :rtype: string
        """

        values = self.cpe.get_attribute_values(att_name)
        if not values:
            return VALUE_ANY
        return values[0]

    def __repr__(self):
        """
        Returns a human-readable representation of the testimony.

        :returns: Representation of testimony as string
        :rtype: string
        """

        return "Testimony({0}, {1})".format(self.source, self.cpe.cpe_str)


class FieldVerdict(object):
    """
    Synthesized conclusion of a single CPE attribute.
    """

    ###############
    #  CONSTANTS  #
    ###############

    #: Two or more sources assert the same value
    AGREED = "agreed"

    #: Exactly one source asserts a value, the rest make no claim
    COMPLEMENTED = "complemented"

    #: Sources assert mutually exclusive values; candidates stay pending
    CONTESTED = "contested"

    #: No source makes any claim about the attribute
    UNINFORMED = "uninformed"

    def __init__(self, attribute, status, value=None,
                 provenance=(), candidates=()):
        """
        Store the verdict of an attribute.

        :param string attribute: attribute name
        :param string status: one of the verdict status constants
        :param string value: adopted value (None when contested)
        :param tuple provenance: names of the sources that asserted
            the adopted value
        :param tuple candidates: tuples (value, sources) kept as pending
            alternatives when the verdict is contested
        :returns: None
        """

        self.attribute = attribute
        self.status = status
        self.value = value
        self.provenance = tuple(provenance)
        self.candidates = tuple(candidates)

    @property
    def needs_device_record(self):
        """
        Returns True if the conclusion of this attribute is contested and
        requires an additional device record to be settled.

        :returns: True if an additional device record is required
        :rtype: boolean
        """

        return self.status == self.CONTESTED

    def __repr__(self):
        """
        Returns a human-readable representation of the verdict.

        :returns: Representation of verdict as string
        :rtype: string
        """

        return "FieldVerdict({0}, {1}, value={2})".format(
            self.attribute, self.status, self.value)


class SynthesisRecord(object):
    """
    Result of synthesizing the testimonies of several sources about the
    same device, with a verdict per CPE attribute.
    """

    ###############
    #  CONSTANTS  #
    ###############

    #: Attributes synthesized, in CPE 2.3 order
    ATTRIBUTES = CPEComponent.CPE_COMP_KEYS_EXTENDED

    ###################
    #  CLASS METHODS  #
    ###################

    @classmethod
    def synthesize(cls, device, testimonies):
        """
        Synthesize the testimonies of two or more sources about the
        device "device" into a single record.

        :param string device: name of the device the testimonies refer to
        :param list testimonies: Testimony objects to merge
        :returns: synthesis record of the device
        :rtype: SynthesisRecord
        :exception: ValueError - less than two testimonies provided
        """

        testimonies = list(testimonies)
        if len(testimonies) < 2:
            errmsg = "At least two testimonies are required to synthesize"
            raise ValueError(errmsg)

        verdicts = OrderedDict()
        for att in cls.ATTRIBUTES:
            # Claims of each source about the attribute, in order;
            # the logical value ANY means the source makes no claim
            claims = OrderedDict()
            for testimony in testimonies:
                value = testimony.value_of(att)
                if value == VALUE_ANY:
                    continue
                claims.setdefault(value, []).append(testimony.source)

            if not claims:
                verdict = FieldVerdict(att, FieldVerdict.UNINFORMED,
                                       value=VALUE_ANY)
            elif len(claims) == 1:
                value, sources = next(iter(claims.items()))
                if len(sources) > 1:
                    status = FieldVerdict.AGREED
                else:
                    status = FieldVerdict.COMPLEMENTED
                verdict = FieldVerdict(att, status, value=value,
                                       provenance=sources)
            else:
                candidates = tuple(
                    (value, tuple(sources))
                    for value, sources in claims.items())
                verdict = FieldVerdict(att, FieldVerdict.CONTESTED,
                                       candidates=candidates)

            verdicts[att] = verdict

        return cls(device, verdicts)

    ####################
    #  OBJECT METHODS  #
    ####################

    def __init__(self, device, verdicts):
        """
        Store a synthesis record of a device.

        :param string device: name of the device
        :param verdicts: attribute verdicts indexed by attribute name
        :returns: None
        """

        self.device = device
        self.verdicts = OrderedDict(verdicts)

    def verdict(self, att_name):
        """
        Returns the verdict of attribute att_name.

        :param string att_name: attribute name to look up
        :returns: verdict of the attribute
        :rtype: FieldVerdict
        :exception: ValueError - invalid attribute name
        """

        if att_name not in self.verdicts:
            errmsg = "Invalid attribute name '{0}'".format(att_name)
            raise ValueError(errmsg)
        return self.verdicts[att_name]

    def pending(self):
        """
        Returns the names of the attributes whose conclusion is contested
        and therefore needs an additional device record to be settled.

        :returns: attribute names with a contested conclusion
        :rtype: list
        """

        return [att for att, verdict in self.verdicts.items()
                if verdict.needs_device_record]

    def as_cpe(self):
        """
        Returns the synthesized CPE Name as a version 2.3 formatted
        string. Adopted values are kept; contested and uninformed
        attributes are emitted as the logical value ANY.

        :returns: synthesized CPE Name as formatted string
        :rtype: string
        """

        fs = ["cpe:2.3"]
        for i in range(0, len(CPEComponent.ordered_comp_parts)):
            att = CPEComponent.ordered_comp_parts[i]
            verdict = self.verdicts[att]

            if (verdict.status == FieldVerdict.CONTESTED or
                    verdict.status == FieldVerdict.UNINFORMED):
                fs.append(VALUE_ANY)
            elif verdict.value == VALUE_NA:
                fs.append(VALUE_NA)
            else:
                fs.append(_fs_quote(verdict.value))

        return CPE._trim(":".join(fs))

    def __repr__(self):
        """
        Returns a human-readable representation of the record.

        :returns: Representation of record as string
        :rtype: string
        """

        return "SynthesisRecord({0}, {1})".format(self.device, self.as_cpe())


def conclusions_needing_device_record(records):
    """
    Inspect the synthesis records of a same-named device and return the
    attribute names whose conclusion is not settled: either contested in
    at least one record, or resolved to different values across records.
    A risk system can use this list to request an additional device
    record for exactly those conclusions.

    :param list records: SynthesisRecord objects of the same device
    :returns: attribute names that need an additional device record
    :rtype: list
    :exception: ValueError - records of different devices provided
    """

    records = list(records)
    if not records:
        return []

    devices = set(record.device for record in records)
    if len(devices) != 1:
        errmsg = "Synthesis records of different devices: {0}".format(
            ", ".join(sorted(devices)))
        raise ValueError(errmsg)

    flagged = []
    for att in SynthesisRecord.ATTRIBUTES:
        verdicts = [record.verdict(att) for record in records]

        if any(verdict.needs_device_record for verdict in verdicts):
            flagged.append(att)
            continue

        resolved = set(
            verdict.value for verdict in verdicts
            if verdict.status in (FieldVerdict.AGREED,
                                  FieldVerdict.COMPLEMENTED))
        if len(resolved) > 1:
            flagged.append(att)

    return flagged


if __name__ == "__main__":
    import doctest
    doctest.testmod()
