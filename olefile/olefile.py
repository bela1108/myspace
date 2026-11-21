"""
olefile (formerly OleFileIO_PL)

Module to read/write Microsoft OLE2 files (also called Structured Storage or
Microsoft Compound Document File Format), such as Microsoft Office 97-2003
documents, Image Composer and FlashPix files, Outlook messages, ...
This version is compatible with Python 2.7 and 3.5+

Project website: https://www.decalage.info/olefile

olefile is copyright (c) 2005-2023 Philippe Lagadec
(https://www.decalage.info)

olefile is based on the OleFileIO module from the PIL library v1.1.7
See: http://www.pythonware.com/products/pil/index.htm
and http://svn.effbot.org/public/tags/pil-1.1.7/PIL/OleFileIO.py

The Python Imaging Library (PIL) is
Copyright (c) 1997-2009 by Secret Labs AB
Copyright (c) 1995-2009 by Fredrik Lundh

See source code and LICENSE.txt for information on usage and redistribution.
"""

# Since olefile v0.47, only Python 2.7 and 3.5+ are supported
# This import enables print() as a function rather than a keyword
# (main requirement to be compatible with Python 3.x)
# The comment on the line below should be printed on Python 2.5 or older:
from __future__ import print_function   # This version of olefile requires Python 2.7 or 3.5+.


#--- LICENSE ------------------------------------------------------------------

# olefile (formerly OleFileIO_PL) is copyright (c) 2005-2023 Philippe Lagadec
# (https://www.decalage.info)
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# ----------
# PIL License:
#
# olefile is based on source code from the OleFileIO module of the Python
# Imaging Library (PIL) published by Fredrik Lundh under the following license:

# The Python Imaging Library (PIL) is
#    Copyright (c) 1997-2009 by Secret Labs AB
#    Copyright (c) 1995-2009 by Fredrik Lundh
#
# By obtaining, using, and/or copying this software and/or its associated
# documentation, you agree that you have read, understood, and will comply with
# the following terms and conditions:
#
# Permission to use, copy, modify, and distribute this software and its
# associated documentation for any purpose and without fee is hereby granted,
# provided that the above copyright notice appears in all copies, and that both
# that copyright notice and this permission notice appear in supporting
# documentation, and that the name of Secret Labs AB or the author(s) not be used
# in advertising or publicity pertaining to distribution of the software
# without specific, written prior permission.
#
# SECRET LABS AB AND THE AUTHORS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
# SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
# IN NO EVENT SHALL SECRET LABS AB OR THE AUTHORS BE LIABLE FOR ANY SPECIAL,
# INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

__date__    = "2023-12-01"
__version__ = '0.47'
__author__  = "Philippe Lagadec"

__all__ = ['isOleFile', 'OleFileIO', 'OleMetadata', 'enable_logging',
           'MAGIC', 'STGTY_EMPTY',
           'STGTY_STREAM', 'STGTY_STORAGE', 'STGTY_ROOT', 'STGTY_PROPERTY',
           'STGTY_LOCKBYTES', 'MINIMAL_OLEFILE_SIZE',
           'DEFECT_UNSURE', 'DEFECT_POTENTIAL', 'DEFECT_INCORRECT',
           'DEFECT_FATAL', 'DEFAULT_PATH_ENCODING',
           'MAXREGSECT', 'DIFSECT', 'FATSECT', 'ENDOFCHAIN', 'FREESECT',
           'MAXREGSID', 'NOSTREAM', 'UNKNOWN_SIZE', 'WORD_CLSID',
           'OleFileIONotClosed',
           'FormatEvidence', 'FormatEvidenceItem',
           'EVIDENCE_CONSTRAINT', 'EVIDENCE_COMPATIBILITY',
           'EVIDENCE_CONTRADICTION', 'EVIDENCE_INSUFFICIENT',
           'get_format_evidence', 'format_evidence',
           'get_forensic_report', 'get_file_format_evidence',
           'get_format_evidence_report', 'get_evidence_report',
           'analyze_format'
]

import io
import sys
import struct, array, os.path, datetime, logging, warnings, traceback

#=== COMPATIBILITY WORKAROUNDS ================================================

# For Python 3.x, need to redefine long as int:
if str is not bytes:
    long = int

# Need to make sure we use xrange both on Python 2 and 3.x:
try:
    # on Python 2 we need xrange:
    iterrange = xrange
except Exception:
    # no xrange, for Python 3 it was renamed as range:
    iterrange = range

# [PL] workaround to fix an issue with array item size on 64 bits systems:
if array.array('L').itemsize == 4:
    # on 32 bits platforms, long integers in an array are 32 bits:
    UINT32 = 'L'
elif array.array('I').itemsize == 4:
    # on 64 bits platforms, integers in an array are 32 bits:
    UINT32 = 'I'
elif array.array('i').itemsize == 4:
    # On 64 bit Jython, signed integers ('i') are the only way to store our 32
    # bit values in an array in a *somewhat* reasonable way, as the otherwise
    # perfectly suited 'H' (unsigned int, 32 bits) results in a completely
    # unusable behaviour. This is most likely caused by the fact that Java
    # doesn't have unsigned values, and thus Jython's "array" implementation,
    # which is based on "jarray", doesn't have them either.
    # NOTE: to trick Jython into converting the values it would normally
    # interpret as "signed" into "unsigned", a binary-and operation with
    # 0xFFFFFFFF can be used. This way it is possible to use the same comparing
    # operations on all platforms / implementations. The corresponding code
    # lines are flagged with a 'JYTHON-WORKAROUND' tag below.
    UINT32 = 'i'
else:
    raise ValueError('Need to fix a bug with 32 bit arrays, please contact author...')


# [PL] These workarounds were inspired from the Path module
# (see http://www.jorendorff.com/articles/python/path/)
# TODO: remove the use of basestring, as it was removed in Python 3
try:
    basestring
except NameError:
    basestring = str

if sys.version_info[0] < 3:
    # On Python 2.x, the default encoding for path names is UTF-8:
    DEFAULT_PATH_ENCODING = 'utf-8'
else:
    # On Python 3.x, the default encoding for path names is Unicode (None):
    DEFAULT_PATH_ENCODING = None


# === LOGGING =================================================================

def get_logger(name, level=logging.CRITICAL+1):
    """
    Create a suitable logger object for this module.
    The goal is not to change settings of the root logger, to avoid getting
    other modules' logs on the screen.
    If a logger exists with same name, reuse it. (Else it would have duplicate
    handlers and messages would be doubled.)
    The level is set to CRITICAL+1 by default, to avoid any logging.
    """
    # First, test if there is already a logger with the same name, else it
    # will generate duplicate messages (due to duplicate handlers):
    if name in logging.Logger.manager.loggerDict:
        #NOTE: another less intrusive but more "hackish" solution would be to
        # use getLogger then test if its effective level is not default.
        logger = logging.getLogger(name)
        # make sure level is OK:
        logger.setLevel(level)
        return logger
    # get a new logger:
    logger = logging.getLogger(name)
    # only add a NullHandler for this logger, it is up to the application
    # to configure its own logging:
    logger.addHandler(logging.NullHandler())
    logger.setLevel(level)
    return logger


# a global logger object used for debugging:
log = get_logger('olefile')


def enable_logging():
    """
    Enable logging for this module (disabled by default).
    This will set the module-specific logger level to NOTSET, which
    means the main application controls the actual logging level.
    """
    log.setLevel(logging.NOTSET)


#=== CONSTANTS ===============================================================

#: magic bytes that should be at the beginning of every OLE file:
MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'

# [PL]: added constants for Sector IDs (from AAF specifications)
MAXREGSECT = 0xFFFFFFFA #: (-6) maximum SECT
DIFSECT    = 0xFFFFFFFC #: (-4) denotes a DIFAT sector in a FAT
FATSECT    = 0xFFFFFFFD #: (-3) denotes a FAT sector in a FAT
ENDOFCHAIN = 0xFFFFFFFE #: (-2) end of a virtual stream chain
FREESECT   = 0xFFFFFFFF #: (-1) unallocated sector

# [PL]: added constants for Directory Entry IDs (from AAF specifications)
MAXREGSID  = 0xFFFFFFFA #: (-6) maximum directory entry ID
NOSTREAM   = 0xFFFFFFFF #: (-1) unallocated directory entry

# [PL] object types in storage (from AAF specifications)
STGTY_EMPTY     = 0 #: empty directory entry
STGTY_STORAGE   = 1 #: element is a storage object
STGTY_STREAM    = 2 #: element is a stream object
STGTY_LOCKBYTES = 3 #: element is an ILockBytes object
STGTY_PROPERTY  = 4 #: element is an IPropertyStorage object
STGTY_ROOT      = 5 #: element is a root storage

# Unknown size for a stream (used by OleStream):
UNKNOWN_SIZE = 0x7FFFFFFF

#
# --------------------------------------------------------------------
# property types

VT_EMPTY=0; VT_NULL=1; VT_I2=2; VT_I4=3; VT_R4=4; VT_R8=5; VT_CY=6;
VT_DATE=7; VT_BSTR=8; VT_DISPATCH=9; VT_ERROR=10; VT_BOOL=11;
VT_VARIANT=12; VT_UNKNOWN=13; VT_DECIMAL=14; VT_I1=16; VT_UI1=17;
VT_UI2=18; VT_UI4=19; VT_I8=20; VT_UI8=21; VT_INT=22; VT_UINT=23;
VT_VOID=24; VT_HRESULT=25; VT_PTR=26; VT_SAFEARRAY=27; VT_CARRAY=28;
VT_USERDEFINED=29; VT_LPSTR=30; VT_LPWSTR=31; VT_FILETIME=64;
VT_BLOB=65; VT_STREAM=66; VT_STORAGE=67; VT_STREAMED_OBJECT=68;
VT_STORED_OBJECT=69; VT_BLOB_OBJECT=70; VT_CF=71; VT_CLSID=72;
VT_VECTOR=0x1000;

# map property id to name (for debugging purposes)
VT = {}
for keyword, var in list(vars().items()):
    if keyword[:3] == "VT_":
        VT[var] = keyword

#
# --------------------------------------------------------------------
# Some common document types (root.clsid fields)

WORD_CLSID = "00020900-0000-0000-C000-000000000046"
# TODO: check Excel, PPT, ...

# [PL]: Defect levels to classify parsing errors - see OleFileIO._raise_defect()
DEFECT_UNSURE =    10    # a case which looks weird, but not sure it's a defect
DEFECT_POTENTIAL = 20    # a potential defect
DEFECT_INCORRECT = 30    # an error according to specifications, but parsing
                         # can go on
DEFECT_FATAL =     40    # an error which cannot be ignored, parsing is
                         # impossible

# Minimal size of an empty OLE file, with 512-bytes sectors = 1536 bytes
# (this is used in isOleFile and OleFileIO.open)
MINIMAL_OLEFILE_SIZE = 1536

#=== FUNCTIONS ===============================================================

def isOleFile (filename=None, data=None):
    """
    Test if a file is an OLE container (according to the magic bytes in its header).

    .. note::
        This function only checks the first 8 bytes of the file, not the
        rest of the OLE structure.
        If data is provided, it also checks if the file size is above
        the minimal size of an OLE file (1536 bytes).
        If filename is provided with the path of the file on disk, the file is
        open only to read the first 8 bytes, then closed.

    .. versionadded:: 0.16

    :param filename: filename, contents or file-like object of the OLE file (string-like or file-like object)

        - if data is provided, filename is ignored.
        - if filename is a unicode string, it is used as path of the file to open on disk.
        - if filename is a bytes string smaller than 1536 bytes, it is used as path
          of the file to open on disk.
        - [deprecated] if filename is a bytes string longer than 1535 bytes, it is parsed
          as the content of an OLE file in memory. (bytes type only)
          Note that this use case is deprecated and should be replaced by the new data parameter
        - if filename is a file-like object (with read and seek methods),
          it is parsed as-is.
    :type filename: bytes, str, unicode or file-like object

    :param data: bytes string with the contents of the file to be checked, when the file is in memory
                 (added in olefile 0.47)
    :type data: bytes

    :returns: True if OLE, False otherwise.
    :rtype: bool
    """
    header = None
    # first check if data is provided and large enough
    if data is not None:
        if len(data) >= MINIMAL_OLEFILE_SIZE:
            header = data[:len(MAGIC)]
        else:
            # the file is too small, cannot be OLE
            return False
    # check if filename is a string-like or file-like object:
    elif hasattr(filename, 'read') and hasattr(filename, 'seek'):
        # file-like object: use it directly
        header = filename.read(len(MAGIC))
        # just in case, seek back to start of file:
        filename.seek(0)
    elif isinstance(filename, bytes) and len(filename) >= MINIMAL_OLEFILE_SIZE:
        # filename is a bytes string containing the OLE file to be parsed:
        header = filename[:len(MAGIC)]
    else:
        # string-like object: filename of file on disk
        with open(filename, 'rb') as fp:
            header = fp.read(len(MAGIC))
    if header == MAGIC:
        return True
    else:
        return False


if bytes is str:
    # version for Python 2.x
    def i8(c):
        return ord(c)
else:
    # version for Python 3.x
    def i8(c):
        return c if c.__class__ is int else c[0]


def i16(c, o = 0):
    """
    Converts a 2-bytes (16 bits) string to an integer.

    :param c: string containing bytes to convert
    :param o: offset of bytes to convert in string
    """
    return struct.unpack("<H", c[o:o+2])[0]


def i32(c, o = 0):
    """
    Converts a 4-bytes (32 bits) string to an integer.

    :param c: string containing bytes to convert
    :param o: offset of bytes to convert in string
    """
    return struct.unpack("<I", c[o:o+4])[0]


def _clsid(clsid):
    """
    Converts a CLSID to a human-readable string.

    :param clsid: string of length 16.
    """
    assert len(clsid) == 16
    # if clsid is only made of null bytes, return an empty string:
    # (PL: why not simply return the string with zeroes?)
    if not clsid.strip(b"\0"):
        return ""
    return (("%08X-%04X-%04X-%02X%02X-" + "%02X" * 6) %
            ((i32(clsid, 0), i16(clsid, 4), i16(clsid, 6)) +
            tuple(map(i8, clsid[8:16]))))



def filetime2datetime(filetime):
    """
    convert FILETIME (64 bits int) to Python datetime.datetime
    """
    # TODO: manage exception when microseconds is too large
    # inspired from https://code.activestate.com/recipes/511425-filetime-to-datetime/
    _FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
    # log.debug('timedelta days=%d' % (filetime//(10*1000000*3600*24)))
    return _FILETIME_null_date + datetime.timedelta(microseconds=filetime//10)



#=== CLASSES ==================================================================

class OleFileError(IOError):
    """
    Generic base error for this module.
    """
    pass

class NotOleFileError(OleFileError):
    """
    Error raised when the opened file is not an OLE file.
    """
    pass


# --- Format evidence ---------------------------------------------------------

#: Evidence categories used by :class:`FormatEvidence`.
EVIDENCE_CONSTRAINT = 'constraint'
EVIDENCE_COMPATIBILITY = 'compatibility'
EVIDENCE_CONTRADICTION = 'contradiction'
EVIDENCE_INSUFFICIENT = 'insufficient'


class FormatEvidenceItem(dict):
    """
    One observation in a :class:`FormatEvidence` report.

    The item is a mapping (so it can be serialised easily) and its keys are
    also available as attributes.  ``category`` is one of the EVIDENCE_*
    constants.  ``passed`` is true for verified constraints and for
    compatibility clues which are present and usable as clues; it is false for
    violated constraints and for unavailable observations.
    """

    def __init__(self, code, category, status, message, field=None,
                 expected=None, observed=None, source=None,
                 conclusive=False, passed=None, reason=None):
        if passed is None:
            passed = status in ('verified', 'compatible', 'present',
                                'legacy', 'informational')
        dict.__init__(
            self,
            code=code,
            category=category,
            kind=category,
            classification=category,
            strength=("conclusive" if conclusive else
                      "compatibility" if category == EVIDENCE_COMPATIBILITY
                      else "insufficient"),
            status=status,
            message=message,
            field=field,
            expected=expected,
            observed=observed,
            source=source,
            conclusive=bool(conclusive),
            passed=bool(passed),
            ok=bool(passed),
            reason=reason,
        )

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __str__(self):
        return '[%s] %s: %s' % (self['status'], self['code'],
                               self['message'])


class FormatEvidence(dict):
    """
    Read-only, eagerly computed description of the file-format declarations
    found in an OLE2/CFB file.

    A report keeps four kinds of observations apart:

    - ``constraints``: structural rules that were verified.  The complete
      rule set is in ``all_constraints``; failed rules are described in
      ``contradictions``.
    - ``compatibility_clues``: non-binding observations such as directory
      timestamps, minor version and CLSIDs.  They can support a hypothesis but
      cannot prove who saved the file.
    - ``contradictions``: declarations which cannot all be true, for example
      DllVersion 3 paired with 4096-byte sectors.
    - ``insufficient_evidence``: attributes which are absent, zero, or only
      compatibility clues and therefore cannot establish a save generation.

    Attributes may be read either as mapping keys or as object attributes.
    Calling the report returns itself, which makes ``ole.format_evidence`` and
    ``ole.format_evidence()`` equivalent.
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __call__(self):
        return self

    def __str__(self):
        return self.get("summary", dict.__repr__(self))

    def as_dict(self, json_safe=False):
        """
        Return the report as plain dictionaries/lists.

        :param json_safe: convert datetime values to ISO-8601 strings.
        """
        def convert(value):
            if isinstance(value, dict):
                return dict((key, convert(val))
                            for key, val in value.items())
            if isinstance(value, (list, tuple)):
                return [convert(val) for val in value]
            if json_safe and isinstance(value, datetime.datetime):
                return value.isoformat()
            if json_safe and isinstance(value, datetime.timedelta):
                return value.total_seconds()
            return value
        return convert(self)

    to_dict = as_dict

    def to_json(self, **kwargs):
        """Return the report as JSON text with ISO timestamps."""
        import json
        kwargs.setdefault("sort_keys", True)
        return json.dumps(self.as_dict(json_safe=True), **kwargs)

    def dump(self):
        """Print the report in a human-readable form."""
        print(self['summary'])
        for title, key in (
                ('Verified constraints', 'verified_constraints'),
                ('Compatibility clues', 'compatibility_clues'),
                ('Contradictions', 'contradictions'),
                ('Not eligible for provenance', 'ineligible_attributes'),
                ('Unavailable attributes', 'unavailable_attributes')):
            print('\n%s:' % title)
            values = self[key]
            if not values:
                print('- none')
            for value in values:
                if isinstance(value, FormatEvidenceItem):
                    print('- %s' % value)
                else:
                    print('- %s' % value)

class OleMetadata:
    """
    Class to parse and store metadata from standard properties of OLE files.

    Available attributes:
    codepage, title, subject, author, keywords, comments, template,
    last_saved_by, revision_number, total_edit_time, last_printed, create_time,
    last_saved_time, num_pages, num_words, num_chars, thumbnail,
    creating_application, security, codepage_doc, category, presentation_target,
    bytes, lines, paragraphs, slides, notes, hidden_slides, mm_clips,
    scale_crop, heading_pairs, titles_of_parts, manager, company, links_dirty,
    chars_with_spaces, unused, shared_doc, link_base, hlinks, hlinks_changed,
    version, dig_sig, content_type, content_status, language, doc_version

    Note: an attribute is set to None when not present in the properties of the
    OLE file.

    References for SummaryInformation stream:

    - https://msdn.microsoft.com/en-us/library/dd942545.aspx
    - https://msdn.microsoft.com/en-us/library/dd925819%28v=office.12%29.aspx
    - https://msdn.microsoft.com/en-us/library/windows/desktop/aa380376%28v=vs.85%29.aspx
    - https://msdn.microsoft.com/en-us/library/aa372045.aspx
    - http://sedna-soft.de/articles/summary-information-stream/
    - https://poi.apache.org/apidocs/org/apache/poi/hpsf/SummaryInformation.html

    References for DocumentSummaryInformation stream:

    - https://msdn.microsoft.com/en-us/library/dd945671%28v=office.12%29.aspx
    - https://msdn.microsoft.com/en-us/library/windows/desktop/aa380374%28v=vs.85%29.aspx
    - https://poi.apache.org/apidocs/org/apache/poi/hpsf/DocumentSummaryInformation.html

    New in version 0.25
    """

    # attribute names for SummaryInformation stream properties:
    # (ordered by property id, starting at 1)
    SUMMARY_ATTRIBS = ['codepage', 'title', 'subject', 'author', 'keywords', 'comments',
        'template', 'last_saved_by', 'revision_number', 'total_edit_time',
        'last_printed', 'create_time', 'last_saved_time', 'num_pages',
        'num_words', 'num_chars', 'thumbnail', 'creating_application',
        'security']

    # attribute names for DocumentSummaryInformation stream properties:
    # (ordered by property id, starting at 1)
    DOCSUM_ATTRIBS = ['codepage_doc', 'category', 'presentation_target', 'bytes', 'lines', 'paragraphs',
        'slides', 'notes', 'hidden_slides', 'mm_clips',
        'scale_crop', 'heading_pairs', 'titles_of_parts', 'manager',
        'company', 'links_dirty', 'chars_with_spaces', 'unused', 'shared_doc',
        'link_base', 'hlinks', 'hlinks_changed', 'version', 'dig_sig',
        'content_type', 'content_status', 'language', 'doc_version']

    def __init__(self):
        """
        Constructor for OleMetadata
        All attributes are set to None by default
        """
        # properties from SummaryInformation stream
        self.codepage = None
        self.title = None
        self.subject = None
        self.author = None
        self.keywords = None
        self.comments = None
        self.template = None
        self.last_saved_by = None
        self.revision_number = None
        self.total_edit_time = None
        self.last_printed = None
        self.create_time = None
        self.last_saved_time = None
        self.num_pages = None
        self.num_words = None
        self.num_chars = None
        self.thumbnail = None
        self.creating_application = None
        self.security = None
        # properties from DocumentSummaryInformation stream
        self.codepage_doc = None
        self.category = None
        self.presentation_target = None
        self.bytes = None
        self.lines = None
        self.paragraphs = None
        self.slides = None
        self.notes = None
        self.hidden_slides = None
        self.mm_clips = None
        self.scale_crop = None
        self.heading_pairs = None
        self.titles_of_parts = None
        self.manager = None
        self.company = None
        self.links_dirty = None
        self.chars_with_spaces = None
        self.unused = None
        self.shared_doc = None
        self.link_base = None
        self.hlinks = None
        self.hlinks_changed = None
        self.version = None
        self.dig_sig = None
        self.content_type = None
        self.content_status = None
        self.language = None
        self.doc_version = None

    def parse_properties(self, ole_file):
        """
        Parse standard properties of an OLE file, from the streams
        ``\\x05SummaryInformation`` and ``\\x05DocumentSummaryInformation``,
        if present.
        Properties are converted to strings, integers or python datetime objects.
        If a property is not present, its value is set to None.

        :param ole_file: OleFileIO object from which to parse properties
        """
        # first set all attributes to None:
        for attrib in (self.SUMMARY_ATTRIBS + self.DOCSUM_ATTRIBS):
            setattr(self, attrib, None)
        if ole_file.exists("\x05SummaryInformation"):
            # get properties from the stream:
            # (converting timestamps to python datetime, except total_edit_time,
            # which is property #10)
            props = ole_file.getproperties("\x05SummaryInformation",
                                           convert_time=True, no_conversion=[10])
            # store them into this object's attributes:
            for i in range(len(self.SUMMARY_ATTRIBS)):
                # ids for standards properties start at 0x01, until 0x13
                value = props.get(i+1, None)
                setattr(self, self.SUMMARY_ATTRIBS[i], value)
        if ole_file.exists("\x05DocumentSummaryInformation"):
            # get properties from the stream:
            props = ole_file.getproperties("\x05DocumentSummaryInformation",
                                           convert_time=True)
            # store them into this object's attributes:
            for i in range(len(self.DOCSUM_ATTRIBS)):
                # ids for standards properties start at 0x01, until 0x13
                value = props.get(i+1, None)
                setattr(self, self.DOCSUM_ATTRIBS[i], value)

    def dump(self):
        """
        Dump all metadata, for debugging purposes.
        """
        print('Properties from SummaryInformation stream:')
        for prop in self.SUMMARY_ATTRIBS:
            value = getattr(self, prop)
            print('- {}: {}'.format(prop, repr(value)))
        print('Properties from DocumentSummaryInformation stream:')
        for prop in self.DOCSUM_ATTRIBS:
            value = getattr(self, prop)
            print('- {}: {}'.format(prop, repr(value)))

class OleFileIONotClosed(RuntimeWarning):
    """
    Warning type used when OleFileIO is destructed but has open file handle.
    """
    def __init__(self, stack_of_open=None):
        super(OleFileIONotClosed, self).__init__()
        self.stack_of_open = stack_of_open

    def __str__(self):
        msg = 'Deleting OleFileIO instance with open file handle. ' \
              'You should ensure that OleFileIO is never deleted ' \
              'without calling close() first. Consider using '\
              '"with OleFileIO(...) as ole: ...".'
        if self.stack_of_open:
            return ''.join([msg, '\n', 'Stacktrace of open() call:\n'] +
                           self.stack_of_open.format())
        else:
            return msg


# --- OleStream ---------------------------------------------------------------

class OleStream(io.BytesIO):
    """
    OLE2 Stream

    Returns a read-only file object which can be used to read
    the contents of a OLE stream (instance of the BytesIO class).
    To open a stream, use the openstream method in the OleFileIO class.

    This function can be used with either ordinary streams,
    or ministreams, depending on the offset, sectorsize, and
    fat table arguments.

    Attributes:

        - size: actual size of data stream, after it was opened.
    """
    # FIXME: should store the list of sects obtained by following
    # the fat chain, and load new sectors on demand instead of
    # loading it all in one go.

    def __init__(self, fp, sect, size, offset, sectorsize, fat, filesize, olefileio):
        """
        Constructor for OleStream class.

        :param fp: file object, the OLE container or the MiniFAT stream
        :param sect: sector index of first sector in the stream
        :param size: total size of the stream
        :param offset: offset in bytes for the first FAT or MiniFAT sector
        :param sectorsize: size of one sector
        :param fat: array/list of sector indexes (FAT or MiniFAT)
        :param filesize: size of OLE file (for debugging)
        :param olefileio: OleFileIO object containing this stream
        :returns: a BytesIO instance containing the OLE stream
        """
        log.debug('OleStream.__init__:')
        log.debug('  sect=%d (%X), size=%d, offset=%d, sectorsize=%d, len(fat)=%d, fp=%s'
            %(sect,sect,size,offset,sectorsize,len(fat), repr(fp)))
        self.ole = olefileio
        # this check is necessary, otherwise when attempting to open a stream
        # from a closed OleFileIO, a stream of size zero is returned without
        # raising an exception. (see issue #81)
        if self.ole.fp.closed:
            raise OSError('Attempting to open a stream from a closed OLE File')
        # [PL] To detect malformed documents with FAT loops, we compute the
        # expected number of sectors in the stream:
        unknown_size = False
        if size == UNKNOWN_SIZE:
            # this is the case when called from OleFileIO._open(), and stream
            # size is not known in advance (for example when reading the
            # Directory stream). Then we can only guess maximum size:
            size = len(fat)*sectorsize
            # and we keep a record that size was unknown:
            unknown_size = True
            log.debug('  stream with UNKNOWN SIZE')
        nb_sectors = (size + (sectorsize-1)) // sectorsize
        log.debug('nb_sectors = %d' % nb_sectors)
        # This number should (at least) be less than the total number of
        # sectors in the given FAT:
        if nb_sectors > len(fat):
            self.ole._raise_defect(DEFECT_INCORRECT, 'malformed OLE document, stream too large')
        # optimization(?): data is first a list of strings, and join() is called
        # at the end to concatenate all in one string.
        # (this may not be really useful with recent Python versions)
        data = []
        # if size is zero, then first sector index should be ENDOFCHAIN:
        if size == 0 and sect != ENDOFCHAIN:
            log.debug('size == 0 and sect != ENDOFCHAIN:')
            self.ole._raise_defect(DEFECT_INCORRECT, 'incorrect OLE sector index for empty stream')
        # [PL] A fixed-length for loop is used instead of an undefined while
        # loop to avoid DoS attacks:
        for i in range(nb_sectors):
            log.debug('Reading stream sector[%d] = %Xh' % (i, sect))
            # Sector index may be ENDOFCHAIN, but only if size was unknown
            if sect == ENDOFCHAIN:
                if unknown_size:
                    log.debug('Reached ENDOFCHAIN sector for stream with unknown size')
                    break
                else:
                    # else this means that the stream is smaller than declared:
                    log.debug('sect=ENDOFCHAIN before expected size')
                    self.ole._raise_defect(DEFECT_INCORRECT, 'incomplete OLE stream')
            # sector index should be within FAT:
            if sect<0 or sect>=len(fat):
                log.debug('sect=%d (%X) / len(fat)=%d' % (sect, sect, len(fat)))
                log.debug('i=%d / nb_sectors=%d' %(i, nb_sectors))
##                tmp_data = b"".join(data)
##                f = open('test_debug.bin', 'wb')
##                f.write(tmp_data)
##                f.close()
##                log.debug('data read so far: %d bytes' % len(tmp_data))
                self.ole._raise_defect(DEFECT_INCORRECT, 'incorrect OLE FAT, sector index out of range')
                # stop reading here if the exception is ignored:
                break
            # TODO: merge this code with OleFileIO.getsect() ?
            # TODO: check if this works with 4K sectors:
            try:
                fp.seek(offset + sectorsize * sect)
            except Exception:
                log.debug('sect=%d, seek=%d, filesize=%d' %
                    (sect, offset+sectorsize*sect, filesize))
                self.ole._raise_defect(DEFECT_INCORRECT, 'OLE sector index out of range')
                # stop reading here if the exception is ignored:
                break
            sector_data = fp.read(sectorsize)
            # [PL] check if there was enough data:
            # Note: if sector is the last of the file, sometimes it is not a
            # complete sector (of 512 or 4K), so we may read less than
            # sectorsize.
            if len(sector_data)!=sectorsize and sect!=(len(fat)-1):
                log.debug('sect=%d / len(fat)=%d, seek=%d / filesize=%d, len read=%d' %
                    (sect, len(fat), offset+sectorsize*sect, filesize, len(sector_data)))
                log.debug('seek+len(read)=%d' % (offset+sectorsize*sect+len(sector_data)))
                self.ole._raise_defect(DEFECT_INCORRECT, 'incomplete OLE sector')
            data.append(sector_data)
            # jump to next sector in the FAT:
            try:
                sect = fat[sect] & 0xFFFFFFFF  # JYTHON-WORKAROUND
            except IndexError:
                # [PL] if pointer is out of the FAT an exception is raised
                self.ole._raise_defect(DEFECT_INCORRECT, 'incorrect OLE FAT, sector index out of range')
                # stop reading here if the exception is ignored:
                break
        # [PL] Last sector should be a "end of chain" marker:
        # if sect != ENDOFCHAIN:
        #     raise IOError('incorrect last sector index in OLE stream')
        data = b"".join(data)
        # Data is truncated to the actual stream size:
        if len(data) >= size:
            log.debug('Read data of length %d, truncated to stream size %d' % (len(data), size))
            data = data[:size]
            # actual stream size is stored for future use:
            self.size = size
        elif unknown_size:
            # actual stream size was not known, now we know the size of read
            # data:
            log.debug('Read data of length %d, the stream size was unknown' % len(data))
            self.size = len(data)
        else:
            # read data is less than expected:
            log.debug('Read data of length %d, less than expected stream size %d' % (len(data), size))
            # TODO: provide details in exception message
            self.size = len(data)
            self.ole._raise_defect(DEFECT_INCORRECT, 'OLE stream size is less than declared')
        # when all data is read in memory, BytesIO constructor is called
        io.BytesIO.__init__(self, data)
        # Then the OleStream object can be used as a read-only file object.


# --- OleDirectoryEntry -------------------------------------------------------

class OleDirectoryEntry:
    """
    OLE2 Directory Entry pointing to a stream or a storage
    """
    # struct to parse directory entries:
    # <: little-endian byte order, standard sizes
    #    (note: this should guarantee that Q returns a 64 bits int)
    # 64s: string containing entry name in unicode UTF-16 (max 31 chars) + null char = 64 bytes
    # H: uint16, number of bytes used in name buffer, including null = (len+1)*2
    # B: uint8, dir entry type (between 0 and 5)
    # B: uint8, color: 0=black, 1=red
    # I: uint32, index of left child node in the red-black tree, NOSTREAM if none
    # I: uint32, index of right child node in the red-black tree, NOSTREAM if none
    # I: uint32, index of child root node if it is a storage, else NOSTREAM
    # 16s: CLSID, unique identifier (only used if it is a storage)
    # I: uint32, user flags
    # Q (was 8s): uint64, creation timestamp or zero
    # Q (was 8s): uint64, modification timestamp or zero
    # I: uint32, SID of first sector if stream or ministream, SID of 1st sector
    #    of stream containing ministreams if root entry, 0 otherwise
    # I: uint32, total stream size in bytes if stream (low 32 bits), 0 otherwise
    # I: uint32, total stream size in bytes if stream (high 32 bits), 0 otherwise
    STRUCT_DIRENTRY = '<64sHBBIII16sIQQIII'
    # size of a directory entry: 128 bytes
    DIRENTRY_SIZE = 128
    assert struct.calcsize(STRUCT_DIRENTRY) == DIRENTRY_SIZE

    def __init__(self, entry, sid, ole_file):
        """
        Constructor for an OleDirectoryEntry object.
        Parses a 128-bytes entry from the OLE Directory stream.

        :param bytes entry: bytes string (must be 128 bytes long)
        :param int sid: index of this directory entry in the OLE file directory
        :param OleFileIO ole_file: OleFileIO object containing this directory entry
        """
        self.sid = sid
        # ref to ole_file is stored for future use
        self.olefile = ole_file
        # kids is a list of children entries, if this entry is a storage:
        # (list of OleDirectoryEntry objects)
        self.kids = []
        # kids_dict is a dictionary of children entries, indexed by their
        # name in lowercase: used to quickly find an entry, and to detect
        # duplicates
        self.kids_dict = {}
        # flag used to detect if the entry is referenced more than once in
        # directory:
        self.used = False
        # decode DirEntry
        (
            self.name_raw, # 64s: string containing entry name in unicode UTF-16 (max 31 chars) + null char = 64 bytes
            self.namelength, # H: uint16, number of bytes used in name buffer, including null = (len+1)*2
            self.entry_type,
            self.color,
            self.sid_left,
            self.sid_right,
            self.sid_child,
            clsid,
            self.dwUserFlags,
            self.createTime,
            self.modifyTime,
            self.isectStart,
            self.sizeLow,
            self.sizeHigh
        ) = struct.unpack(OleDirectoryEntry.STRUCT_DIRENTRY, entry)
        if self.entry_type not in [STGTY_ROOT, STGTY_STORAGE, STGTY_STREAM, STGTY_EMPTY]:
            ole_file._raise_defect(DEFECT_INCORRECT, 'unhandled OLE storage type')
        # only first directory entry can (and should) be root:
        if self.entry_type == STGTY_ROOT and sid != 0:
            ole_file._raise_defect(DEFECT_INCORRECT, 'duplicate OLE root entry')
        if sid == 0 and self.entry_type != STGTY_ROOT:
            ole_file._raise_defect(DEFECT_INCORRECT, 'incorrect OLE root entry')
        # log.debug(struct.unpack(fmt_entry, entry[:len_entry]))
        # name should be at most 31 unicode characters + null character,
        # so 64 bytes in total (31*2 + 2):
        if self.namelength > 64:
            ole_file._raise_defect(DEFECT_INCORRECT, 'incorrect DirEntry name length >64 bytes')
            # if exception not raised, namelength is set to the maximum value:
            self.namelength = 64
        # only characters without ending null char are kept:
        self.name_utf16 = self.name_raw[:(self.namelength-2)]
        # TODO: check if the name is actually followed by a null unicode character ([MS-CFB] 2.6.1)
        # TODO: check if the name does not contain forbidden characters:
        # [MS-CFB] 2.6.1: "The following characters are illegal and MUST NOT be part of the name: '/', '\', ':', '!'."
        # name is converted from UTF-16LE to the path encoding specified in the OleFileIO:
        self.name = ole_file._decode_utf16_str(self.name_utf16)

        log.debug('DirEntry SID=%d: %s' % (self.sid, repr(self.name)))
        log.debug(' - type: %d' % self.entry_type)
        log.debug(' - sect: %Xh' % self.isectStart)
        log.debug(' - SID left: %d, right: %d, child: %d' % (self.sid_left,
            self.sid_right, self.sid_child))

        # sizeHigh is only used for 4K sectors, it should be zero for 512 bytes
        # sectors, BUT apparently some implementations set it as 0xFFFFFFFF, 1
        # or some other value so it cannot be raised as a defect in general:
        if ole_file.sectorsize == 512:
            if self.sizeHigh != 0 and self.sizeHigh != 0xFFFFFFFF:
                log.debug('sectorsize=%d, sizeLow=%d, sizeHigh=%d (%X)' %
                          (ole_file.sectorsize, self.sizeLow, self.sizeHigh, self.sizeHigh))
                ole_file._raise_defect(DEFECT_UNSURE, 'incorrect OLE stream size')
            self.size = self.sizeLow
        else:
            self.size = self.sizeLow + (long(self.sizeHigh)<<32)
        log.debug(' - size: %d (sizeLow=%d, sizeHigh=%d)' % (self.size, self.sizeLow, self.sizeHigh))

        self.clsid = _clsid(clsid)
        # a storage should have a null size, BUT some implementations such as
        # Word 8 for Mac seem to allow non-null values => Potential defect:
        if self.entry_type == STGTY_STORAGE and self.size != 0:
            ole_file._raise_defect(DEFECT_POTENTIAL, 'OLE storage with size>0')
        # check if stream is not already referenced elsewhere:
        self.is_minifat = False
        if self.entry_type in (STGTY_ROOT, STGTY_STREAM) and self.size>0:
            if self.size < ole_file.minisectorcutoff \
            and self.entry_type==STGTY_STREAM: # only streams can be in MiniFAT
                # ministream object
                self.is_minifat = True
            else:
                self.is_minifat = False
            ole_file._check_duplicate_stream(self.isectStart, self.is_minifat)
        self.sect_chain = None

    def build_sect_chain(self, ole_file):
        """
        Build the sector chain for a stream (from the FAT or the MiniFAT)

        :param OleFileIO ole_file: OleFileIO object containing this directory entry
        :return: nothing
        """
        # TODO: seems to be used only from _write_mini_stream, is it useful?
        # TODO: use self.olefile instead of ole_file
        if self.sect_chain:
            return
        if self.entry_type not in (STGTY_ROOT, STGTY_STREAM) or self.size == 0:
            return

        self.sect_chain = list()

        if self.is_minifat and not ole_file.minifat:
            ole_file.loadminifat()

        next_sect = self.isectStart
        while next_sect != ENDOFCHAIN:
            self.sect_chain.append(next_sect)
            if self.is_minifat:
                next_sect = ole_file.minifat[next_sect]
            else:
                next_sect = ole_file.fat[next_sect]

    def build_storage_tree(self):
        """
        Read and build the red-black tree attached to this OleDirectoryEntry
        object, if it is a storage.
        Note that this method builds a tree of all subentries, so it should
        only be called for the root object once.
        """
        log.debug('build_storage_tree: SID=%d - %s - sid_child=%d'
            % (self.sid, repr(self.name), self.sid_child))
        if self.sid_child != NOSTREAM:
            # if child SID is not NOSTREAM, then this entry is a storage.
            # Let's walk through the tree of children to fill the kids list:
            self.append_kids(self.sid_child)

            # Note from OpenOffice documentation: the safest way is to
            # recreate the tree because some implementations may store broken
            # red-black trees...

            # in the OLE file, entries are sorted on (length, name).
            # for convenience, we sort them on name instead:
            # (see rich comparison methods in this class)
            self.kids.sort()

    def append_kids(self, child_sid):
        """
        Walk through red-black tree of children of this directory entry to add
        all of them to the kids list. (recursive method)

        :param child_sid: index of child directory entry to use, or None when called
            first time for the root. (only used during recursion)
        """
        log.debug('append_kids: child_sid=%d' % child_sid)
        # [PL] this method was added to use simple recursion instead of a complex
        # algorithm.
        # if this is not a storage or a leaf of the tree, nothing to do:
        if child_sid == NOSTREAM:
            return
        # check if child SID is in the proper range:
        if child_sid<0 or child_sid>=len(self.olefile.direntries):
            self.olefile._raise_defect(DEFECT_INCORRECT, 'OLE DirEntry index out of range')
        else:
            # get child direntry:
            child = self.olefile._load_direntry(child_sid) #direntries[child_sid]
            log.debug('append_kids: child_sid=%d - %s - sid_left=%d, sid_right=%d, sid_child=%d'
                % (child.sid, repr(child.name), child.sid_left, child.sid_right, child.sid_child))
            # Check if kid was not already referenced in a storage:
            if child.used:
                self.olefile._raise_defect(DEFECT_INCORRECT,
                    'OLE Entry referenced more than once')
                return
            child.used = True
            # the directory entries are organized as a red-black tree.
            # (cf. Wikipedia for details)
            # First walk through left side of the tree:
            self.append_kids(child.sid_left)
            # Check if its name is not already used (case-insensitive):
            name_lower = child.name.lower()
            if name_lower in self.kids_dict:
                self.olefile._raise_defect(DEFECT_INCORRECT,
                    "Duplicate filename in OLE storage")
            # Then the child_sid OleDirectoryEntry object is appended to the
            # kids list and dictionary:
            self.kids.append(child)
            self.kids_dict[name_lower] = child
            # Finally walk through right side of the tree:
            self.append_kids(child.sid_right)
            # Afterwards build kid's own tree if it's also a storage:
            child.build_storage_tree()

    def __eq__(self, other):
        "Compare entries by name"
        return self.name == other.name

    def __lt__(self, other):
        "Compare entries by name"
        return self.name < other.name

    def __ne__(self, other):
        return not self.__eq__(other)

    def __le__(self, other):
        return self.__eq__(other) or self.__lt__(other)

    # Reflected __lt__() and __le__() will be used for __gt__() and __ge__()

    # TODO: replace by the same function as MS implementation ?
    # (order by name length first, then case-insensitive order)

    def dump(self, tab = 0):
        "Dump this entry, and all its subentries (for debug purposes only)"
        TYPES = ["(invalid)", "(storage)", "(stream)", "(lockbytes)",
                 "(property)", "(root)"]
        try:
            type_name = TYPES[self.entry_type]
        except IndexError:
            type_name = '(UNKNOWN)'
        print(" "*tab + repr(self.name), type_name, end=' ')
        if self.entry_type in (STGTY_STREAM, STGTY_ROOT):
            print(self.size, "bytes", end=' ')
        print()
        if self.entry_type in (STGTY_STORAGE, STGTY_ROOT) and self.clsid:
            print(" "*tab + "{%s}" % self.clsid)

        for kid in self.kids:
            kid.dump(tab + 2)

    def getmtime(self):
        """
        Return modification time of a directory entry.

        :returns: None if modification time is null, a python datetime object
            otherwise (UTC timezone)

        new in version 0.26
        """
        if self.modifyTime == 0:
            return None
        return filetime2datetime(self.modifyTime)


    def getctime(self):
        """
        Return creation time of a directory entry.

        :returns: None if modification time is null, a python datetime object
            otherwise (UTC timezone)

        new in version 0.26
        """
        if self.createTime == 0:
            return None
        return filetime2datetime(self.createTime)


#--- OleFileIO ----------------------------------------------------------------

class OleFileIO:
    """
    OLE container object

    This class encapsulates the interface to an OLE 2 structured
    storage file.  Use the listdir and openstream methods to
    access the contents of this file.

    Object names are given as a list of strings, one for each subentry
    level.  The root entry should be omitted.  For example, the following
    code extracts all image streams from a Microsoft Image Composer file::

        with OleFileIO("fan.mic") as ole:

            for entry in ole.listdir():
                if entry[1:2] == "Image":
                    fin = ole.openstream(entry)
                    fout = open(entry[0:1], "wb")
                    while True:
                        s = fin.read(8192)
                        if not s:
                            break
                        fout.write(s)

    You can use the viewer application provided with the Python Imaging
    Library to view the resulting files (which happens to be standard
    TIFF files).
    """

    def __init__(self, filename=None, raise_defects=DEFECT_FATAL,
                 write_mode=False, debug=False, path_encoding=DEFAULT_PATH_ENCODING):
        """
        Constructor for the OleFileIO class.

        :param filename: file to open.

            - if filename is a string smaller than 1536 bytes, it is the path
              of the file to open. (bytes or unicode string)
            - if filename is a string longer than 1535 bytes, it is parsed
              as the content of an OLE file in memory. (bytes type only)
            - if filename is a file-like object (with read, seek and tell methods),
              it is parsed as-is. The caller is responsible for closing it when done.

        :param raise_defects: minimal level for defects to be raised as exceptions.
            (use DEFECT_FATAL for a typical application, DEFECT_INCORRECT for a
            security-oriented application, see source code for details)

        :param write_mode: bool, if True the file is opened in read/write mode instead
            of read-only by default.

        :param debug: bool, set debug mode (deprecated, not used anymore)

        :param path_encoding: None or str, name of the codec to use for path
            names (streams and storages), or None for Unicode.
            Unicode by default on Python 3+, UTF-8 on Python 2.x.
            (new in olefile 0.42, was hardcoded to Latin-1 until olefile v0.41)
        """
        # minimal level for defects to be raised as exceptions:
        self._raise_defects_level = raise_defects
        #: list of defects/issues not raised as exceptions:
        #: tuples of (exception type, message)
        self.parsing_issues = []
        self.write_mode = write_mode
        self.path_encoding = path_encoding
        # initialize all attributes to default values:
        self._filesize = None
        self.ministream = None
        self._used_streams_fat = []
        self._used_streams_minifat = []
        self.byte_order = None
        self.directory_fp = None
        self.direntries = None
        self.dll_version = None
        self.fat = None
        self.first_difat_sector = None
        self.first_dir_sector = None
        self.first_mini_fat_sector = None
        self.fp = None
        self.header_clsid = None
        self.header_signature = None
        self.metadata = None
        self.mini_sector_shift = None
        self.mini_sector_size = None
        self.mini_stream_cutoff_size = None
        self.minifat = None
        self.minifatsect = None
        # TODO: duplicates?
        self.minisectorcutoff = None
        self.minisectorsize = None
        self.ministream = None
        self.minor_version = None
        self.nb_sect = None
        self.num_difat_sectors = None
        self.num_dir_sectors = None
        self.num_fat_sectors = None
        self.num_mini_fat_sectors = None
        self.reserved1 = None
        self.reserved2 = None
        self.root = None
        self.sector_shift = None
        self.sector_size = None
        self.transaction_signature_number = None
        self.warn_if_not_closed = False
        self._we_opened_fp = False
        self._open_stack = None
        # raw header values, captured before olefile normalises any of them:
        self._raw_header = None
        self._raw_header_bytes = None
        # cached FormatEvidence report:
        self._format_evidence = None
        if filename:
            # try opening, ensure fp is closed if that fails
            try:
                self.open(filename, write_mode=write_mode)
            except Exception:
                # caller has no chance of calling close() now
                self._close(warn=False)
                raise

    def __del__(self):
        """Destructor, ensures all file handles are closed that we opened."""
        self._close(warn=True)
        # super(OleFileIO, self).__del__()  # there's no super-class destructor


    def __enter__(self):
        return self


    def __exit__(self, *args):
        self._close(warn=False)


    def _raise_defect(self, defect_level, message, exception_type=OleFileError):
        """
        This method should be called for any defect found during file parsing.
        It may raise an OleFileError exception according to the minimal level chosen
        for the OleFileIO object.

        :param defect_level: defect level, possible values are:

            - DEFECT_UNSURE    : a case which looks weird, but not sure it's a defect
            - DEFECT_POTENTIAL : a potential defect
            - DEFECT_INCORRECT : an error according to specifications, but parsing can go on
            - DEFECT_FATAL     : an error which cannot be ignored, parsing is impossible

        :param message: string describing the defect, used with raised exception.
        :param exception_type: exception class to be raised, OleFileError by default
        """
        # added by [PL]
        if defect_level >= self._raise_defects_level:
            log.error(message)
            raise exception_type(message)
        else:
            # just record the issue, no exception raised:
            self.parsing_issues.append((exception_type, message))
            log.warning(message)


    def _decode_utf16_str(self, utf16_str, errors='replace'):
        """
        Decode a string encoded in UTF-16 LE format, as found in the OLE
        directory or in property streams. Return a string encoded
        according to the path_encoding specified for the OleFileIO object.

        :param bytes utf16_str: bytes string encoded in UTF-16 LE format
        :param str errors: str, see python documentation for str.decode()
        :return: str, encoded according to path_encoding
        :rtype: str
        """
        unicode_str = utf16_str.decode('UTF-16LE', errors)
        if self.path_encoding:
            # an encoding has been specified for path names:
            return unicode_str.encode(self.path_encoding, errors)
        else:
            # path_encoding=None, return the Unicode string as-is:
            return unicode_str


    def open(self, filename, write_mode=False):
        """
        Open an OLE2 file in read-only or read/write mode.
        Read and parse the header, FAT and directory.

        :param filename: string-like or file-like object, OLE file to parse

            - if filename is a string smaller than 1536 bytes, it is the path
              of the file to open. (bytes or unicode string)
            - if filename is a string longer than 1535 bytes, it is parsed
              as the content of an OLE file in memory. (bytes type only)
            - if filename is a file-like object (with read, seek and tell methods),
              it is parsed as-is. The caller is responsible for closing it when done

        :param write_mode: bool, if True the file is opened in read/write mode instead
            of read-only by default. (ignored if filename is not a path)
        """
        self.write_mode = write_mode
        # a report describes one opened file; do not reuse a stale report
        self._format_evidence = None
        # [PL] check if filename is a string-like or file-like object:
        # (it is better to check for a read() method)
        if hasattr(filename, 'read'):
            # TODO: also check seek and tell methods?
            # file-like object: use it directly
            self.fp = filename
        elif isinstance(filename, bytes) and len(filename) >= MINIMAL_OLEFILE_SIZE:
            # filename is a bytes string containing the OLE file to be parsed:
            # convert it to BytesIO
            self.fp = io.BytesIO(filename)
        else:
            # string-like object: filename of file on disk
            if self.write_mode:
                # open file in mode 'read with update, binary'
                # According to https://docs.python.org/library/functions.html#open
                # 'w' would truncate the file, 'a' may only append on some Unixes
                mode = 'r+b'
            else:
                # read-only mode by default
                mode = 'rb'
            self.fp = open(filename, mode)
            self._we_opened_fp = True
            self._open_stack = traceback.extract_stack()   # remember for warning
        # obtain the filesize by using seek and tell, which should work on most
        # file-like objects:
        # TODO: do it above, using getsize with filename when possible?
        # TODO: fix code to fail with clear exception when filesize cannot be obtained
        filesize = 0
        self.fp.seek(0, os.SEEK_END)
        try:
            filesize = self.fp.tell()
        finally:
            self.fp.seek(0)
        self._filesize = filesize
        log.debug('File size: %d bytes (%Xh)' % (self._filesize, self._filesize))

        # lists of streams in FAT and MiniFAT, to detect duplicate references
        # (list of indexes of first sectors of each stream)
        self._used_streams_fat = []
        self._used_streams_minifat = []

        header = self.fp.read(512)

        if len(header) != 512 or header[:8] != MAGIC:
            log.debug('Magic = {!r} instead of {!r}'.format(header[:8], MAGIC))
            self._raise_defect(DEFECT_FATAL, "not an OLE2 structured storage file", NotOleFileError)

        # [PL] header structure according to AAF specifications:
        ##Header
        ##struct StructuredStorageHeader { // [offset from start (bytes), length (bytes)]
        ##BYTE _abSig[8]; // [00H,08] {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1,
        ##                // 0x1a, 0xe1} for current version
        ##CLSID _clsid;   // [08H,16] reserved must be zero (WriteClassStg/
        ##                // GetClassFile uses root directory class id)
        ##USHORT _uMinorVersion; // [18H,02] minor version of the format: 33 is
        ##                       // written by reference implementation
        ##USHORT _uDllVersion;   // [1AH,02] major version of the dll/format: 3 for
        ##                       // 512-byte sectors, 4 for 4 KB sectors
        ##USHORT _uByteOrder;    // [1CH,02] 0xFFFE: indicates Intel byte-ordering
        ##USHORT _uSectorShift;  // [1EH,02] size of sectors in power-of-two;
        ##                       // typically 9 indicating 512-byte sectors
        ##USHORT _uMiniSectorShift; // [20H,02] size of mini-sectors in power-of-two;
        ##                          // typically 6 indicating 64-byte mini-sectors
        ##USHORT _usReserved; // [22H,02] reserved, must be zero
        ##ULONG _ulReserved1; // [24H,04] reserved, must be zero
        ##FSINDEX _csectDir; // [28H,04] must be zero for 512-byte sectors,
        ##                   // number of SECTs in directory chain for 4 KB
        ##                   // sectors
        ##FSINDEX _csectFat; // [2CH,04] number of SECTs in the FAT chain
        ##SECT _sectDirStart; // [30H,04] first SECT in the directory chain
        ##DFSIGNATURE _signature; // [34H,04] signature used for transactions; must
        ##                        // be zero. The reference implementation
        ##                        // does not support transactions
        ##ULONG _ulMiniSectorCutoff; // [38H,04] maximum size for a mini stream;
        ##                           // typically 4096 bytes
        ##SECT _sectMiniFatStart; // [3CH,04] first SECT in the MiniFAT chain
        ##FSINDEX _csectMiniFat; // [40H,04] number of SECTs in the MiniFAT chain
        ##SECT _sectDifStart; // [44H,04] first SECT in the DIFAT chain
        ##FSINDEX _csectDif; // [48H,04] number of SECTs in the DIFAT chain
        ##SECT _sectFat[109]; // [4CH,436] the SECTs of first 109 FAT sectors
        ##};

        # [PL] header decoding:
        # '<' indicates little-endian byte ordering for Intel (cf. struct module help)
        fmt_header = '<8s16sHHHHHHLLLLLLLLLL'
        header_size = struct.calcsize(fmt_header)
        log.debug( "fmt_header size = %d, +FAT = %d" % (header_size, header_size + 109*4) )
        header1 = header[:header_size]
        (
            self.header_signature,
            self.header_clsid,
            self.minor_version,
            self.dll_version,
            self.byte_order,
            self.sector_shift,
            self.mini_sector_shift,
            self.reserved1,
            self.reserved2,
            self.num_dir_sectors,
            self.num_fat_sectors,
            self.first_dir_sector,
            self.transaction_signature_number,
            self.mini_stream_cutoff_size,
            self.first_mini_fat_sector,
            self.num_mini_fat_sectors,
            self.first_difat_sector,
            self.num_difat_sectors
        ) = struct.unpack(fmt_header, header1)
        log.debug( struct.unpack(fmt_header,    header1))

        # Keep the declarations exactly as they were stored in the header.
        # The parser below normalises some of them (notably the CLSID and the
        # mini stream cutoff), but a forensic report must describe what the
        # file actually declared, not the repaired in-memory value.
        self._raw_header_bytes = header[:512]
        self._raw_header = {
            'signature': self.header_signature,
            'clsid_raw': self.header_clsid,
            'minor_version': self.minor_version,
            'dll_version': self.dll_version,
            'byte_order': self.byte_order,
            'sector_shift': self.sector_shift,
            'mini_sector_shift': self.mini_sector_shift,
            'reserved1': self.reserved1,
            'reserved2': self.reserved2,
            'num_dir_sectors': self.num_dir_sectors,
            'num_fat_sectors': self.num_fat_sectors,
            'first_dir_sector': self.first_dir_sector,
            'transaction_signature_number': self.transaction_signature_number,
            'mini_stream_cutoff_size': self.mini_stream_cutoff_size,
            'first_mini_fat_sector': self.first_mini_fat_sector,
            'num_mini_fat_sectors': self.num_mini_fat_sectors,
            'first_difat_sector': self.first_difat_sector,
            'num_difat_sectors': self.num_difat_sectors,
        }

        if self.header_signature != MAGIC:
            # OLE signature should always be present
            self._raise_defect(DEFECT_FATAL, "incorrect OLE signature")
        if self.header_clsid != bytearray(16):
            # according to AAF specs, CLSID should always be zero
            self._raise_defect(DEFECT_INCORRECT, "incorrect CLSID in OLE header")
        log.debug( "Minor Version = %d" % self.minor_version )
        # TODO: according to MS-CFB, minor version should be 0x003E
        log.debug( "DLL Version   = %d (expected: 3 or 4)" % self.dll_version )
        if self.dll_version not in [3, 4]:
            # version 3: usual format, 512 bytes per sector
            # version 4: large format, 4K per sector
            self._raise_defect(DEFECT_INCORRECT, "incorrect DllVersion in OLE header")
        log.debug( "Byte Order    = %X (expected: FFFE)" % self.byte_order )
        if self.byte_order != 0xFFFE:
            # For now only common little-endian documents are handled correctly
            self._raise_defect(DEFECT_INCORRECT, "incorrect ByteOrder in OLE header")
            # TODO: add big-endian support for documents created on Mac ?
            # But according to [MS-CFB] ? v20140502, ByteOrder MUST be 0xFFFE.
        self.sector_size = 2**self.sector_shift
        log.debug( "Sector Size   = %d bytes (expected: 512 or 4096)" % self.sector_size )
        if self.sector_size not in [512, 4096]:
            self._raise_defect(DEFECT_INCORRECT, "incorrect sector_size in OLE header")
        if (self.dll_version==3 and self.sector_size!=512) \
        or (self.dll_version==4 and self.sector_size!=4096):
            self._raise_defect(DEFECT_INCORRECT, "sector_size does not match DllVersion in OLE header")
        self.mini_sector_size = 2**self.mini_sector_shift
        log.debug( "MiniFAT Sector Size   = %d bytes (expected: 64)" % self.mini_sector_size )
        if self.mini_sector_size not in [64]:
            self._raise_defect(DEFECT_INCORRECT, "incorrect mini_sector_size in OLE header")
        if self.reserved1 != 0 or self.reserved2 != 0:
            self._raise_defect(DEFECT_INCORRECT, "incorrect OLE header (non-null reserved bytes)")
        log.debug( "Number of Directory sectors = %d" % self.num_dir_sectors )
        # Number of directory sectors (only allowed if DllVersion != 3)
        if self.sector_size==512 and self.num_dir_sectors!=0:
            self._raise_defect(DEFECT_INCORRECT, "incorrect number of directory sectors in OLE header")
        log.debug( "Number of FAT sectors = %d" % self.num_fat_sectors )
        # num_fat_sectors = number of FAT sectors in the file
        log.debug( "First Directory sector  = %Xh" % self.first_dir_sector )
        # first_dir_sector = 1st sector containing the directory
        log.debug( "Transaction Signature Number    = %d" % self.transaction_signature_number )
        # Signature should be zero, BUT some implementations do not follow this
        # rule => only a potential defect:
        # (according to MS-CFB, may be != 0 for applications supporting file
        # transactions)
        if self.transaction_signature_number != 0:
            self._raise_defect(DEFECT_POTENTIAL, "incorrect OLE header (transaction_signature_number>0)")
        log.debug( "Mini Stream cutoff size = %Xh (expected: 1000h)" % self.mini_stream_cutoff_size )
        # MS-CFB: This integer field MUST be set to 0x00001000. This field
        # specifies the maximum size of a user-defined data stream allocated
        # from the mini FAT and mini stream, and that cutoff is 4096 bytes.
        # Any user-defined data stream larger than or equal to this cutoff size
        # must be allocated as normal sectors from the FAT.
        if self.mini_stream_cutoff_size != 0x1000:
            self._raise_defect(DEFECT_INCORRECT, "incorrect mini_stream_cutoff_size in OLE header")
            # if no exception is raised, the cutoff size is fixed to 0x1000
            log.warning('Fixing the mini_stream_cutoff_size to 4096 (mandatory value) instead of %d' %
                        self.mini_stream_cutoff_size)
            self.mini_stream_cutoff_size = 0x1000
        # TODO: check if these values are OK
        log.debug( "First MiniFAT sector      = %Xh" % self.first_mini_fat_sector )
        log.debug( "Number of MiniFAT sectors = %d" % self.num_mini_fat_sectors )
        log.debug( "First DIFAT sector        = %Xh" % self.first_difat_sector )
        log.debug( "Number of DIFAT sectors   = %d" % self.num_difat_sectors )

        # calculate the number of sectors in the file
        # (-1 because header doesn't count)
        self.nb_sect = ( (filesize + self.sector_size-1) // self.sector_size) - 1
        log.debug( "Maximum number of sectors in the file: %d (%Xh)" % (self.nb_sect, self.nb_sect))
        # TODO: change this test, because an OLE file MAY contain other data
        # after the last sector.

        # file clsid
        self.header_clsid = _clsid(header[8:24])

        # TODO: remove redundant attributes, and fix the code which uses them?
        self.sectorsize = self.sector_size #1 << i16(header, 30)
        self.minisectorsize = self.mini_sector_size  #1 << i16(header, 32)
        self.minisectorcutoff = self.mini_stream_cutoff_size # i32(header, 56)

        # check known streams for duplicate references (these are always in FAT,
        # never in MiniFAT):
        self._check_duplicate_stream(self.first_dir_sector)
        # check MiniFAT only if it is not empty:
        if self.num_mini_fat_sectors:
            self._check_duplicate_stream(self.first_mini_fat_sector)
        # check DIFAT only if it is not empty:
        if self.num_difat_sectors:
            self._check_duplicate_stream(self.first_difat_sector)

        # Load file allocation tables
        self.loadfat(header)
        # Load directory.  This sets both the direntries list (ordered by sid)
        # and the root (ordered by hierarchy) members.
        self.loaddirectory(self.first_dir_sector)
        self.minifatsect = self.first_mini_fat_sector

    def close(self):
        """
        close the OLE file, release the file object if we created it ourselves.

        Leaves the file handle open if it was provided by the caller.
        """
        self._close(warn=False)

    def _close(self, warn=False):
        """Implementation of close() with internal arg `warn`."""
        if self._we_opened_fp:
            if warn and self.warn_if_not_closed:
                # we only raise a warning if the file was not explicitly closed,
                # and if the option warn_if_not_closed is enabled
                warnings.warn(OleFileIONotClosed(self._open_stack))
            self.fp.close()
            self._we_opened_fp = False

    def _check_duplicate_stream(self, first_sect, minifat=False):
        """
        Checks if a stream has not been already referenced elsewhere.
        This method should only be called once for each known stream, and only
        if stream size is not null.

        :param first_sect: int, index of first sector of the stream in FAT
        :param minifat: bool, if True, stream is located in the MiniFAT, else in the FAT
        """
        if minifat:
            log.debug('_check_duplicate_stream: sect=%Xh in MiniFAT' % first_sect)
            used_streams = self._used_streams_minifat
        else:
            log.debug('_check_duplicate_stream: sect=%Xh in FAT' % first_sect)
            # some values can be safely ignored (not a real stream):
            if first_sect in (DIFSECT,FATSECT,ENDOFCHAIN,FREESECT):
                return
            used_streams = self._used_streams_fat
        # TODO: would it be more efficient using a dict or hash values, instead
        #      of a list of long ?
        if first_sect in used_streams:
            self._raise_defect(DEFECT_INCORRECT, 'Stream referenced twice')
        else:
            used_streams.append(first_sect)

    def dumpfat(self, fat, firstindex=0):
        """
        Display a part of FAT in human-readable form for debugging purposes
        """
        # dictionary to convert special FAT values in human-readable strings
        VPL = 8 # values per line (8+1 * 8+1 = 81)
        fatnames = {
            FREESECT:   "..free..",
            ENDOFCHAIN: "[ END. ]",
            FATSECT:    "FATSECT ",
            DIFSECT:    "DIFSECT "
            }
        nbsect = len(fat)
        nlines = (nbsect+VPL-1)//VPL
        print("index", end=" ")
        for i in range(VPL):
            print("%8X" % i, end=" ")
        print()
        for l in range(nlines):
            index = l*VPL
            print("%6X:" % (firstindex+index), end=" ")
            for i in range(index, index+VPL):
                if i>=nbsect:
                    break
                sect = fat[i]
                aux = sect & 0xFFFFFFFF  # JYTHON-WORKAROUND
                if aux in fatnames:
                    name = fatnames[aux]
                else:
                    if sect == i+1:
                        name = "    --->"
                    else:
                        name = "%8X" % sect
                print(name, end=" ")
            print()

    def dumpsect(self, sector, firstindex=0):
        """
        Display a sector in a human-readable form, for debugging purposes
        """
        VPL=8 # number of values per line (8+1 * 8+1 = 81)
        tab = array.array(UINT32, sector)
        if sys.byteorder == 'big':
            tab.byteswap()
        nbsect = len(tab)
        nlines = (nbsect+VPL-1)//VPL
        print("index", end=" ")
        for i in range(VPL):
            print("%8X" % i, end=" ")
        print()
        for l in range(nlines):
            index = l*VPL
            print("%6X:" % (firstindex+index), end=" ")
            for i in range(index, index+VPL):
                if i>=nbsect:
                    break
                sect = tab[i]
                name = "%8X" % sect
                print(name, end=" ")
            print()

    def sect2array(self, sect):
        """
        convert a sector to an array of 32 bits unsigned integers,
        swapping bytes on big endian CPUs such as PowerPC (old Macs)
        """
        # TODO: make this a static function
        a = array.array(UINT32, sect)
        # if CPU is big endian, swap bytes:
        if sys.byteorder == 'big':
            a.byteswap()
        return a

    def loadfat_sect(self, sect):
        """
        Adds the indexes of the given sector to the FAT

        :param sect: string containing the first FAT sector, or array of long integers
        :returns: index of last FAT sector.
        """
        # a FAT sector is an array of ulong integers.
        if isinstance(sect, array.array):
            # if sect is already an array it is directly used
            fat1 = sect
        else:
            # if it's a raw sector, it is parsed in an array
            fat1 = self.sect2array(sect)
            # Display the sector contents only if the logging level is debug:
            if log.isEnabledFor(logging.DEBUG):
                self.dumpsect(sect)
        # The FAT is a sector chain starting at the first index of itself.
        # initialize isect, just in case:
        isect = None
        for isect in fat1:
            isect = isect & 0xFFFFFFFF  # JYTHON-WORKAROUND
            log.debug("isect = %X" % isect)
            if isect == ENDOFCHAIN or isect == FREESECT:
                # the end of the sector chain has been reached
                log.debug("found end of sector chain")
                break
            # read the FAT sector
            s = self.getsect(isect)
            # parse it as an array of 32 bits integers, and add it to the
            # global FAT array
            nextfat = self.sect2array(s)
            self.fat = self.fat + nextfat
        return isect

    def loadfat(self, header):
        """
        Load the FAT table.
        """
        # The 1st sector of the file contains sector numbers for the first 109
        # FAT sectors, right after the header which is 76 bytes long.
        # (always 109, whatever the sector size: 512 bytes = 76+4*109)
        # Additional sectors are described by DIF blocks

        log.debug('Loading the FAT table, starting with the 1st sector after the header')
        sect = header[76:512]
        log.debug( "len(sect)=%d, so %d integers" % (len(sect), len(sect)//4) )
        # fat    = []
        # FAT is an array of 32 bits unsigned ints, it's more effective
        # to use an array than a list in Python.
        # It's initialized as empty first:
        self.fat = array.array(UINT32)
        self.loadfat_sect(sect)
        # self.dumpfat(self.fat)
        # for i in range(0, len(sect), 4):
        #     ix = i32(sect, i)
        #     # [PL] if ix == -2 or ix == -1: # ix == 0xFFFFFFFE or ix == 0xFFFFFFFF:
        #     if ix == 0xFFFFFFFE or ix == 0xFFFFFFFF:
        #         break
        #     s = self.getsect(ix)
        #     # fat    = fat + [i32(s, i) for i in range(0, len(s), 4)]
        #     fat = fat + array.array(UINT32, s)
        if self.num_difat_sectors != 0:
            log.debug('DIFAT is used, because file size > 6.8MB.')
            # [PL] There's a DIFAT because file is larger than 6.8MB
            # some checks just in case:
            if self.num_fat_sectors <= 109:
                # there must be at least 109 blocks in header and the rest in
                # DIFAT, so number of sectors must be >109.
                self._raise_defect(DEFECT_INCORRECT, 'incorrect DIFAT, not enough sectors')
            if self.first_difat_sector >= self.nb_sect:
                # initial DIFAT block index must be valid
                self._raise_defect(DEFECT_FATAL, 'incorrect DIFAT, first index out of range')
            log.debug( "DIFAT analysis..." )
            # We compute the necessary number of DIFAT sectors :
            # Number of pointers per DIFAT sector = (sectorsize/4)-1
            # (-1 because the last pointer is the next DIFAT sector number)
            nb_difat_sectors = (self.sectorsize//4)-1
            # (if 512 bytes: each DIFAT sector = 127 pointers + 1 towards next DIFAT sector)
            nb_difat = (self.num_fat_sectors-109 + nb_difat_sectors-1)//nb_difat_sectors
            log.debug( "nb_difat = %d" % nb_difat )
            if self.num_difat_sectors != nb_difat:
                raise IOError('incorrect DIFAT')
            isect_difat = self.first_difat_sector
            for i in iterrange(nb_difat):
                log.debug( "DIFAT block %d, sector %X" % (i, isect_difat) )
                # TODO: check if corresponding FAT SID = DIFSECT
                sector_difat = self.getsect(isect_difat)
                difat = self.sect2array(sector_difat)
                # Display the sector contents only if the logging level is debug:
                if log.isEnabledFor(logging.DEBUG):
                    self.dumpsect(sector_difat)
                self.loadfat_sect(difat[:nb_difat_sectors])
                # last DIFAT pointer is next DIFAT sector:
                isect_difat = difat[nb_difat_sectors]
                log.debug( "next DIFAT sector: %X" % isect_difat )
            # checks:
            if isect_difat not in [ENDOFCHAIN, FREESECT]:
                # last DIFAT pointer value must be ENDOFCHAIN or FREESECT
                raise IOError('incorrect end of DIFAT')
            # if len(self.fat) != self.num_fat_sectors:
            #     # FAT should contain num_fat_sectors blocks
            #     print("FAT length: %d instead of %d" % (len(self.fat), self.num_fat_sectors))
            #     raise IOError('incorrect DIFAT')
        else:
            log.debug('No DIFAT, because file size < 6.8MB.')
        # since FAT is read from fixed-size sectors, it may contain more values
        # than the actual number of sectors in the file.
        # Keep only the relevant sector indexes:
        if len(self.fat) > self.nb_sect:
            log.debug('len(fat)=%d, shrunk to nb_sect=%d' % (len(self.fat), self.nb_sect))
            self.fat = self.fat[:self.nb_sect]
        log.debug('FAT references %d sectors / Maximum %d sectors in file' % (len(self.fat), self.nb_sect))
        # Display the FAT contents only if the logging level is debug:
        if log.isEnabledFor(logging.DEBUG):
            log.debug('\nFAT:')
            self.dumpfat(self.fat)

    def loadminifat(self):
        """
        Load the MiniFAT table.
        """
        # MiniFAT is stored in a standard  sub-stream, pointed to by a header
        # field.
        # NOTE: there are two sizes to take into account for this stream:
        # 1) Stream size is calculated according to the number of sectors
        #    declared in the OLE header. This allocated stream may be more than
        #    needed to store the actual sector indexes.
        # (self.num_mini_fat_sectors is the number of sectors of size self.sector_size)
        stream_size = self.num_mini_fat_sectors * self.sector_size
        # 2) Actually used size is calculated by dividing the MiniStream size
        #    (given by root entry size) by the size of mini sectors, *4 for
        #    32 bits indexes:
        nb_minisectors = (self.root.size + self.mini_sector_size-1) // self.mini_sector_size
        used_size = nb_minisectors * 4
        log.debug('loadminifat(): minifatsect=%d, nb FAT sectors=%d, used_size=%d, stream_size=%d, nb MiniSectors=%d' %
            (self.minifatsect, self.num_mini_fat_sectors, used_size, stream_size, nb_minisectors))
        if used_size > stream_size:
            # This is not really a problem, but may indicate a wrong implementation:
            self._raise_defect(DEFECT_INCORRECT, 'OLE MiniStream is larger than MiniFAT')
        # In any case, first read stream_size:
        s = self._open(self.minifatsect, stream_size, force_FAT=True).read()
        # [PL] Old code replaced by an array:
        #self.minifat = [i32(s, i) for i in range(0, len(s), 4)]
        self.minifat = self.sect2array(s)
        # Then shrink the array to used size, to avoid indexes out of MiniStream:
        log.debug('MiniFAT shrunk from %d to %d sectors' % (len(self.minifat), nb_minisectors))
        self.minifat = self.minifat[:nb_minisectors]
        log.debug('loadminifat(): len=%d' % len(self.minifat))
        # Display the FAT contents only if the logging level is debug:
        if log.isEnabledFor(logging.DEBUG):
            log.debug('\nMiniFAT:')
            self.dumpfat(self.minifat)

    def getsect(self, sect):
        """
        Read given sector from file on disk.

        :param sect: int, sector index
        :returns: a string containing the sector data.
        """
        # From [MS-CFB]: A sector number can be converted into a byte offset
        # into the file by using the following formula:
        # (sector number + 1) x Sector Size.
        # This implies that sector #0 of the file begins at byte offset Sector
        # Size, not at 0.

        # [PL] the original code in PIL was wrong when sectors are 4KB instead of
        # 512 bytes:
        #self.fp.seek(512 + self.sectorsize * sect)
        # [PL]: added safety checks:
        #print("getsect(%X)" % sect)
        try:
            self.fp.seek(self.sectorsize * (sect+1))
        except Exception:
            log.debug('getsect(): sect=%X, seek=%d, filesize=%d' %
                (sect, self.sectorsize*(sect+1), self._filesize))
            self._raise_defect(DEFECT_FATAL, 'OLE sector index out of range')
        sector = self.fp.read(self.sectorsize)
        if len(sector) != self.sectorsize:
            log.debug('getsect(): sect=%X, read=%d, sectorsize=%d' %
                (sect, len(sector), self.sectorsize))
            self._raise_defect(DEFECT_FATAL, 'incomplete OLE sector')
        return sector

    def write_sect(self, sect, data, padding=b'\x00'):
        """
        Write given sector to file on disk.

        :param sect: int, sector index
        :param data: bytes, sector data
        :param padding: single byte, padding character if data < sector size
        """
        if not isinstance(data, bytes):
            raise TypeError("write_sect: data must be a bytes string")
        if not isinstance(padding, bytes) or len(padding)!=1:
            raise TypeError("write_sect: padding must be a bytes string of 1 char")
        # TODO: we could allow padding=None for no padding at all
        try:
            self.fp.seek(self.sectorsize * (sect+1))
        except Exception:
            log.debug('write_sect(): sect=%X, seek=%d, filesize=%d' %
                (sect, self.sectorsize*(sect+1), self._filesize))
            self._raise_defect(DEFECT_FATAL, 'OLE sector index out of range')
        if len(data) < self.sectorsize:
            # add padding
            data += padding * (self.sectorsize - len(data))
        elif len(data) > self.sectorsize:
            raise ValueError("Data is larger than sector size")
        self.fp.write(data)

    def _write_mini_sect(self, fp_pos, data, padding = b'\x00'):
        """
        Write given sector to file on disk.

        :param fp_pos: int, file position
        :param data: bytes, sector data
        :param padding: single byte, padding character if data < sector size
        """
        if not isinstance(data, bytes):
            raise TypeError("write_mini_sect: data must be a bytes string")
        if not isinstance(padding, bytes) or len(padding) != 1:
            raise TypeError("write_mini_sect: padding must be a bytes string of 1 char")

        try:
            self.fp.seek(fp_pos)
        except Exception:
            log.debug('write_mini_sect(): fp_pos=%d, filesize=%d' %
                      (fp_pos, self._filesize))
            self._raise_defect(DEFECT_FATAL, 'OLE sector index out of range')
        len_data = len(data)
        if len_data < self.mini_sector_size:
            data += padding * (self.mini_sector_size - len_data)
        if self.mini_sector_size < len_data:
            raise ValueError("Data is larger than sector size")
        self.fp.write(data)

    def loaddirectory(self, sect):
        """
        Load the directory.

        :param sect: sector index of directory stream.
        """
        log.debug('Loading the Directory:')
        # The directory is  stored in a standard
        # substream, independent of its size.

        # open directory stream as a read-only file:
        # (stream size is not known in advance)
        self.directory_fp = self._open(sect, force_FAT=True)

        # [PL] to detect malformed documents and avoid DoS attacks, the maximum
        # number of directory entries can be calculated:
        max_entries = self.directory_fp.size // 128
        log.debug('loaddirectory: size=%d, max_entries=%d' %
            (self.directory_fp.size, max_entries))

        # Create list of directory entries
        # self.direntries = []
        # We start with a list of "None" object
        self.direntries = [None] * max_entries
        # for sid in iterrange(max_entries):
        #     entry = fp.read(128)
        #     if not entry:
        #         break
        #     self.direntries.append(OleDirectoryEntry(entry, sid, self))
        # load root entry:
        root_entry = self._load_direntry(0)
        # Root entry is the first entry:
        self.root = self.direntries[0]
        # TODO: read ALL directory entries (ignore bad entries?)
        # TODO: adapt build_storage_tree to avoid duplicate reads
        # for i in range(1, max_entries):
        #     self._load_direntry(i)
        # read and build all storage trees, starting from the root:
        self.root.build_storage_tree()

    def _load_direntry (self, sid):
        """
        Load a directory entry from the directory.
        This method should only be called once for each storage/stream when
        loading the directory.

        :param sid: index of storage/stream in the directory.
        :returns: a OleDirectoryEntry object

        :exception OleFileError: if the entry has always been referenced.
        """
        # check if SID is OK:
        if sid<0 or sid>=len(self.direntries):
            self._raise_defect(DEFECT_FATAL, "OLE directory index out of range")
        # check if entry was already referenced:
        if self.direntries[sid] is not None:
            self._raise_defect(DEFECT_INCORRECT,
                "double reference for OLE stream/storage")
            # if exception not raised, return the object
            return self.direntries[sid]
        self.directory_fp.seek(sid * 128)
        entry = self.directory_fp.read(128)
        self.direntries[sid] = OleDirectoryEntry(entry, sid, self)
        return self.direntries[sid]

    def dumpdirectory(self):
        """
        Dump directory (for debugging only)
        """
        self.root.dump()

    def _open(self, start, size = UNKNOWN_SIZE, force_FAT=False):
        """
        Open a stream, either in FAT or MiniFAT according to its size.
        (openstream helper)

        :param start: index of first sector
        :param size: size of stream (or nothing if size is unknown)
        :param force_FAT: if False (default), stream will be opened in FAT or MiniFAT
            according to size. If True, it will always be opened in FAT.
        """
        log.debug('OleFileIO.open(): sect=%Xh, size=%d, force_FAT=%s' %
            (start, size, str(force_FAT)))
        # stream size is compared to the mini_stream_cutoff_size threshold:
        if size < self.minisectorcutoff and not force_FAT:
            # ministream object
            if not self.ministream:
                # load MiniFAT if it wasn't already done:
                self.loadminifat()
                # The first sector index of the miniFAT stream is stored in the
                # root directory entry:
                size_ministream = self.root.size
                log.debug('Opening MiniStream: sect=%Xh, size=%d' %
                    (self.root.isectStart, size_ministream))
                self.ministream = self._open(self.root.isectStart,
                    size_ministream, force_FAT=True)
            return OleStream(fp=self.ministream, sect=start, size=size,
                             offset=0, sectorsize=self.minisectorsize,
                             fat=self.minifat, filesize=self.ministream.size,
                             olefileio=self)
        else:
            # standard stream
            return OleStream(fp=self.fp, sect=start, size=size,
                             offset=self.sectorsize,
                             sectorsize=self.sectorsize, fat=self.fat,
                             filesize=self._filesize,
                             olefileio=self)

    def _list(self, files, prefix, node, streams=True, storages=False):
        """
        listdir helper

        :param files: list of files to fill in
        :param prefix: current location in storage tree (list of names)
        :param node: current node (OleDirectoryEntry object)
        :param streams: bool, include streams if True (True by default) - new in v0.26
        :param storages: bool, include storages if True (False by default) - new in v0.26
            (note: the root storage is never included)
        """
        prefix = prefix + [node.name]
        for entry in node.kids:
            if entry.entry_type == STGTY_STORAGE:
                # this is a storage
                if storages:
                    # add it to the list
                    files.append(prefix[1:] + [entry.name])
                # check its kids
                self._list(files, prefix, entry, streams, storages)
            elif entry.entry_type == STGTY_STREAM:
                # this is a stream
                if streams:
                    # add it to the list
                    files.append(prefix[1:] + [entry.name])
            else:
                self._raise_defect(DEFECT_INCORRECT, 'The directory tree contains an entry which is not a stream nor a storage.')

    def listdir(self, streams=True, storages=False):
        """
        Return a list of streams and/or storages stored in this file

        :param streams: bool, include streams if True (True by default) - new in v0.26
        :param storages: bool, include storages if True (False by default) - new in v0.26
            (note: the root storage is never included)
        :returns: list of stream and/or storage paths
        """
        files = []
        self._list(files, [], self.root, streams, storages)
        return files

    def _find(self, filename):
        """
        Returns directory entry of given filename. (openstream helper)
        Note: this method is case-insensitive.

        :param filename: path of stream in storage tree (except root entry), either:

            - a string using Unix path syntax, for example:
              'storage_1/storage_1.2/stream'
            - or a list of storage filenames, path to the desired stream/storage.
              Example: ['storage_1', 'storage_1.2', 'stream']

        :returns: sid of requested filename
        :exception IOError: if file not found
        """

        # if filename is a string instead of a list, split it on slashes to
        # convert to a list:
        if isinstance(filename, basestring):
            filename = filename.split('/')
        # walk across storage tree, following given path:
        node = self.root
        for name in filename:
            for kid in node.kids:
                if kid.name.lower() == name.lower():
                    break
            else:
                raise IOError("file not found")
            node = kid
        return node.sid

    def openstream(self, filename):
        """
        Open a stream as a read-only file object (BytesIO).
        Note: filename is case-insensitive.

        :param filename: path of stream in storage tree (except root entry), either:

            - a string using Unix path syntax, for example:
              'storage_1/storage_1.2/stream'
            - or a list of storage filenames, path to the desired stream/storage.
              Example: ['storage_1', 'storage_1.2', 'stream']

        :returns: file object (read-only)
        :exception IOError: if filename not found, or if this is not a stream.
        """
        sid = self._find(filename)
        entry = self.direntries[sid]
        if entry.entry_type != STGTY_STREAM:
            raise IOError("this file is not a stream")
        return self._open(entry.isectStart, entry.size)

    def _write_mini_stream(self, entry, data_to_write):
        if not entry.sect_chain:
            entry.build_sect_chain(self)
        nb_sectors = len(entry.sect_chain)

        if not self.root.sect_chain:
            self.root.build_sect_chain(self)
        block_size = self.sector_size // self.mini_sector_size
        for idx, sect in enumerate(entry.sect_chain):
            sect_base = sect // block_size
            sect_offset = sect % block_size
            fp_pos = (self.root.sect_chain[sect_base] + 1)*self.sector_size + sect_offset*self.mini_sector_size
            if idx < (nb_sectors - 1):
                data_per_sector = data_to_write[idx * self.mini_sector_size: (idx + 1) * self.mini_sector_size]
            else:
                data_per_sector = data_to_write[idx * self.mini_sector_size:]
            self._write_mini_sect(fp_pos, data_per_sector)

    def write_stream(self, stream_name, data):
        """
        Write a stream to disk. For now, it is only possible to replace an
        existing stream by data of the same size.

        :param stream_name: path of stream in storage tree (except root entry), either:

            - a string using Unix path syntax, for example:
              'storage_1/storage_1.2/stream'
            - or a list of storage filenames, path to the desired stream/storage.
              Example: ['storage_1', 'storage_1.2', 'stream']

        :param data: bytes, data to be written, must be the same size as the original
            stream.
        """
        if not isinstance(data, bytes):
            raise TypeError("write_stream: data must be a bytes string")
        sid = self._find(stream_name)
        entry = self.direntries[sid]
        if entry.entry_type != STGTY_STREAM:
            raise IOError("this is not a stream")
        size = entry.size
        if size != len(data):
            raise ValueError("write_stream: data must be the same size as the existing stream")
        if size < self.minisectorcutoff and entry.entry_type != STGTY_ROOT:
            return self._write_mini_stream(entry = entry, data_to_write = data)

        sect = entry.isectStart
        # number of sectors to write
        nb_sectors = (size + (self.sectorsize-1)) // self.sectorsize
        log.debug('nb_sectors = %d' % nb_sectors)
        for i in range(nb_sectors):
            # try:
            #     self.fp.seek(offset + self.sectorsize * sect)
            # except Exception:
            #     log.debug('sect=%d, seek=%d' %
            #         (sect, offset+self.sectorsize*sect))
            #     raise IOError('OLE sector index out of range')
            # extract one sector from data, the last one being smaller:
            if i<(nb_sectors-1):
                data_sector = data [i*self.sectorsize : (i+1)*self.sectorsize]
                # TODO: comment this if it works
                assert(len(data_sector)==self.sectorsize)
            else:
                data_sector = data [i*self.sectorsize:]
                # TODO: comment this if it works
                log.debug('write_stream: size=%d sectorsize=%d data_sector=%Xh size%%sectorsize=%d'
                    % (size, self.sectorsize, len(data_sector), size % self.sectorsize))
                assert(len(data_sector) % self.sectorsize==size % self.sectorsize)
            self.write_sect(sect, data_sector)
            # self.fp.write(data_sector)
            # jump to next sector in the FAT:
            try:
                sect = self.fat[sect]
            except IndexError:
                # [PL] if pointer is out of the FAT an exception is raised
                raise IOError('incorrect OLE FAT, sector index out of range')
        # [PL] Last sector should be a "end of chain" marker:
        if sect != ENDOFCHAIN:
            raise IOError('incorrect last sector index in OLE stream')

    def _evidence_filetime(self, value):
        if not value:
            return None
        try:
            return filetime2datetime(value)
        except Exception:
            return None

    def _evidence_directory_entries(self):
        paths = {}

        def walk(node, prefix):
            path = prefix + [node.name]
            paths[node.sid] = path
            for kid in node.kids:
                walk(kid, path)

        if self.root is not None:
            walk(self.root, [])
        entries = []
        fp = self.directory_fp
        if fp is None:
            return entries
        try:
            total = fp.size
        except Exception:
            total = 0
        max_entries = total // OleDirectoryEntry.DIRENTRY_SIZE
        try:
            old_pos = fp.tell()
        except Exception:
            old_pos = 0
        for sid in range(max_entries):
            try:
                fp.seek(sid * OleDirectoryEntry.DIRENTRY_SIZE)
                raw_entry = fp.read(OleDirectoryEntry.DIRENTRY_SIZE)
                if len(raw_entry) != OleDirectoryEntry.DIRENTRY_SIZE:
                    break
                (name_raw, namelength, entry_type, color, sid_left,
                 sid_right, sid_child, clsid_raw, user_flags, create_time,
                 modify_time, isect_start, size_low, size_high) = struct.unpack(
                    OleDirectoryEntry.STRUCT_DIRENTRY, raw_entry)
            except Exception:
                continue
            if namelength >= 2:
                name_utf16 = name_raw[:min(namelength - 2, 64)]
            else:
                name_utf16 = b""
            try:
                name = self._decode_utf16_str(name_utf16)
            except Exception:
                name = repr(name_utf16)
            path = paths.get(sid)
            path_text = "/".join(path) if path else None
            clsid = _clsid(clsid_raw)
            create_dt = self._evidence_filetime(create_time)
            modify_dt = self._evidence_filetime(modify_time)
            missing = []
            if not create_time:
                missing.append("create_time")
            if not modify_time:
                missing.append("modify_time")
            timestamp_status = ("absent" if len(missing) == 2 else
                                "partial" if missing else "present")
            entries.append({
                "sid": sid,
                "path": path_text,
                "reachable": path is not None,
                "name": name,
                "entry_type": entry_type,
                "entry_type_name": {
                    STGTY_EMPTY: "empty",
                    STGTY_STORAGE: "storage",
                    STGTY_STREAM: "stream",
                    STGTY_LOCKBYTES: "lockbytes",
                    STGTY_PROPERTY: "property",
                    STGTY_ROOT: "root"}.get(entry_type, "unknown"),
                "is_root": sid == 0,
                "create_time_raw": create_time,
                "modify_time_raw": modify_time,
                "createTime": create_time,
                "modifyTime": modify_time,
                "create_time": create_dt,
                "modify_time": modify_dt,
                "ctime": create_dt,
                "mtime": modify_dt,
                "create_time_available": bool(create_time),
                "modify_time_available": bool(modify_time),
                "timestamp_status": timestamp_status,
                "timestamp_complete": not missing,
                "missing_timestamp_fields": missing,
                "clsid": clsid,
                "clsid_raw": "".join("%02X" % i8(c) for c in bytearray(clsid_raw)),
                "clsid_present": bool(clsid),
                "clsid_source": "directory",
                "clsid_origin": "directory[%d]" % sid,
                "size": size_low + (size_high << 32),
                "isect_start": isect_start,
            })
        try:
            fp.seek(old_pos)
        except Exception:
            pass
        return entries

    def _build_format_evidence(self):
        raw = self._raw_header or {}
        raw_signature = raw.get("signature", self.header_signature)
        raw_clsid = raw.get("clsid_raw", b"\0" * 16)
        raw_minor = raw.get("minor_version", self.minor_version)
        raw_major = raw.get("dll_version", self.dll_version)
        raw_byte_order = raw.get("byte_order", self.byte_order)
        raw_sector_shift = raw.get("sector_shift", self.sector_shift)
        raw_mini_shift = raw.get("mini_sector_shift", self.mini_sector_shift)
        raw_reserved1 = raw.get("reserved1", self.reserved1)
        raw_reserved2 = raw.get("reserved2", self.reserved2)
        raw_num_dir = raw.get("num_dir_sectors", self.num_dir_sectors)
        raw_num_fat = raw.get("num_fat_sectors", self.num_fat_sectors)
        raw_first_dir = raw.get("first_dir_sector", self.first_dir_sector)
        raw_transaction = raw.get("transaction_signature_number",
                                  self.transaction_signature_number)
        raw_cutoff = raw.get("mini_stream_cutoff_size",
                             self.mini_stream_cutoff_size)
        raw_first_mini_fat = raw.get("first_mini_fat_sector",
                                     self.first_mini_fat_sector)
        raw_num_mini_fat = raw.get("num_mini_fat_sectors",
                                   self.num_mini_fat_sectors)
        raw_first_difat = raw.get("first_difat_sector",
                                  self.first_difat_sector)
        raw_num_difat = raw.get("num_difat_sectors", self.num_difat_sectors)

        declared_sector_size = None
        if isinstance(raw_sector_shift, int) and 0 <= raw_sector_shift < 32:
            declared_sector_size = 2 ** raw_sector_shift
        declared_mini_sector_size = None
        if isinstance(raw_mini_shift, int) and 0 <= raw_mini_shift < 32:
            declared_mini_sector_size = 2 ** raw_mini_shift
        actual_sector_size = self.sector_size or declared_sector_size
        actual_mini_sector_size = self.mini_sector_size or declared_mini_sector_size
        nb_sect = self.nb_sect or 0
        clsid_zero = not raw_clsid.strip(b"\0")

        constraints = []
        verified_constraints = []
        contradictions = []
        clues = []
        insufficient_evidence = []
        ineligible_attributes = []
        ineligible_records = []
        unavailable_attributes = []

        def add_constraint(code, passed, message, field=None, expected=None,
                           observed=None, source="header", conclusive=True,
                           reason=None):
            item = FormatEvidenceItem(
                code, EVIDENCE_CONSTRAINT,
                "verified" if passed else "violated", message,
                field=field, expected=expected, observed=observed,
                source=source, conclusive=conclusive, passed=passed,
                reason=reason)
            constraints.append(item)
            if passed:
                verified_constraints.append(item)
            else:
                contradiction = FormatEvidenceItem(
                    code, EVIDENCE_CONTRADICTION, "violated", message,
                    field=field, expected=expected, observed=observed,
                    source=source, conclusive=conclusive, passed=False,
                    reason=reason)
                contradictions.append(contradiction)
            return item

        def add_clue(code, status, message, field=None, observed=None,
                     expected=None, source="header", conclusive=False,
                     passed=None,
                    reason=None):
            item = FormatEvidenceItem(
                code, EVIDENCE_COMPATIBILITY, status, message,
                field=field, expected=expected, observed=observed, source=source,
                conclusive=conclusive, passed=passed, reason=reason)
            clues.append(item)
            return item

        def mark_ineligible(attribute, reason, source=None, observed=None,
                            unavailable=False):
            if attribute not in ineligible_attributes:
                ineligible_attributes.append(attribute)
            if unavailable and attribute not in unavailable_attributes:
                unavailable_attributes.append(attribute)
            item = FormatEvidenceItem(
                attribute, EVIDENCE_INSUFFICIENT,
                "unavailable" if unavailable else "not_eligible",
                reason, field=attribute, observed=observed, source=source,
                conclusive=False, passed=False, reason=reason)
            insufficient_evidence.append(item)
            ineligible_records.append(item)
            return item

        add_constraint(
            "header.signature", raw_signature == MAGIC,
            "The first eight bytes must be the OLE/CFB signature.",
            field="signature", expected="D0CF11E0A1B11AE1",
            observed="".join("%02X" % i8(c) for c in bytearray(raw_signature)))
        add_constraint(
            "header.byte_order", raw_byte_order == 0xFFFE,
            "The byte-order mark must identify little-endian data.",
            field="byte_order", expected="0xFFFE", observed=raw_byte_order)
        add_constraint(
            "header.dll_version", raw_major in (3, 4),
            "The major format version must be 3 or 4.",
            field="dll_version", expected=[3, 4], observed=raw_major)
        geometry_ok = (
            (raw_major == 3 and raw_sector_shift == 9) or
            (raw_major == 4 and raw_sector_shift == 12))
        add_constraint(
            "header.sector_geometry", geometry_ok,
            "Version 3 requires 512-byte sectors (shift 9); version 4 requires 4096-byte sectors (shift 12).",
            field="sector_shift",
            expected="9 for version 3, 12 for version 4",
            observed=raw_sector_shift,
            reason="This is the binding link between the declared version and the sector layout.")
        add_constraint(
            "header.mini_sector_geometry", raw_mini_shift == 6,
            "Mini-sectors must be 64 bytes (shift 6).",
            field="mini_sector_shift", expected=6, observed=raw_mini_shift)
        add_constraint(
            "header.clsid", clsid_zero,
            "The header CLSID is reserved and must be zero; storage class IDs belong in directory entries.",
            field="clsid", expected="00000000-0000-0000-0000-000000000000",
            observed="" if clsid_zero else _clsid(raw_clsid),
            source="header[0x08]",
            reason="A non-zero value is a declaration conflict, not an alternative CLSID source.")
        add_constraint(
            "header.reserved", raw_reserved1 == 0 and raw_reserved2 == 0,
            "The two reserved header fields must be zero.",
            field="reserved1/reserved2", expected=0,
            observed=[raw_reserved1, raw_reserved2])
        add_constraint(
            "header.mini_stream_cutoff", raw_cutoff == 0x1000,
            "The mini-stream cutoff must be 4096 bytes.",
            field="mini_stream_cutoff_size", expected=0x1000,
            observed=raw_cutoff)
        dir_count_ok = (
            (raw_major == 3 and raw_num_dir == 0) or
            (raw_major == 4 and raw_num_dir > 0))
        add_constraint(
            "header.directory_sector_count", dir_count_ok,
            "Version 3 must declare zero directory sectors; version 4 must declare at least one.",
            field="num_dir_sectors",
            expected="0 for version 3, at least 1 for version 4",
            observed=raw_num_dir)
        add_constraint(
            "header.fat_sector_count", raw_num_fat >= 1,
            "At least one FAT sector must be declared.",
            field="num_fat_sectors", expected="at least 1",
            observed=raw_num_fat)
        add_constraint(
            "header.fat_sector_count_range",
            raw_num_fat is not None and raw_num_fat <= nb_sect,
            "The declared FAT sector count cannot exceed the sectors in the file.",
            field="num_fat_sectors",
            expected="0 < value <= %d" % nb_sect, observed=raw_num_fat)
        if raw_major == 4:
            add_constraint(
                "header.directory_sector_count_range",
                raw_num_dir is not None and raw_num_dir <= nb_sect,
                "The declared directory sector count cannot exceed the sectors in the file.",
                field="num_dir_sectors",
                expected="0 < value <= %d" % nb_sect, observed=raw_num_dir)
        dir_start_ok = raw_first_dir is not None and 0 <= raw_first_dir < nb_sect
        add_constraint(
            "sector.first_directory_sector", dir_start_ok,
            "The first directory sector must lie inside the file.",
            field="first_dir_sector", expected="0 <= value < %d" % nb_sect,
            observed=raw_first_dir)
        if raw_num_mini_fat:
            add_constraint(
                "sector.first_mini_fat_sector",
                raw_first_mini_fat is not None and 0 <= raw_first_mini_fat < nb_sect,
                "When MiniFAT sectors are declared, their first sector must lie inside the file.",
                field="first_mini_fat_sector", observed=raw_first_mini_fat)
        if raw_num_difat:
            add_constraint(
                "sector.first_difat_sector",
                raw_first_difat is not None and 0 <= raw_first_difat < nb_sect,
                "When DIFAT sectors are declared, their first sector must lie inside the file.",
                field="first_difat_sector", observed=raw_first_difat)

        directory_stream_size = getattr(self.directory_fp, "size", None)
        actual_directory_sectors = None
        if directory_stream_size and actual_sector_size:
            actual_directory_sectors = (
                directory_stream_size + actual_sector_size - 1) // actual_sector_size
        directory_chain_consistent = None
        if raw_major == 4 and actual_directory_sectors is not None:
            directory_chain_consistent = actual_directory_sectors == raw_num_dir
            add_constraint(
                "sector.directory_chain_length", directory_chain_consistent,
                "The version 4 directory chain length must match num_dir_sectors.",
                field="num_dir_sectors", expected=actual_directory_sectors,
                observed=raw_num_dir, source="sector")

        if raw_minor == 0x003E:
            add_clue(
                "header.minor_version", "compatible",
                "Minor version 62 is the reference-implementation value.",
                field="minor_version", expected=0x003E, observed=raw_minor,
                reason="A fixed reference value is not evidence of a particular Office generation.")
        elif raw_minor == 0x0033:
            add_clue(
                "header.minor_version", "legacy",
                "Minor version 51 is an older compatibility value.",
                field="minor_version", expected=0x003E, observed=raw_minor,
                reason="Legacy compatibility gives no reliable writer provenance.")
        else:
            add_clue(
                "header.minor_version", "unrecognized",
                "The minor version is neither the reference value 62 nor the legacy value 51.",
                field="minor_version", expected=[0x003E, 0x0033],
                observed=raw_minor,
                reason="An unrecognized minor version is a compatibility clue, not a reliable generation marker.")
        if raw_transaction:
            add_clue(
                "header.transaction_signature", "present",
                "A non-zero transaction signature indicates a transacted-writing implementation.",
                field="transaction_signature_number", observed=raw_transaction,
                reason="Transactions describe a write capability and do not identify the save generation.")
        else:
            add_clue(
                "header.transaction_signature", "absent",
                "No transaction signature is declared.",
                field="transaction_signature_number", observed=0,
                reason="A zero field is the common default and carries no provenance information.")
        if raw_num_difat:
            add_clue(
                "header.difat", "present",
                "DIFAT sectors are used, which is compatible with a large file.",
                field="num_difat_sectors", observed=raw_num_difat,
                reason="DIFAT usage is a size/layout clue, not a writer-generation marker.")

        directory_entries = self._evidence_directory_entries()
        active_entries = [entry for entry in directory_entries
                          if entry["entry_type"] in (STGTY_STORAGE,
                                                      STGTY_STREAM, STGTY_ROOT)]
        root_entry = next((entry for entry in directory_entries
                           if entry["sid"] == 0), None)
        missing_timestamps = []
        missing_timestamp_details = []
        for entry in active_entries:
            for field in entry["missing_timestamp_fields"]:
                label = entry["path"] or "directory[%d]" % entry["sid"]
                name = "%s/%s" % (label, field)
                missing_timestamps.append(name)
                missing_timestamp_details.append({
                    "sid": entry["sid"],
                    "path": entry["path"],
                    "field": field,
                    "reason": "FILETIME is zero (not set).",
                })
                mark_ineligible(
                    name,
                    "The directory FILETIME is zero, meaning not set; it cannot be used for source or generation attribution.",
                    source="directory[%d]" % entry["sid"],
                    observed=0, unavailable=True)
            if entry["timestamp_status"] == "present":
                add_clue(
                    "directory[%d].timestamps" % entry["sid"], "present",
                    "Both directory timestamps are present for %r." %
                    (entry["path"] or entry["name"]),
                    field="create_time/modify_time",
                    observed={"create_time": entry["create_time"],
                              "modify_time": entry["modify_time"]},
                    source="directory[%d]" % entry["sid"],
                    reason="Timestamps are mutable, copyable and may be preserved from a template.")
            elif entry["timestamp_status"] == "partial":
                add_clue(
                    "directory[%d].timestamps" % entry["sid"], "partial",
                    "Only one directory timestamp is present for %r." %
                    (entry["path"] or entry["name"]),
                    field="create_time/modify_time",
                    observed={"create_time": entry["create_time"],
                              "modify_time": entry["modify_time"]},
                    source="directory[%d]" % entry["sid"],
                    reason="A partial timestamp cannot be treated as a save-time interval.")
            else:
                add_clue(
                    "directory[%d].timestamps" % entry["sid"], "absent",
                    "Both directory timestamps are zero for %r." %
                    (entry["path"] or entry["name"]),
                    field="create_time/modify_time", observed=0,
                    source="directory[%d]" % entry["sid"],
                    reason="Absent timestamps are not evidence about the save generation.")

        all_times_complete = bool(active_entries) and all(
            entry["timestamp_complete"] for entry in active_entries)
        any_times_available = any(
            entry["create_time_available"] or entry["modify_time_available"]
            for entry in active_entries)
        if not all_times_complete:
            mark_ineligible(
                "directory.timestamps",
                "At least one active directory entry has no creation or modification FILETIME; the timestamp set is incomplete.",
                source="directory", observed={
                    "complete": all_times_complete,
                    "available": any_times_available,
                    "missing": missing_timestamps}, unavailable=not any_times_available)

        clsid_origins = [{
            "source": "header",
            "origin": "header[0x08]",
            "clsid_source": "header",
            "offset": "0x08",
            "sid": None,
            "path": None,
            "entry_type": None,
            "clsid": "" if clsid_zero else _clsid(raw_clsid),
            "clsid_present": not clsid_zero,
            "eligible": False,
            "eligible_for_provenance": False,
            "conclusive": False,
            "reason": "Reserved header field; it is not a storage class identifier.",
        }]
        for entry in directory_entries:
            if (entry["entry_type"] in (STGTY_STORAGE, STGTY_ROOT)
                    or entry["clsid_present"]):
                clsid_origins.append({
                    "source": "directory",
                    "origin": "directory[%d]" % entry["sid"],
                    "clsid_source": "directory",
                    "offset": None,
                    "sid": entry["sid"],
                    "path": entry["path"],
                    "entry_type": entry["entry_type"],
                    "entry_type_name": entry["entry_type_name"],
                    "clsid": entry["clsid"],
                    "clsid_present": entry["clsid_present"],
                    "eligible": False,
                    "eligible_for_provenance": False,
                    "conclusive": False,
                    "reason": "Storage class identifiers are compatibility clues; they can be inherited, copied or left null.",
                })

        root_clsid = root_entry["clsid"] if root_entry else ""
        if root_clsid:
            add_clue(
                "clsid.root", "present",
                "The root directory declares a storage class CLSID.",
                field="clsid", observed=root_clsid, source="directory[0]",
                reason="The root CLSID identifies a storage class and may be inherited or copied; it is not proof of the writer generation.")
            mark_ineligible(
                "root.clsid",
                "The root CLSID is a compatibility clue only; it can be inherited or copied and does not establish the save generation.",
                source="directory[0]", observed=root_clsid)
        else:
            mark_ineligible(
                "root.clsid",
                "The root CLSID is null, so it cannot identify a storage class or a source.",
                source="directory[0]", observed="", unavailable=True)
        for entry in active_entries:
            if entry["entry_type"] == STGTY_STORAGE:
                label = entry["path"] or "directory[%d]" % entry["sid"]
                attr = "%s.clsid" % label
                if entry["clsid"]:
                    add_clue(
                        "clsid.%s" % label, "present",
                        "A substorage declares a class CLSID.",
                        field="clsid", observed=entry["clsid"],
                        source="directory[%d]" % entry["sid"],
                        reason="A substorage class identifies embedded content, not the outer save generation.")
                    mark_ineligible(
                        attr,
                        "The CLSID is a compatibility clue only; it can be inherited or copied and does not establish the save generation.",
                        source="directory[%d]" % entry["sid"],
                        observed=entry["clsid"])
                else:
                    mark_ineligible(
                        attr,
                        "The substorage CLSID is null and cannot be used for attribution.",
                        source="directory[%d]" % entry["sid"],
                        observed="", unavailable=True)
        mark_ineligible(
            "header.clsid",
            "The header CLSID is reserved and must be zero; it is not an independent source identifier.",
            source="header[0x08]", observed="" if clsid_zero else _clsid(raw_clsid),
            unavailable=clsid_zero)
        mark_ineligible(
            "header.minor_version",
            "The minor version is a fixed or legacy declaration and is not a save-generation marker.",
            source="header[0x18]", observed=raw_minor)
        mark_ineligible(
            "header.transaction_signature_number",
            "The transaction signature describes transacted-write capability, not document provenance.",
            source="header[0x34]", observed=raw_transaction,
            unavailable=not bool(raw_transaction))
        mark_ineligible(
            "header.dll_version",
            "The major version establishes the sector family only; it does not identify the Office or application that saved the file.",
            source="header[0x1A]", observed=raw_major,
            unavailable=raw_major not in (3, 4))
        mark_ineligible(
            "header.sector_shift",
            "The sector shift establishes the sector layout only; it does not identify the save generation.",
            source="header[0x1E]", observed=raw_sector_shift)
        mark_ineligible(
            "header.mini_sector_shift",
            "The mini-sector shift is a mandatory layout value, not a provenance marker.",
            source="header[0x20]", observed=raw_mini_shift)

        format_version = None
        if raw_signature == MAGIC and raw_byte_order == 0xFFFE and geometry_ok:
            format_version = raw_major
        format_family = None
        if format_version == 3:
            format_family = "V3"
        elif format_version == 4:
            format_family = "V4"

        header = {
            "signature": "".join(
                "%02X" % i8(c) for c in bytearray(raw_signature)),
            "signature_hex": "".join(
                "%02X" % i8(c) for c in bytearray(raw_signature)),
            "signature_valid": raw_signature == MAGIC,
            "clsid": "" if clsid_zero else _clsid(raw_clsid),
            "clsid_raw": "".join("%02X" % i8(c) for c in bytearray(raw_clsid)),
            "clsid_zero": clsid_zero,
            "minor_version": raw_minor,
            "minor": raw_minor,
            "major_version": raw_major,
            "version": raw_major,
            "dll_version": raw_major,
            "byte_order": raw_byte_order,
            "sector_shift": raw_sector_shift,
            "mini_sector_shift": raw_mini_shift,
            "declared_sector_size": declared_sector_size,
            "sector_size": declared_sector_size,
            "declared_mini_sector_size": declared_mini_sector_size,
            "mini_sector_size": declared_mini_sector_size,
            "reserved1": raw_reserved1,
            "reserved2": raw_reserved2,
            "num_dir_sectors": raw_num_dir,
            "num_fat_sectors": raw_num_fat,
            "first_dir_sector": raw_first_dir,
            "transaction_signature_number": raw_transaction,
            "mini_stream_cutoff_size": raw_cutoff,
            "first_mini_fat_sector": raw_first_mini_fat,
            "num_mini_fat_sectors": raw_num_mini_fat,
            "first_difat_sector": raw_first_difat,
            "num_difat_sectors": raw_num_difat,
        }
        sector = {
            "sector_size": actual_sector_size,
            "size": actual_sector_size,
            "sectorsize": actual_sector_size,
            "sector_shift": raw_sector_shift,
            "shift": raw_sector_shift,
            "declared_sector_size": declared_sector_size,
            "mini_sector_size": actual_mini_sector_size,
            "mini_size": actual_mini_sector_size,
            "minisectorsize": actual_mini_sector_size,
            "mini_sector_shift": raw_mini_shift,
            "mini_shift": raw_mini_shift,
            "declared_mini_sector_size": declared_mini_sector_size,
            "file_size": self._filesize,
            "num_sectors": nb_sect,
            "count": nb_sect,
            "nb_sect": nb_sect,
            "fat_sectors_declared": raw_num_fat,
            "fat_entries_loaded": (len(self.fat)
                                    if self.fat is not None else None),
            "directory_stream_size": directory_stream_size,
            "actual_directory_sectors": actual_directory_sectors,
            "num_dir_sectors": raw_num_dir,
            "directory_chain_consistent": directory_chain_consistent,
            "first_difat_sector": raw_first_difat,
            "num_difat_sectors": raw_num_difat,
        }
        observed_times = []
        for entry in active_entries:
            if entry["create_time"] is not None:
                observed_times.append(entry["create_time"])
            if entry["modify_time"] is not None:
                observed_times.append(entry["modify_time"])
        earliest_time = min(observed_times) if observed_times else None
        latest_time = max(observed_times) if observed_times else None
        time_span = (latest_time - earliest_time) if observed_times else None
        directory_times = {
            "entries": directory_entries,
            "root": root_entry,
            "root_entry": root_entry,
            "create_time": root_entry["create_time"] if root_entry else None,
            "modify_time": root_entry["modify_time"] if root_entry else None,
            "create_time_raw": root_entry["create_time_raw"] if root_entry else None,
            "modify_time_raw": root_entry["modify_time_raw"] if root_entry else None,
            "root_create_time": root_entry["create_time"] if root_entry else None,
            "root_modify_time": root_entry["modify_time"] if root_entry else None,
            "root_create_time_raw": root_entry["create_time_raw"] if root_entry else None,
            "root_modify_time_raw": root_entry["modify_time_raw"] if root_entry else None,
            "root_create_time_available": bool(root_entry and root_entry["create_time_available"]),
            "root_modify_time_available": bool(root_entry and root_entry["modify_time_available"]),
            "available": any_times_available,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "earliest": earliest_time,
            "latest": latest_time,
            "span": time_span,
            "complete": all_times_complete,
            "partial": bool(any_times_available) and not all_times_complete,
            "eligible_for_provenance": all_times_complete,
            "missing": missing_timestamps,
            "missing_details": missing_timestamp_details,
        }
        clsids = {
            "header": "" if clsid_zero else _clsid(raw_clsid),
            "header_value": "" if clsid_zero else _clsid(raw_clsid),
            "header_origin": clsid_origins[0],
            "root": root_clsid,
            "root_value": root_clsid,
            "root_origin": next((item for item in clsid_origins
                                  if item["sid"] == 0), None),
            "entries": [entry for entry in directory_entries
                        if (entry["entry_type"] in (STGTY_STORAGE, STGTY_ROOT)
                            or entry["clsid_present"])],
            "origins": clsid_origins,
        }
        any_clsid = any(entry["clsid_present"] for entry in directory_entries)
        if contradictions:
            provenance_status = "conflicted"
            provenance_reason = "Incompatible format declarations prevent a reliable provenance conclusion."
        elif not all_times_complete:
            provenance_status = "undetermined"
            provenance_reason = "Directory timestamps are incomplete; remaining CLSID and version declarations are compatibility clues only."
        else:
            provenance_status = "clue_only"
            provenance_reason = "Timestamps and CLSIDs are compatibility clues. No file field conclusively identifies the save generation."

        def attribute_record(eligible, conclusive, reason, source=None,
                             value=None):
            return {
                "eligible": bool(eligible),
                "eligible_for_provenance": bool(eligible),
                "conclusive": bool(conclusive),
                "reason": reason,
                "source": source,
                "value": value,
            }

        attribute_eligibility = {
            "format.version": attribute_record(
                format_version is not None, format_version is not None,
                "Establishes the CFB sector family, not the save generation.",
                "header[0x1A]", format_version),
            "format.major_version": attribute_record(
                format_version is not None, format_version is not None,
                "Establishes the CFB sector family only.",
                "header[0x1A]", raw_major),
            "header.dll_version": attribute_record(
                format_version is not None, format_version is not None,
                "Establishes the CFB sector family only.",
                "header[0x1A]", raw_major),
            "header.sector_shift": attribute_record(
                geometry_ok, True,
                "Establishes the sector layout only.",
                "header[0x1E]", raw_sector_shift),
            "sector.size": attribute_record(
                bool(actual_sector_size), True,
                "Establishes the sector layout only.",
                "header[0x1E]", actual_sector_size),
            "header.signature": attribute_record(
                raw_signature == MAGIC, True,
                "Establishes CFB identity only.", "header[0x00]", raw_signature == MAGIC),
            "header.minor_version": attribute_record(
                False, False,
                "Fixed or legacy declaration; not a save-generation marker.",
                "header[0x18]", raw_minor),
            "minor_version": attribute_record(
                False, False,
                "Fixed or legacy declaration; not a save-generation marker.",
                "header[0x18]", raw_minor),
            "header.clsid": attribute_record(
                False, False,
                "Reserved field that must be zero; not a CLSID source.",
                "header[0x08]", "" if clsid_zero else _clsid(raw_clsid)),
            "header_clsid": attribute_record(
                False, False,
                "Reserved field that must be zero; not a CLSID source.",
                "header[0x08]", "" if clsid_zero else _clsid(raw_clsid)),
            "header.transaction_signature_number": attribute_record(
                False, False,
                "Describes transacted-write capability, not provenance.",
                "header[0x34]", raw_transaction),
            "transaction_signature_number": attribute_record(
                False, False,
                "Describes transacted-write capability, not provenance.",
                "header[0x34]", raw_transaction),
            "directory.timestamps": attribute_record(
                all_times_complete, False,
                "Timestamps are mutable, copyable and may be inherited from a template.",
                "directory", missing_timestamps),
            "directory.times": attribute_record(
                all_times_complete, False,
                "Timestamps are mutable, copyable and may be inherited from a template.",
                "directory", missing_timestamps),
            "directory_timestamps": attribute_record(
                all_times_complete, False,
                "Timestamps are mutable, copyable and may be inherited from a template.",
                "directory", missing_timestamps),
            "timestamps": attribute_record(
                all_times_complete, False,
                "Timestamps are mutable, copyable and may be inherited from a template.",
                "directory", missing_timestamps),
            "root.create_time": attribute_record(
                bool(root_entry and root_entry["create_time_available"]), False,
                "A root creation time can bound a timeline but does not identify the writer.",
                "directory[0]" if root_entry else None,
                root_entry["create_time"] if root_entry else None),
            "root.createTime": attribute_record(
                bool(root_entry and root_entry["create_time_available"]), False,
                "A root creation time can bound a timeline but does not identify the writer.",
                "directory[0]" if root_entry else None,
                root_entry["create_time"] if root_entry else None),
            "root.modify_time": attribute_record(
                bool(root_entry and root_entry["modify_time_available"]), False,
                "A root modification time can bound a timeline but does not identify the writer.",
                "directory[0]" if root_entry else None,
                root_entry["modify_time"] if root_entry else None),
            "root.modifyTime": attribute_record(
                bool(root_entry and root_entry["modify_time_available"]), False,
                "A root modification time can bound a timeline but does not identify the writer.",
                "directory[0]" if root_entry else None,
                root_entry["modify_time"] if root_entry else None),
            "root.clsid": attribute_record(
                bool(root_clsid), False,
                "A compatibility clue that can be inherited or copied.",
                "directory[0]" if root_entry else None, root_clsid),
            "root_clsid": attribute_record(
                bool(root_clsid), False,
                "A compatibility clue that can be inherited or copied.",
                "directory[0]" if root_entry else None, root_clsid),
            "directory.clsid": attribute_record(
                any_clsid, False,
                "Storage CLSIDs identify classes and embedded content, not the save generation.",
                "directory", any_clsid),
            "directory_clsid": attribute_record(
                any_clsid, False,
                "Storage CLSIDs identify classes and embedded content, not the save generation.",
                "directory", any_clsid),
            "clsid": attribute_record(
                any_clsid, False,
                "Storage CLSIDs are compatibility clues only.",
                "directory", any_clsid),
        }

        for mark in (
                ("header.dll_version", "format-family only"),
                ("header.sector_shift", "format-layout only"),
                ("header.mini_sector_shift", "format-layout only"),
                ("format.version", "format-family only"),
                ("format.major_version", "format-family only"),
                ("sector.size", "format-layout only"),
                ("header.signature", "format-identity only"),
                ("root.create_time", "timeline clue only"),
                ("root.createTime", "timeline clue only"),
                ("root.modify_time", "timeline clue only"),
                ("root.modifyTime", "timeline clue only"),
                ("root.clsid", "storage-class clue only"),
                ("root_clsid", "storage-class clue only"),
                ("directory.clsid", "storage-class clue only"),
                ("directory_clsid", "storage-class clue only"),
                ("clsid", "storage-class clue only"),
                ("directory.timestamps", "timeline clue only"),
                ("directory.times", "timeline clue only"),
                ("directory_timestamps", "timeline clue only"),
                ("timestamps", "timeline clue only")):
            if mark[0] in attribute_eligibility:
                attribute_eligibility[mark[0]]["eligible_for_provenance"] = False
                attribute_eligibility[mark[0]]["reason"] = (
                    attribute_eligibility[mark[0]]["reason"] +
                    " Not eligible for writer/source attribution (%s)." % mark[1])

        evidence_attributes = [
            "header.signature", "header.byte_order", "header.dll_version",
            "header.sector_shift", "header.mini_sector_shift",
            "header.reserved", "header.mini_stream_cutoff",
            "header.directory_sector_count", "header.fat_sector_count",
            "directory.timestamps", "root.create_time", "root.modify_time",
            "root.clsid", "directory.clsid", "header.clsid",
            "header.minor_version", "header.transaction_signature_number"]

        positive_clues = [item for item in clues if item["passed"]]
        constraints_verified = len(contradictions) == 0
        is_consistent = constraints_verified
        if contradictions:
            summary = (
                "Incompatible format declarations were found (%d); a provenance conclusion cannot be drawn from these declarations." %
                len(contradictions))
        elif format_version is None:
            summary = "The file is readable but its format family could not be confirmed from compatible declarations."
        elif not all_times_complete:
            summary = (
                "CFB %s constraints are verified, but directory timestamps are incomplete and are not eligible for source determination." %
                format_family)
        else:
            summary = (
                "CFB %s constraints are verified; timestamps and CLSIDs are compatibility clues only and do not prove the save generation." %
                format_family)

        report = FormatEvidence({
            "format_version": format_version,
            "format": "OLE2/CFB",
            "container": "OLE2/CFB",
            "is_ole": True,
            "sector_size": actual_sector_size,
            "mini_sector_size": actual_mini_sector_size,
            "sector_shift": raw_sector_shift,
            "mini_sector_shift": raw_mini_shift,
            "num_sectors": nb_sect,
            "nb_sect": nb_sect,
            "file_size": self._filesize,
            "header_clsid": "" if clsid_zero else _clsid(raw_clsid),
            "header_clsid_origin": clsid_origins[0],
            "root_clsid": root_clsid,
            "root_clsid_origin": next((item for item in clsid_origins
                                        if item["sid"] == 0), None),
            "storage_clsids": [entry["clsid"] for entry in active_entries
                               if entry["entry_type"] == STGTY_STORAGE
                               and entry["clsid"]],
            "minor_version": raw_minor,
            "transaction_signature_number": raw_transaction,
            "num_dir_sectors": raw_num_dir,
            "num_fat_sectors": raw_num_fat,
            "byte_order": raw_byte_order,
            "reserved1": raw_reserved1,
            "reserved2": raw_reserved2,
            "mini_stream_cutoff_size": raw_cutoff,
            "version": format_version,
            "version_string": (str(format_version)
                                if format_version is not None else None),
            "version_label": format_family,
            "major_version": raw_major,
            "declared_version": raw_major,
            "dll_version": raw_major,
            "format_family": format_family,
            "generation": None,
            "save_generation": None,
            "generation_number": None,
            "format_generation": format_family,
            "format_generation_number": format_version,
            "source_generation": None,
            "source": None,
            "writer": None,
            "office_generation": None,
            "provenance_generation": None,
            "generation_status": ("conflicted" if contradictions
                                  else "undetermined"),
            "generation_determined": False,
            "provenance_status": provenance_status,
            "provenance_conclusive": False,
            "source_status": provenance_status,
            "format_status": ("confirmed" if format_version
                              else "conflicted" if contradictions
                              else "undetermined"),
            "readable": True,
            "read_only": True,
            "valid": is_consistent,
            "is_valid": is_consistent,
            "consistent": is_consistent,
            "has_contradictions": bool(contradictions),
            "is_consistent": is_consistent,
            "constraints_verified": constraints_verified,
            "constraints_ok": constraints_verified,
            "format_constraints_verified": constraints_verified,
            "constraint_count": len(verified_constraints),
            "all_constraint_count": len(constraints),
            "verified_constraint_count": len(verified_constraints),
            "contradiction_count": len(contradictions),
            "clue_count": len(positive_clues),
            "insufficient_count": len(insufficient_evidence),
            "constraints": verified_constraints,
            "all_constraints": constraints,
            "format_constraints": constraints,
            "constraint_checks": constraints,
            "verified_constraints": verified_constraints,
            "constraints_passed": verified_constraints,
            "constraints_failed": contradictions,
            "compatibility_clues": positive_clues,
            "compatibility": positive_clues,
            "clues": positive_clues,
            "clue_observations": clues,
            "contradictions": contradictions,
            "conflicts": contradictions,
            "violations": contradictions,
            "incompatible_declarations": contradictions,
            "incompatibilities": contradictions,
            "insufficient_evidence": insufficient_evidence,
            "insufficient": insufficient_evidence,
            "ineligible_evidence": insufficient_evidence,
            "ineligible_records": insufficient_evidence,
            "ineligible_attributes": ineligible_attributes,
            "ineligible": ineligible_attributes,
            "not_eligible_for_provenance": ineligible_attributes,
            "not_eligible": ineligible_attributes,
            "unusable_attributes": ineligible_attributes,
            "unavailable_attributes": unavailable_attributes,
            "unavailable": unavailable_attributes,
            "missing_attributes": unavailable_attributes,
            "missing": unavailable_attributes,
            "missing_timestamps": missing_timestamps,
            "missing_timestamp_details": missing_timestamp_details,
            "missing_timestamp_attributes": missing_timestamp_details,
            "attribute_eligibility": attribute_eligibility,
            "provenance_attributes": attribute_eligibility,
            "evidence_attributes": evidence_attributes,
            "directory_times": directory_times,
            "directory_timestamps": directory_times,
            "timestamps": directory_times,
            "clsids": clsids,
            "clsid_origins": clsid_origins,
            "clsid_sources": clsid_origins,
            "header": header,
            "sector": sector,
            "sectors": sector,
            "sector_specification": sector,
            "sector_specs": sector,
            "directory": {"entries": directory_entries},
            "header_fields": header,
            "header_declarations": header,
            "directory_time_evidence": directory_times,
            "clsid_evidence": clsid_origins,
            "attributes": attribute_eligibility,
            "eligibility": attribute_eligibility,
            "constraint_map": dict((item.code, item) for item in constraints),
            "contradiction_codes": [item.code for item in contradictions],
            "clue_codes": [item.code for item in clues],
            "provenance": {
                "status": provenance_status,
                "state": provenance_status,
                "verdict": provenance_status,
                "determined": False,
                "confidence": "none",
                "generation": None,
                "source_generation": None,
                "source": None,
                "writer": None,
                "application": None,
                "office_generation": None,
                "conclusive": False,
                "eligible": False,
                "reason": provenance_reason,
                "eligible_attributes": [name for name, item in
                                         attribute_eligibility.items()
                                         if item["eligible"]],
                "conclusive_attributes": [name for name, item in
                                           attribute_eligibility.items()
                                           if item["eligible_for_provenance"]],
                "ineligible_attributes": ineligible_attributes,
                "unavailable_attributes": unavailable_attributes,
            },
            "categories": {
                "constraints": constraints,
                "compatibility_clues": positive_clues,
                "compatibility_observations": clues,
                "contradictions": contradictions,
                "insufficient": insufficient_evidence,
            },
            "parsing_issues": [
                {"exception": getattr(exc_type, "__name__", repr(exc_type)),
                 "message": message}
                for exc_type, message in (self.parsing_issues or [])],
            "summary": summary,
            "conclusion": summary,
        })
        return report

    def get_forensic_report(self):
        return self.get_format_evidence()

    def get_forensic_evidence(self):
        return self.get_format_evidence()

    def get_file_format_evidence(self):
        return self.get_format_evidence()

    def get_evidence(self):
        return self.get_format_evidence()

    def get_format_evidence_report(self):
        return self.get_format_evidence()

    def get_evidence_report(self):
        return self.get_format_evidence()

    format_evidence = property(lambda self: self.get_format_evidence())
    evidence_report = property(lambda self: self.get_format_evidence())

    evidence = property(lambda self: self.get_format_evidence())
    forensic_report = property(lambda self: self.get_format_evidence())
    file_format_evidence = property(lambda self: self.get_format_evidence())

    def get_forensics(self):
        return self.get_format_evidence()

    def get_format_evidence(self):
        """Return the read-only file-format evidence report."""
        if self._format_evidence is None:
            self._format_evidence = self._build_format_evidence()
        return self._format_evidence

    def get_type(self, filename):
        """
        Test if given filename exists as a stream or a storage in the OLE
        container, and return its type.

        :param filename: path of stream in storage tree. (see openstream for syntax)
        :returns: False if object does not exist, its entry type (>0) otherwise:

            - STGTY_STREAM: a stream
            - STGTY_STORAGE: a storage
            - STGTY_ROOT: the root entry
        """
        try:
            sid = self._find(filename)
            entry = self.direntries[sid]
            return entry.entry_type
        except Exception:
            return False

    def getclsid(self, filename):
        """
        Return clsid of a stream/storage.

        :param filename: path of stream/storage in storage tree. (see openstream for
            syntax)
        :returns: Empty string if clsid is null, a printable representation of the clsid otherwise

        new in version 0.44
        """
        sid = self._find(filename)
        entry = self.direntries[sid]
        return entry.clsid

    def getmtime(self, filename):
        """
        Return modification time of a stream/storage.

        :param filename: path of stream/storage in storage tree. (see openstream for
            syntax)
        :returns: None if modification time is null, a python datetime object
            otherwise (UTC timezone)

        new in version 0.26
        """
        sid = self._find(filename)
        entry = self.direntries[sid]
        return entry.getmtime()

    def getctime(self, filename):
        """
        Return creation time of a stream/storage.

        :param filename: path of stream/storage in storage tree. (see openstream for
            syntax)
        :returns: None if creation time is null, a python datetime object
            otherwise (UTC timezone)

        new in version 0.26
        """
        sid = self._find(filename)
        entry = self.direntries[sid]
        return entry.getctime()

    def exists(self, filename):
        """
        Test if given filename exists as a stream or a storage in the OLE
        container.
        Note: filename is case-insensitive.

        :param filename: path of stream in storage tree. (see openstream for syntax)
        :returns: True if object exist, else False.
        """
        try:
            sid = self._find(filename)
            return True
        except Exception:
            return False

    def get_size(self, filename):
        """
        Return size of a stream in the OLE container, in bytes.

        :param filename: path of stream in storage tree (see openstream for syntax)
        :returns: size in bytes (long integer)
        :exception IOError: if file not found
        :exception TypeError: if this is not a stream.
        """
        sid = self._find(filename)
        entry = self.direntries[sid]
        if entry.entry_type != STGTY_STREAM:
            # TODO: Should it return zero instead of raising an exception ?
            raise TypeError('object is not an OLE stream')
        return entry.size

    def get_rootentry_name(self):
        """
        Return root entry name. Should usually be 'Root Entry' or 'R' in most
        implementations.
        """
        return self.root.name

    def getproperties(self, filename, convert_time=False, no_conversion=None):
        """
        Return properties described in substream.

        :param filename: path of stream in storage tree (see openstream for syntax)
        :param convert_time: bool, if True timestamps will be converted to Python datetime
        :param no_conversion: None or list of int, timestamps not to be converted
            (for example total editing time is not a real timestamp)

        :returns: a dictionary of values indexed by id (integer)
        """
        #REFERENCE: [MS-OLEPS] https://msdn.microsoft.com/en-us/library/dd942421.aspx
        # make sure no_conversion is a list, just to simplify code below:
        if no_conversion == None:
            no_conversion = []
        # stream path as a string to report exceptions:
        streampath = filename
        if not isinstance(streampath, str):
            streampath = '/'.join(streampath)
        fp = self.openstream(filename)
        data = {}
        try:
            # header
            s = fp.read(28)
            clsid = _clsid(s[8:24])
            # format id
            s = fp.read(20)
            fmtid = _clsid(s[:16])
            fp.seek(i32(s, 16))
            # get section
            s = b"****" + fp.read(i32(fp.read(4))-4)
            # number of properties:
            num_props = i32(s, 4)
        except BaseException as exc:
            # catch exception while parsing property header, and only raise
            # a DEFECT_INCORRECT then return an empty dict, because this is not
            # a fatal error when parsing the whole file
            msg = 'Error while parsing properties header in stream {}: {}'.format(
                repr(streampath), exc)
            self._raise_defect(DEFECT_INCORRECT, msg, type(exc))
            return data
        # clamp num_props based on the data length
        num_props = min(num_props, int(len(s) / 8))
        for i in iterrange(num_props):
            property_id = 0 # just in case of an exception
            try:
                property_id = i32(s, 8+i*8)
                offset = i32(s, 12+i*8)
                property_type = i32(s, offset)

                vt_name = VT.get(property_type, 'UNKNOWN')
                log.debug('property id=%d: type=%d/%s offset=%X' % (property_id, property_type, vt_name, offset))

                value = self._parse_property(s, offset+4, property_id, property_type, convert_time, no_conversion)
                data[property_id] = value
            except BaseException as exc:
                # catch exception while parsing each property, and only raise
                # a DEFECT_INCORRECT, because parsing can go on
                msg = 'Error while parsing property id %d in stream %s: %s' % (
                    property_id, repr(streampath), exc)
                self._raise_defect(DEFECT_INCORRECT, msg, type(exc))

        return data

    def _parse_property(self, s, offset, property_id, property_type, convert_time, no_conversion):
        v = None
        if property_type <= VT_BLOB or property_type in (VT_CLSID, VT_CF):
            v, _ = self._parse_property_basic(s, offset, property_id, property_type, convert_time, no_conversion)
        elif property_type == VT_VECTOR | VT_VARIANT:
            log.debug('property_type == VT_VECTOR | VT_VARIANT')
            off = 4
            count = i32(s, offset)
            values = []
            for _ in range(count):
                property_type = i32(s, offset + off)
                v, sz  = self._parse_property_basic(s, offset + off + 4, property_id, property_type, convert_time, no_conversion)
                values.append(v)
                off += sz + 4
            v = values

        elif property_type & VT_VECTOR:
            property_type_base = property_type & ~VT_VECTOR
            log.debug('property_type == VT_VECTOR | %s' % VT.get(property_type_base, 'UNKNOWN'))
            off = 4
            count = i32(s, offset)
            values = []
            for _ in range(count):
                v, sz = self._parse_property_basic(s, offset + off, property_id, property_type & ~VT_VECTOR, convert_time, no_conversion)
                values.append(v)
                off += sz
            v = values
        else:
            log.debug('property id=%d: type=%d not implemented in parser yet' % (property_id, property_type))
        return v

    def _parse_property_basic(self, s, offset, property_id, property_type, convert_time, no_conversion):
            value = None
            size = 0
            # test for common types first (should perhaps use
            # a dictionary instead?)

            if property_type == VT_I2: # 16-bit signed integer
                value = i16(s, offset)
                if value >= 32768:
                    value = value - 65536
                size = 2
            elif property_type == VT_UI2: # 2-byte unsigned integer
                value = i16(s, offset)
                size = 2
            elif property_type in (VT_I4, VT_INT, VT_ERROR):
                # VT_I4: 32-bit signed integer
                # VT_ERROR: HRESULT, similar to 32-bit signed integer,
                # see https://msdn.microsoft.com/en-us/library/cc230330.aspx
                value = i32(s, offset)
                size = 4
            elif property_type in (VT_UI4, VT_UINT): # 4-byte unsigned integer
                value = i32(s, offset) # FIXME
                size = 4
            elif property_type in (VT_BSTR, VT_LPSTR):
                # CodePageString, see https://msdn.microsoft.com/en-us/library/dd942354.aspx
                # size is a 32 bits integer, including the null terminator, and
                # possibly trailing or embedded null chars
                #TODO: if codepage is unicode, the string should be converted as such
                count = i32(s, offset)
                value = s[offset+4:offset+4+count-1]
                # remove all null chars:
                value = value.replace(b'\x00', b'')
                size = 4 + count
            elif property_type == VT_BLOB:
                # binary large object (BLOB)
                # see https://msdn.microsoft.com/en-us/library/dd942282.aspx
                count = i32(s, offset)
                value = s[offset+4:offset+4+count]
                size = 4 + count
            elif property_type == VT_LPWSTR:
                # UnicodeString
                # see https://msdn.microsoft.com/en-us/library/dd942313.aspx
                # "the string should NOT contain embedded or additional trailing
                # null characters."
                count = i32(s, offset+4)
                value = self._decode_utf16_str(s[offset+4:offset+4+count*2])
                size = 4 + count * 2
            elif property_type == VT_FILETIME:
                value = long(i32(s, offset)) + (long(i32(s, offset+4))<<32)
                # FILETIME is a 64-bit int: "number of 100ns periods
                # since Jan 1,1601".
                if convert_time and property_id not in no_conversion:
                    log.debug('Converting property #%d to python datetime, value=%d=%fs'
                            %(property_id, value, float(value)/10000000))
                    # convert FILETIME to Python datetime.datetime
                    # inspired from https://code.activestate.com/recipes/511425-filetime-to-datetime/
                    _FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
                    log.debug('timedelta days=%d' % (value//(10*1000000*3600*24)))
                    value = _FILETIME_null_date + datetime.timedelta(microseconds=value//10)
                else:
                    # legacy code kept for backward compatibility: returns a
                    # number of seconds since Jan 1,1601
                    value = value // 10000000 # seconds
                size = 8
            elif property_type == VT_UI1: # 1-byte unsigned integer
                value = i8(s[offset])
                size = 1
            elif property_type == VT_CLSID:
                value = _clsid(s[offset:offset+16])
                size = 16
            elif property_type == VT_CF:
                # PropertyIdentifier or ClipboardData??
                # see https://msdn.microsoft.com/en-us/library/dd941945.aspx
                count = i32(s, offset)
                value = s[offset+4:offset+4+count]
                size = 4 + count
            elif property_type == VT_BOOL:
                # VARIANT_BOOL, 16 bits bool, 0x0000=Fals, 0xFFFF=True
                # see https://msdn.microsoft.com/en-us/library/cc237864.aspx
                value = bool(i16(s, offset))
                size = 2
            else:
                value = None # everything else yields "None"
                log.debug('property id=%d: type=%d not implemented in parser yet' % (property_id, property_type))

                # missing: VT_EMPTY, VT_NULL, VT_R4, VT_R8, VT_CY, VT_DATE,
                # VT_DECIMAL, VT_I1, VT_I8, VT_UI8,
                # see https://msdn.microsoft.com/en-us/library/dd942033.aspx

                #print("%08x" % property_id, repr(value), end=" ")
                #print("(%s)" % VT[i32(s, offset) & 0xFFF])
            return value, size


    def get_metadata(self):
        """
        Parse standard properties streams, return an OleMetadata object
        containing all the available metadata.
        (also stored in the metadata attribute of the OleFileIO object)

        new in version 0.25
        """
        self.metadata = OleMetadata()
        self.metadata.parse_properties(self)
        return self.metadata

    def get_userdefined_properties(self, filename, convert_time=False, no_conversion=None):
        """
        Return properties described in substream.

        :param filename: path of stream in storage tree (see openstream for syntax)
        :param convert_time: bool, if True timestamps will be converted to Python datetime
        :param no_conversion: None or list of int, timestamps not to be converted
            (for example total editing time is not a real timestamp)

        :returns: a dictionary of values indexed by id (integer)
        """
        # REFERENCE: [MS-OLEPS] https://msdn.microsoft.com/en-us/library/dd942421.aspx
        # REFERENCE: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/2ea8be67-a4a0-4e2e-b42f-49a182645562
        #'D5CDD502-2E9C-101B-9397-08002B2CF9AE'
        # TODO: testing the code more rigorously
        # TODO: adding exception handeling
        FMTID_USERDEFINED_PROPERTIES = _clsid(b'\x05\xD5\xCD\xD5\x9C\x2E\x1B\x10\x93\x97\x08\x00\x2B\x2C\xF9\xAE')

        # make sure no_conversion is a list, just to simplify code below:
        if no_conversion == None:
            no_conversion = []
        # stream path as a string to report exceptions:
        streampath = filename
        if not isinstance(streampath, str):
            streampath = '/'.join(streampath)

        fp = self.openstream(filename)

        data = []

        # header
        s = fp.read(28)
        clsid = _clsid(s[8:24])

        # PropertySetStream.cSections (4 bytes starts at 1c): number of property sets in this stream
        sections_count = i32(s, 24)

        section_file_pointers = []

        try:
            for i in range(sections_count):
                # format id
                s = fp.read(20)
                fmtid = _clsid(s[:16])

                if fmtid == FMTID_USERDEFINED_PROPERTIES:
                    file_pointer = i32(s, 16)
                    fp.seek(file_pointer)
                    # read saved sections
                    s = b"****" + fp.read(i32(fp.read(4)) - 4)
                    # number of properties:
                    num_props = i32(s, 4)

                    PropertyIdentifierAndOffset = s[8: 8+8*num_props]

                    # property names (dictionary)
                    # ref: https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-OLEPS/99127b7f-c440-4697-91a4-c853086d6b33
                    index = 8+8*num_props
                    entry_count = i32(s[index: index+4])
                    index += 4
                    for i in range(entry_count):
                        identifier = s[index: index +4]
                        str_size = i32(s[index+4: index + 8])
                        string = s[index+8: index+8+str_size].decode('utf_8').strip('\0')
                        data.append({'property_name':string, 'value':None})
                        index = index+8+str_size
                    # clamp num_props based on the data length
                    num_props = min(num_props, int(len(s) / 8))

                    # property values
                    # ref: https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-OLEPS/f122b9d7-e5cf-4484-8466-83f6fd94b3cc
                    for i in iterrange(2, num_props):
                        property_id = 0  # just in case of an exception
                        try:
                            property_id = i32(s, 8 + i * 8)
                            offset = i32(s, 12 + i * 8)
                            property_type = i32(s, offset)

                            vt_name = VT.get(property_type, 'UNKNOWN')
                            log.debug('property id=%d: type=%d/%s offset=%X' % (property_id, property_type, vt_name, offset))

                            # test for common types first (should perhaps use
                            # a dictionary instead?)

                            if property_type == VT_I2:  # 16-bit signed integer
                                value = i16(s, offset + 4)
                                if value >= 32768:
                                    value = value - 65536
                            elif property_type == 1:
                                # supposed to be VT_NULL but seems it is not NULL
                                str_size = i32(s, offset + 8)
                                value = s[offset + 12:offset + 12 + str_size - 1]

                            elif property_type == VT_UI2:  # 2-byte unsigned integer
                                value = i16(s, offset + 4)
                            elif property_type in (VT_I4, VT_INT, VT_ERROR):
                                # VT_I4: 32-bit signed integer
                                # VT_ERROR: HRESULT, similar to 32-bit signed integer,
                                # see https://msdn.microsoft.com/en-us/library/cc230330.aspx
                                value = i32(s, offset + 4)
                            elif property_type in (VT_UI4, VT_UINT):  # 4-byte unsigned integer
                                value = i32(s, offset + 4)  # FIXME
                            elif property_type in (VT_BSTR, VT_LPSTR):
                                # CodePageString, see https://msdn.microsoft.com/en-us/library/dd942354.aspx
                                # size is a 32 bits integer, including the null terminator, and
                                # possibly trailing or embedded null chars
                                # TODO: if codepage is unicode, the string should be converted as such
                                count = i32(s, offset + 4)
                                value = s[offset + 8:offset + 8 + count - 1]
                                # remove all null chars:
                                value = value.replace(b'\x00', b'')
                            elif property_type == VT_BLOB:
                                # binary large object (BLOB)
                                # see https://msdn.microsoft.com/en-us/library/dd942282.aspx
                                count = i32(s, offset + 4)
                                value = s[offset + 8:offset + 8 + count]
                            elif property_type == VT_LPWSTR:
                                # UnicodeString
                                # see https://msdn.microsoft.com/en-us/library/dd942313.aspx
                                # "the string should NOT contain embedded or additional trailing
                                # null characters."
                                count = i32(s, offset + 4)
                                value = self._decode_utf16_str(s[offset + 8:offset + 8 + count * 2])
                            elif property_type == VT_FILETIME:
                                value = long(i32(s, offset + 4)) + (long(i32(s, offset + 8)) << 32)
                                # FILETIME is a 64-bit int: "number of 100ns periods
                                # since Jan 1,1601".
                                if convert_time and property_id not in no_conversion:
                                    log.debug('Converting property #%d to python datetime, value=%d=%fs'
                                              % (property_id, value, float(value) / 10000000))
                                    # convert FILETIME to Python datetime.datetime
                                    # inspired from https://code.activestate.com/recipes/511425-filetime-to-datetime/
                                    _FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
                                    log.debug('timedelta days=%d' % (value // (10 * 1000000 * 3600 * 24)))
                                    value = _FILETIME_null_date + datetime.timedelta(microseconds=value // 10)
                                else:
                                    # legacy code kept for backward compatibility: returns a
                                    # number of seconds since Jan 1,1601
                                    value = value // 10000000  # seconds
                            elif property_type == VT_UI1:  # 1-byte unsigned integer
                                value = i8(s[offset + 4])
                            elif property_type == VT_CLSID:
                                value = _clsid(s[offset + 4:offset + 20])
                            elif property_type == VT_CF:
                                # PropertyIdentifier or ClipboardData??
                                # see https://msdn.microsoft.com/en-us/library/dd941945.aspx
                                count = i32(s, offset + 4)
                                value = s[offset + 8:offset + 8 + count]
                            elif property_type == VT_BOOL:
                                # VARIANT_BOOL, 16 bits bool, 0x0000=Fals, 0xFFFF=True
                                # see https://msdn.microsoft.com/en-us/library/cc237864.aspx
                                value = bool(i16(s, offset + 4))
                            else:
                                value = None  # everything else yields "None"
                                log.debug(
                                    'property id=%d: type=%d not implemented in parser yet' % (property_id, property_type))

                            # missing: VT_EMPTY, VT_NULL, VT_R4, VT_R8, VT_CY, VT_DATE,
                            # VT_DECIMAL, VT_I1, VT_I8, VT_UI8,
                            # see https://msdn.microsoft.com/en-us/library/dd942033.aspx

                            # FIXME: add support for VT_VECTOR
                            # VT_VECTOR is a 32 uint giving the number of items, followed by
                            # the items in sequence. The VT_VECTOR value is combined with the
                            # type of items, e.g. VT_VECTOR|VT_BSTR
                            # see https://msdn.microsoft.com/en-us/library/dd942011.aspx

                            # print("%08x" % property_id, repr(value), end=" ")
                            # print("(%s)" % VT[i32(s, offset) & 0xFFF])

                            data[i-2]['value']=value
                        except BaseException as exc:
                            # catch exception while parsing each property, and only raise
                            # a DEFECT_INCORRECT, because parsing can go on
                            msg = 'Error while parsing property id %d in stream %s: %s' % (
                                property_id, repr(streampath), exc)
                            self._raise_defect(DEFECT_INCORRECT, msg, type(exc))

        except BaseException as exc:
            # catch exception while parsing property header, and only raise
            # a DEFECT_INCORRECT then return an empty dict, because this is not
            # a fatal error when parsing the whole file
            msg = 'Error while parsing properties header in stream %s: %s' % (
                repr(streampath), exc)
            self._raise_defect(DEFECT_INCORRECT, msg, type(exc))
            return data

        return data


# --------------------------------------------------------------------
def get_format_evidence(filename, raise_defects=DEFECT_FATAL,
                        write_mode=False,
                        path_encoding=DEFAULT_PATH_ENCODING):
    """
    Open a file and return its read-only format evidence report.

    This is a convenience wrapper around OleFileIO.get_format_evidence.
    The report is fully materialised before the file is closed.
    """
    restore_position = None
    if hasattr(filename, "tell"):
        try:
            restore_position = filename.tell()
        except Exception:
            restore_position = None
    ole = OleFileIO(filename, raise_defects=raise_defects,
                    write_mode=write_mode, path_encoding=path_encoding)
    try:
        return ole.get_format_evidence()
    finally:
        ole.close()
        if restore_position is not None:
            try:
                filename.seek(restore_position)
            except Exception:
                pass


get_forensic_report = get_format_evidence
get_file_format_evidence = get_format_evidence
get_format_evidence_report = get_format_evidence
get_evidence_report = get_format_evidence
analyze_format = get_format_evidence
format_evidence = get_format_evidence
forensic_report = get_format_evidence
evidence_report = get_format_evidence

# This script can be used to dump the directory of any OLE2 structured
# storage file.

def main():
    """
    Main function when olefile is runs as a script from the command line.
    This will open an OLE2 file and display its structure and properties
    :return: nothing
    """
    import sys, optparse

    DEFAULT_LOG_LEVEL = "warning" # Default log level
    LOG_LEVELS = {
        'debug':    logging.DEBUG,
        'info':     logging.INFO,
        'warning':  logging.WARNING,
        'error':    logging.ERROR,
        'critical': logging.CRITICAL
        }

    usage = 'usage: %prog [options] <filename> [filename2 ...]'
    parser = optparse.OptionParser(usage=usage)

    parser.add_option("-c", action="store_true", dest="check_streams",
        help='check all streams (for debugging purposes)')
    parser.add_option("-p", action="store_true", dest="extract_customprop",
                      help='extract all user-defined propertires')
    parser.add_option("-e", "--evidence", action="store_true",
                      dest="format_evidence",
                      help="display the read-only file-format evidence report")
    parser.add_option("-d", action="store_true", dest="debug_mode",
        help='debug mode, shortcut for -l debug (displays a lot of debug information, for developers only)')
    parser.add_option('-l', '--loglevel', dest="loglevel", action="store", default=DEFAULT_LOG_LEVEL,
                            help="logging level debug/info/warning/error/critical (default=%default)")

    (options, args) = parser.parse_args()

    print('olefile version {} {} - https://www.decalage.info/en/olefile\n'.format(__version__, __date__))

    # Print help if no arguments are passed
    if len(args) == 0:
        print(__doc__)
        parser.print_help()
        sys.exit()

    if options.debug_mode:
        options.loglevel = 'debug'

    # setup logging to the console
    logging.basicConfig(level=LOG_LEVELS[options.loglevel], format='%(levelname)-8s %(message)s')

    # also enable the module's logger:
    enable_logging()

    for filename in args:
        try:
            ole = OleFileIO(filename)#, raise_defects=DEFECT_INCORRECT)
            print("-" * 68)
            print(filename)
            print("-" * 68)
            ole.dumpdirectory()
            if options.format_evidence:
                print()
                print("File-format evidence:")
                ole.get_format_evidence().dump()
            for streamname in ole.listdir():
                if streamname[-1][0] == "\005":
                    print("%r: properties" % streamname)
                    try:
                        props = ole.getproperties(streamname, convert_time=True)
                        props = sorted(props.items())
                        for k, v in props:
                            # [PL]: avoid to display too large or binary values:
                            if isinstance(v, (basestring, bytes)):
                                if len(v) > 50:
                                    v = v[:50]
                            if isinstance(v, bytes):
                                # quick and dirty binary check:
                                for c in (1,2,3,4,5,6,7,11,12,14,15,16,17,18,19,20,
                                          21,22,23,24,25,26,27,28,29,30,31):
                                    if c in bytearray(v):
                                        v = '(binary data)'
                                        break
                            print("   ", k, v)
                    except Exception:
                        log.exception('Error while parsing property stream %r' % streamname)

                    try:
                        if options.extract_customprop:
                            variables = ole.get_userdefined_properties(streamname, convert_time=True)
                            if len(variables):
                                print("%r: user-defined properties" % streamname)
                                for index, variable in enumerate(variables):
                                    print('\t{} {}: {}'.format(index, variable['property_name'],variable['value']))

                    except:
                        log.exception('Error while parsing user-defined property stream %r' % streamname)


            if options.check_streams:
                # Read all streams to check if there are errors:
                print('\nChecking streams...')
                for streamname in ole.listdir():
                    # print name using repr() to convert binary chars to \xNN:
                    print('-', repr('/'.join(streamname)),'-', end=' ')
                    st_type = ole.get_type(streamname)
                    if st_type == STGTY_STREAM:
                        print('size %d' % ole.get_size(streamname))
                        # just try to read stream in memory:
                        ole.openstream(streamname)
                    else:
                        print('NOT a stream : type=%d' % st_type)
                print()

            # for streamname in ole.listdir():
            #     # print name using repr() to convert binary chars to \xNN:
            #     print('-', repr('/'.join(streamname)),'-', end=' ')
            #     print(ole.getmtime(streamname))
            # print()

            print('Modification/Creation times of all directory entries:')
            for entry in ole.direntries:
                if entry is not None:
                    print('- {}: mtime={} ctime={}'.format(entry.name,
                        entry.getmtime(), entry.getctime()))
            print()

            # parse and display metadata:
            try:
                meta = ole.get_metadata()
                meta.dump()
            except Exception:
                log.exception('Error while parsing metadata')
            print()
            # [PL] Test a few new methods:
            root = ole.get_rootentry_name()
            print('Root entry name: "%s"' % root)
            if ole.exists('worddocument'):
                print("This is a Word document.")
                print("type of stream 'WordDocument':", ole.get_type('worddocument'))
                print("size :", ole.get_size('worddocument'))
                if ole.exists('macros/vba'):
                    print("This document may contain VBA macros.")

            # print parsing issues:
            print('\nNon-fatal issues raised during parsing:')
            if ole.parsing_issues:
                for exctype, msg in ole.parsing_issues:
                    print('- {}: {}'.format(exctype.__name__, msg))
            else:
                print('None')
            ole.close()
        except Exception:
            log.exception('Error while parsing file %r' % filename)


if __name__ == "__main__":
    main()

# this code was developed while listening to The Wedding Present "Sea Monsters"
