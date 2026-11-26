from LnkParse3.decorators import packed_uuid
from LnkParse3.extra.lnk_extra_base import LnkExtraBase
from LnkParse3.utils import parse_packed_uuid


DARWIN_ANSI_START = 8
DARWIN_ANSI_SIZE = 260
DARWIN_UNICODE_START = DARWIN_ANSI_START + DARWIN_ANSI_SIZE
DARWIN_UNICODE_SIZE = 520
DARWIN_PACKED_PRODUCT_LENGTH = 20


def decode_darwin_descriptor(data):
    """Decode one DarwinData string without choosing ANSI or Unicode."""
    result = {
        "raw": None,
        "form": None,
        "form_number": None,
        "has_feature": False,
        "has_component": False,
        "product_code_id": None,
        "product_packed_code": None,
        "feature_name": None,
        "component_id": None,
        "component_packed_id": None,
        "decode_error": None,
    }

    if not data:
        result["decode_error"] = "Darwin string is empty"
        return result

    text = str(data).split("\x00", 1)[0]
    result["raw"] = text

    if len(text) < DARWIN_PACKED_PRODUCT_LENGTH:
        result["decode_error"] = "Darwin string is shorter than packed product code"
        return result

    product_packed = text[:DARWIN_PACKED_PRODUCT_LENGTH]
    result["product_packed_code"] = product_packed
    try:
        result["product_code_id"] = parse_packed_uuid(product_packed)
    except (IndexError, ValueError) as exc:
        result["decode_error"] = f"invalid packed product code: {exc}"
        return result

    rest = text[DARWIN_PACKED_PRODUCT_LENGTH:]
    terminators = [(position, char) for position, char in enumerate(rest) if char in "<>"]
    if not terminators:
        result["decode_error"] = "Darwin string has no '<' or '>' terminator"
        return result

    terminator_position, terminator = min(terminators, key=lambda item: item[0])
    feature_name = rest[:terminator_position] or None
    result["feature_name"] = feature_name
    result["has_feature"] = feature_name is not None

    if terminator == "<":
        result["form_number"] = 3 if feature_name else 4
        result["form"] = (
            "product_feature_advertisement" if feature_name else "product_advertisement"
        )
        return result

    component_packed = rest[terminator_position + 1 :][:DARWIN_PACKED_PRODUCT_LENGTH]
    result["component_packed_id"] = component_packed or None
    if not component_packed:
        result["decode_error"] = "Darwin '>' terminator is not followed by a component code"
        return result

    try:
        result["component_id"] = parse_packed_uuid(component_packed)
    except (IndexError, ValueError) as exc:
        result["decode_error"] = f"invalid packed component code: {exc}"
        return result

    result["has_component"] = True
    result["form_number"] = 1 if feature_name else 2
    result["form"] = "product_feature_component" if feature_name else "product_component"
    return result


"""
------------------------------------------------------------------
|     0-7b     |     8-15b     |     16-23b     |     24-31b     |
------------------------------------------------------------------
|              <u_int32> BlockSize == 0x00000314                 |
------------------------------------------------------------------
|            <u_int32> BlockSignature == 0xA0000006              |
------------------------------------------------------------------
|                    <str> DarwinDataAnsi                        |
|                           260 B                                |
------------------------------------------------------------------
|               <unicode_str> DarwinDataUnicode                  |
|                           520 B                                |
------------------------------------------------------------------

DarwinData consists of {Product-Code, Feature Key, Component Code}. It is stored
in a compressed format, e.g. "w_1^VX!!!!!!!!!MKKSkEXCELFiles>tW{~$4Q]c@II=l2xaTO5Z",
which can results into
{91120000-0030-0000-0000-0000000ff1ce}EXCELFiles{0638c49d-bb8b-4cd1-b191-052e8f325736}.

There are four variants according to
https://community.broadcom.com/symantecenterprise/viewdocument/working-with-darwin-descriptors:
1. {compressed product code}{feature name}>{compressed component ID}
2. {compressed product code}>{compressed component ID}
3. {compressed product code}{feature name}<
4. {compressed product code}<

See http://www.laurierhodes.info/?q=node/34 or
https://metadataconsulting.blogspot.com/2019/12/CSharp-Convert-a-GUID-to-a-Darwin-Descriptor-and-back.html
or https://web.archive.org/web/20080323160816/http://support.microsoft.com/kb/243630.
"""


class Darwin(LnkExtraBase):
    def name(self):
        return "DARWIN_BLOCK"

    def darwin_data_ansi(self):
        start = DARWIN_ANSI_START
        end = start + DARWIN_ANSI_SIZE
        binary = self._raw[start:end]
        text = self.text_processor.read_string(binary)
        return text

    def darwin_data_unicode(self):
        start = DARWIN_UNICODE_START
        end = start + DARWIN_UNICODE_SIZE
        binary = self._raw[start:end]
        text = self.text_processor.read_unicode_string(binary)
        return text

    def descriptor(self, encoding="unicode"):
        if encoding.lower() in {"ansi", "ascii"}:
            return decode_darwin_descriptor(self.darwin_data_ansi())
        if encoding.lower() in {"unicode", "utf-16", "wide"}:
            return decode_darwin_descriptor(self.darwin_data_unicode())
        raise ValueError(f"unknown Darwin encoding: {encoding}")

    def ansi_descriptor(self):
        return self.descriptor("ansi")

    def unicode_descriptor(self):
        return self.descriptor("unicode")

    @packed_uuid
    def product_code_id(self):
        data = self.darwin_data_unicode()
        start, end = 0, 20
        text = data[start:end]
        return text

    def feature_name(self):
        data = self.darwin_data_unicode()
        start = 20
        # Search for a termiantor sign which can be either `<` or `>`.
        # None of these characters should be located in a packed GUID.
        # If the character is not found, `find` returns `-1`, i.e. by using max
        # we want to get the one which is present.
        # An absence of both characters leads to an exception.
        terminator = max(data.find(">"), data.find("<"))
        if terminator == start:
            # If the terminator is found but is the same as the start position,
            # there is no feature name.
            return None
        end = terminator
        text = data[start:end]
        return text

    @packed_uuid
    def component_id(self):
        data = self.darwin_data_unicode()
        terminator = data.find(">")
        if terminator == -1:
            # Set the ID to `None` if `terminator` is not found.
            return None
        start = terminator + 1
        text = data[start:]
        return text

    def as_dict(self):
        tmp = super().as_dict()
        tmp["darwin_data_ansi"] = self.darwin_data_ansi()
        tmp["darwin_data_unicode"] = self.darwin_data_unicode()
        tmp["product_code_id"] = self.product_code_id()
        tmp["feature_name"] = self.feature_name()
        tmp["component_id"] = self.component_id()
        return tmp
