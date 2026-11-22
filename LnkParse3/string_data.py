import struct
import warnings
from struct import unpack

from LnkParse3.text_processor import TextProcessor


"""
STRING_DATA:
Zero or more optional StringData structures (section 2.4), which are used to
convey user interface and path identification information. The presence of
these structures is specified by bits (LinkFlags section 2.1.1) in the
ShellLinkHeader.
"""

# LNK File UI Character Limitation:
# Windows Explorer displays only 260 characters in the 'Target' field for LNK shortcuts,
# while the maximum length for a command line argument is 4096 characters. This technical
# limitation creates a discrepancy between what is visible in the UI and what may be
# present in the complete file. It allows to hide commands by inserting non-printable whitespace
# characters to pad the visible section of the LNK file.


class StringData:
    def __init__(self, lnk_file, indata=None, cp=None, base_offset=0):
        self._raw = indata
        self._data = {}
        self._field_meta = {}

        self._lnk_file = lnk_file
        self.text_processor = TextProcessor(cp=cp)
        self.base_offset = base_offset

        start = 0
        try:
            if self._lnk_file.has_name():
                text, length, meta = self.read_with_meta(
                    self._raw[start:], limit_length=True, field_start=start
                )
                self._data["description"] = text
                self._field_meta["description"] = meta
                start += length

            if self._lnk_file.has_relative_path():
                text, length, meta = self.read_with_meta(
                    self._raw[start:], limit_length=True, field_start=start
                )
                self._data["relative_path"] = text
                self._field_meta["relative_path"] = meta
                start += length

            if self._lnk_file.has_working_dir():
                text, length, meta = self.read_with_meta(
                    self._raw[start:], limit_length=True, field_start=start
                )
                self._data["working_directory"] = text
                self._field_meta["working_directory"] = meta
                start += length

            if self._lnk_file.has_arguments():
                text, length, meta = self.read_with_meta(self._raw[start:], field_start=start)
                self._data["command_line_arguments"] = text
                self._field_meta["command_line_arguments"] = meta
                start += length

            if self._lnk_file.has_icon_location():
                text, length, meta = self.read_with_meta(self._raw[start:], field_start=start)
                self._data["icon_location"] = text
                self._field_meta["icon_location"] = meta
                start += length
        except struct.error as e:
            warnings.warn(f"Error while parsing String data: {e!r}")

        self._size = start

    def size(self):
        return self._size

    def description(self):
        return self._data.get("description")

    def relative_path(self):
        return self._data.get("relative_path")

    def working_directory(self):
        return self._data.get("working_directory")

    def command_line_arguments(self):
        return self._data.get("command_line_arguments")

    def icon_location(self):
        return self._data.get("icon_location")

    def read(self, binary, limit_length=False):
        text, length, _ = self.read_with_meta(binary, limit_length=limit_length)
        return text, length

    def read_with_meta(self, binary, limit_length=False, field_start=0):
        offset = 2
        char_count = unpack("<H", binary[0:offset])[0]
        length = 260 if limit_length and char_count > 260 else char_count

        if self._lnk_file.is_unicode():
            read = self.text_processor.read_unicode_string_with_status
            length *= 2  # UTF-16
            encoding = "utf-16le"
        else:
            read = self.text_processor.read_string_with_status
            encoding = self.text_processor.cp

        payload = binary[offset : offset + length]
        text, status, value_length = read(payload)
        meta = {
            "offset": self.base_offset + field_start + offset,
            "length": value_length,
            "stored_length": length,
            "encoding": encoding,
            "decoding": status,
        }
        return text, offset + length, meta

    def field_meta(self):
        return {name: dict(meta) for name, meta in self._field_meta.items()}

    def as_dict(self):
        return {k: v for k, v in self._data.items() if v is not None}
