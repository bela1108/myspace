"""
Structures of the Shell Link Binary File Format can define strings in
fixed-length fields, strings MUST be null-terminated. If a string is smaller
than the size of the field that contains it, the bytes in the field following
the terminating null character are undefined and can have any value. The
undefined bytes MUST NOT be used.
"""

import warnings


class TextProcessor:
    def __init__(self, cp=None):
        self.cp = cp or "cp1252"

    def read_strings(self, binary):
        chars = []

        def _chars_to_string(lst):
            bin_string = b"".join(lst)
            try:
                string = bin_string.decode(self.cp)
            except UnicodeDecodeError:
                # Fallback to UTF-8 before giving up.
                try:
                    string = bin_string.decode("utf-8")
                except UnicodeDecodeError as e:
                    string = bin_string.decode(self.cp, errors="replace")
                    msg = f"Error while decoding string `{string}` ({e})"
                    warnings.warn(msg)
            yield string

        for char in binary:
            if char == 0x00:
                yield from _chars_to_string(chars)
                chars = []
            else:
                chars.append(bytes([char]))

        yield from _chars_to_string(chars)

    def read_string(self, binary):
        text, _, _ = self.read_string_with_status(binary)
        return text

    def read_string_with_status(self, binary):
        """Read one code-page string and report how certain its decoding is.

        The returned status is one of ``exact``, ``utf8_fallback`` or
        ``replacement``.  A fallback or replacement decoding is deliberately
        distinguishable from an exact decoding so callers can keep uncertain
        values out of material that leaves the evidence system.
        """
        raw = self._first_ansi_string(binary)
        try:
            return raw.decode(self.cp), "exact", len(raw)
        except UnicodeDecodeError:
            # Keep the historical UTF-8 fallback, but do not claim it is
            # certain: the bytes did not decode with the declared code page.
            try:
                return raw.decode("utf-8"), "utf8_fallback", len(raw)
            except UnicodeDecodeError as e:
                string = raw.decode(self.cp, errors="replace")
                msg = f"Error while decoding string `{string}` ({e})"
                warnings.warn(msg)
                return string, "replacement", len(raw)

    def read_unicode_strings(self, binary):
        chars = []

        def _chars_to_string(lst):
            bin_string = b"".join(lst)
            try:
                string = bin_string.decode("utf-16le")
            except UnicodeDecodeError as e:
                string = bin_string.decode("utf-16le", errors="replace")
                msg = f"Error while decoding string `{string}` ({e})"
                warnings.warn(msg)
            yield string

        for char in self._2bytes_each(binary):
            if char == b"\x00\x00":
                yield from _chars_to_string(chars)
                chars = []
            else:
                chars.append(char)

        yield from _chars_to_string(chars)

    def read_unicode_string(self, binary):
        text, _, _ = self.read_unicode_string_with_status(binary)
        return text

    def read_unicode_string_with_status(self, binary):
        """Read one UTF-16LE string and report decoding certainty."""
        raw = self._first_unicode_string(binary)
        try:
            return raw.decode("utf-16le"), "exact", len(raw)
        except UnicodeDecodeError as e:
            string = raw.decode("utf-16le", errors="replace")
            msg = f"Error while decoding string `{string}` ({e})"
            warnings.warn(msg)
            return string, "replacement", len(raw)

    @staticmethod
    def _first_ansi_string(binary):
        end = binary.find(b"\x00")
        if end == -1:
            return binary
        return binary[:end]

    @staticmethod
    def _first_unicode_string(binary):
        for index in range(0, len(binary) - 1, 2):
            if binary[index : index + 2] == b"\x00\x00":
                return binary[:index]
        return binary

    @staticmethod
    def _2bytes_each(binary):
        it = iter(binary)
        while True:
            tmp = None
            try:
                tmp = bytes([next(it)])
                tmp += bytes([next(it)])
                yield tmp
            except StopIteration:
                if tmp:
                    yield tmp
                return None
