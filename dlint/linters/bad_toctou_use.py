from __future__ import absolute_import

from ..toctou import analyze, SAFE
from . import base


class BadTOCTOUUseLinter(base.BaseLinter):
    off_by_default = False
    _code = 'DUO139'
    _error_tmpl = 'DUO139 possible TOCTOU between path check and file use'

    def visit_Module(self, node):
        report = analyze(node)
        seen = set()
        for diagnostic in report:
            if diagnostic.status == SAFE:
                continue
            for location in (diagnostic.check_location, diagnostic.use_location):
                key = (location.line, location.column)
                if key in seen:
                    continue
                seen.add(key)
                self.results.append(base.Flake8Result(
                    lineno=location.line,
                    col_offset=location.column,
                    message=self._error_tmpl,
                ))


BadToctouUseLinter = BadTOCTOUUseLinter
BadOpenSafeUseLinter = BadTOCTOUUseLinter
BadTOCTOUOpenSafeUseLinter = BadTOCTOUUseLinter
