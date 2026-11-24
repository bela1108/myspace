from __future__ import absolute_import, division, print_function, unicode_literals

from .. import audit_generator
from . import base


class BadAuditGeneratorUseLinter(base.BaseLinter):
    off_by_default = False
    _code = 'DUO139'
    _error_tmpl = 'DUO139 audit generator confirmation lifecycle issue'

    def visit_Module(self, node):
        findings = audit_generator.AuditGeneratorAnalyzer().analyze(node)
        for finding in findings:
            message = '{} [{}] {}'.format(
                self._error_tmpl,
                finding.state,
                self._detail(finding),
            )
            self.results.append(base.Flake8Result(
                lineno=finding.lineno,
                col_offset=finding.col_offset,
                message=message,
            ))
        self.generic_visit(node)

    @staticmethod
    def _detail(finding):
        parts = ['factory={}'.format(finding.factory_name)]
        if finding.confirmation_lineno is not None:
            parts.append('confirmation_line={}'.format(finding.confirmation_lineno))
        if finding.consumer_lineno is not None:
            parts.append('consumer_line={}'.format(finding.consumer_lineno))
        if finding.suppression_lineno is not None:
            parts.append('suppression_line={}'.format(finding.suppression_lineno))
        if finding.wrapper_name is not None:
            parts.append('wrapper={}'.format(finding.wrapper_name))
        return ' '.join(parts)


AuditGeneratorUseLinter = BadAuditGeneratorUseLinter
BadAuditGeneratorCompletionUseLinter = BadAuditGeneratorUseLinter
AuditGeneratorCompletionUseLinter = BadAuditGeneratorUseLinter
