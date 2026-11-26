# coding: utf-8
"""
Reporting and side-by-side comparison of two reviewed certificate batches.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from .review import (
    FINDING_DUPLICATE_FRIENDLY_NAME,
    FINDING_NO_CONFIRMABLE_CHAIN,
    FINDING_UNAUTHORIZED_USAGE,
    review_archive,
)


_FINDING_TITLES = {
    FINDING_DUPLICATE_FRIENDLY_NAME: 'Duplicate friendly name',
    FINDING_NO_CONFIRMABLE_CHAIN: 'No confirmable chain',
    FINDING_UNAUTHORIZED_USAGE: 'Unauthorized usage',
}


def build_report(archive, manifest, verify_signatures=True):
    review = review_archive(archive, manifest, verify_signatures)
    review['manifest'] = manifest.as_dict()
    return review


def build_comparison(review_a, review_b):
    """
    Compare two review results and decide which archive's public material is
    complete enough for handover.
    """
    ready = []
    for review in (review_a, review_b):
        if review['summary']['ready_for_handover']:
            ready.append(review['source'])

    if len(ready) == 1:
        verdict = 'one_ready'
    elif len(ready) == 2:
        verdict = 'both_ready'
    else:
        verdict = 'none_ready'

    def difference(review):
        summary = review['summary']
        return {
            'source': review['source'],
            'ready_for_handover': summary['ready_for_handover'],
            'distinct_certificates': review['inventory']['distinct_certificates'],
            'leaf_count': summary['leaf_count'],
            'confirmable_chain_count': summary['confirmable_chain_count'],
            'approved_leaf_count': summary['approved_leaf_count'],
            'private_key_material_present': summary['private_key_material_present'],
            'findings': {
                FINDING_DUPLICATE_FRIENDLY_NAME: summary['duplicate_friendly_name_count'],
                FINDING_NO_CONFIRMABLE_CHAIN: summary['no_confirmable_chain_count'],
                FINDING_UNAUTHORIZED_USAGE: summary['unauthorized_usage_count'],
            },
        }

    return {
        'verdict': verdict,
        'ready_sources': ready,
        'archives': [difference(review_a), difference(review_b)],
        'shared_leaf_fingerprints': sorted(
            set(leaf['fingerprint_sha256'] for leaf in review_a['leaves'])
            & set(leaf['fingerprint_sha256'] for leaf in review_b['leaves'])
        ),
    }


def _render_archive(review, indent=''):
    lines = []
    summary = review['summary']
    lines.append('%sArchive: %s' % (indent, review['source']))
    lines.append('%s  distinct certificates : %d' % (
        indent, review['inventory']['distinct_certificates']))
    lines.append('%s  leaf certificates      : %d' % (indent, summary['leaf_count']))
    lines.append('%s  confirmable chains     : %d/%d' % (
        indent, summary['confirmable_chain_count'], summary['leaf_count']))
    lines.append('%s  approved leaves        : %d/%d' % (
        indent, summary['approved_leaf_count'], summary['leaf_count']))
    lines.append('%s  key bags (not exported): %d plain, %d shrouded, %d opaque safe(s)' % (
        indent,
        review['inventory']['key_bags'],
        review['inventory']['shrouded_key_bags'],
        review['inventory']['encrypted_safe_contents'],
    ))
    lines.append('%s  handover ready         : %s' % (indent, summary['ready_for_handover']))

    if review['leaves']:
        lines.append('%s  leaves:' % indent)
        for leaf in review['leaves']:
            chain = leaf['chain']
            chain_text = 'confirmed' if chain['confirmed'] else 'unconfirmed (%s)' % chain['reason']
            lines.append('%s    - %s' % (indent, leaf['subject']))
            lines.append('%s      sha256     : %s' % (indent, leaf['fingerprint_sha256']))
            lines.append('%s      chain      : %s, depth %d' % (
                indent, chain_text, len(chain['path'])))
            lines.append('%s      eku        : %s' % (
                indent, ', '.join(leaf['extended_key_usages']) or '(none)'))
            lines.append('%s      authorized : %s%s' % (
                indent,
                'yes (%s)' % ', '.join(leaf['granted_usage']) if leaf['approved'] else 'no',
                ' [' + '; '.join(leaf['approval_notes']) + ']' if leaf['approval_notes'] else '',
            ))

    if review['findings']:
        lines.append('%s  retained findings:' % indent)
        for finding in review['findings']:
            title = _FINDING_TITLES.get(finding['type'], finding['type'])
            if finding['type'] == FINDING_DUPLICATE_FRIENDLY_NAME:
                detail = '"%s" -> %d cert(s)' % (
                    finding['friendly_name'], len(finding['certificates']))
            elif finding['type'] == FINDING_NO_CONFIRMABLE_CHAIN:
                detail = '%s (%s)' % (finding['subject'], finding['reason'])
            else:
                detail = '%s (%s)' % (finding['subject'], '; '.join(finding['reasons']))
            lines.append('%s    - %s: %s' % (indent, title, detail))
    return lines


def render_text(review_a, review_b=None, comparison=None):
    lines = []
    lines.append('Certificate archive handover review')
    lines.append('===================================')
    reviews = [review_a]
    if review_b is not None:
        reviews.append(review_b)
    for review in reviews:
        lines.extend(_render_archive(review))
        lines.append('')

    if comparison is not None:
        lines.append('Comparison')
        lines.append('----------')
        if comparison['verdict'] == 'one_ready':
            lines.append(
                'Complete public handover material is present in: %s' % comparison['ready_sources'][0]
            )
        elif comparison['verdict'] == 'both_ready':
            lines.append('Both archives contain complete public handover material.')
        else:
            lines.append('Neither archive contains complete public handover material.')

        for entry in comparison['archives']:
            lines.append(
                ' - %s: ready=%s, chains %d/%d, approved %d/%d, duplicate names=%d, '
                'unconfirmed=%d, unauthorized=%d' % (
                    entry['source'],
                    entry['ready_for_handover'],
                    entry['confirmable_chain_count'],
                    entry['leaf_count'],
                    entry['approved_leaf_count'],
                    entry['leaf_count'],
                    entry['findings'][FINDING_DUPLICATE_FRIENDLY_NAME],
                    entry['findings'][FINDING_NO_CONFIRMABLE_CHAIN],
                    entry['findings'][FINDING_UNAUTHORIZED_USAGE],
                )
            )
    return '\n'.join(lines)
