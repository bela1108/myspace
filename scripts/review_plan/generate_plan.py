#!/usr/bin/env python3
"""Generate a review assignment plan from an offline detect-secrets baseline.

Produces three kinds of output:
  1. plan_internal.json        - full plan incl. real paths and the reasons a
                                 finding could not be staffed (internal only).
  2. distribution_manifest.json - external hand-off for the distribution
                                 program: opaque seat tokens mapped to
                                 candidate IDs and evidence aliases only.
  3. seats/<SEAT>.json          - one file per seat containing only the
                                 materials assigned to that seat.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path


ALIAS_DOMAIN = 'review-plan-evidence-alias-v1'


def load_json(path):
    with open(path) as f:
        return json.load(f)


def build_findings(baseline):
    """Flatten baseline results into deterministically ordered candidates."""
    findings = []
    for filename in sorted(baseline['results']):
        secrets = sorted(
            baseline['results'][filename],
            key=lambda item: (item['line_number'], item['hashed_secret']),
        )
        for secret in secrets:
            findings.append({
                'candidate_id': 'FND-{:03d}'.format(len(findings) + 1),
                'filename': filename,
                'line_number': secret['line_number'],
                'type': secret['type'],
                'hashed_secret': secret['hashed_secret'],
            })
    return findings


def is_test_path(filename, test_path_prefixes):
    return any(filename.startswith(prefix) for prefix in test_path_prefixes)


def evidence_alias(candidate_id, filename, hashed_secret):
    """One-way alias so external lists never expose paths or secret hashes."""
    payload = '|'.join([ALIAS_DOMAIN, candidate_id, filename, hashed_secret])
    return 'EVID-' + hashlib.sha256(payload.encode()).hexdigest()[:12]


def disqualification_reason(reviewer, finding, roster, active_substitutes):
    """Return None if the reviewer may take a seat on this finding."""
    reviewer_id = reviewer['id']
    if reviewer.get('absent'):
        note = reviewer.get('absence_note', 'unavailable')
        return 'absent ({})'.format(note)

    covered = reviewer.get('substitute_for', [])
    if covered and reviewer_id not in active_substitutes:
        return 'substitute not activated (primary reviewer present)'

    if finding['filename'] in reviewer.get('recent_authored_paths', []):
        return 'recent author of {}'.format(finding['filename'])

    if (
        is_test_path(finding['filename'], roster['test_path_prefixes'])
        and not reviewer.get('clearance', {}).get('test_paths', False)
    ):
        if covered:
            return 'substitute boundary: no test-department clearance'
        return 'lacks test-department clearance'

    return None


def assign_findings(findings, roster):
    """Greedily staff each finding, least-loaded qualified reviewer first."""
    required = roster.get('required_seats_per_finding', 2)
    absent_ids = {r['id'] for r in roster['reviewers'] if r.get('absent')}
    active_substitutes = {
        r['id']
        for r in roster['reviewers']
        if any(primary in absent_ids for primary in r.get('substitute_for', []))
    }

    load = {r['id']: 0 for r in roster['reviewers']}
    assignments = []
    unassigned = []

    for finding in findings:
        qualified = []
        explanations = []
        for reviewer in roster['reviewers']:
            reason = disqualification_reason(
                reviewer, finding, roster, active_substitutes,
            )
            if reason is None:
                qualified.append(reviewer['id'])
            else:
                explanations.append('{}: {}'.format(reviewer['id'], reason))

        qualified.sort(key=lambda rid: (load[rid], rid))
        chosen = qualified[:required]

        if len(chosen) < required:
            unassigned.append({
                'candidate_id': finding['candidate_id'],
                'filename': finding['filename'],
                'line_number': finding['line_number'],
                'type': finding['type'],
                'seats_filled': len(chosen),
                'seats_required': required,
                'explanations': explanations,
            })
            continue

        for reviewer_id in chosen:
            load[reviewer_id] += 1
        assignments.append({
            'candidate_id': finding['candidate_id'],
            'filename': finding['filename'],
            'line_number': finding['line_number'],
            'type': finding['type'],
            'reviewers': chosen,
        })

    return assignments, unassigned


def build_outputs(assignments, unassigned, findings, roster):
    findings_by_id = {f['candidate_id']: f for f in findings}

    seated_reviewers = sorted({
        reviewer_id
        for assignment in assignments
        for reviewer_id in assignment['reviewers']
    })
    seat_tokens = {
        reviewer_id: 'SEAT-{:03d}'.format(index + 1)
        for index, reviewer_id in enumerate(seated_reviewers)
    }

    manifest = {'seats': {}}
    seat_files = {}
    for reviewer_id, token in seat_tokens.items():
        items = [
            {
                'candidate_id': assignment['candidate_id'],
                'evidence_alias': evidence_alias(
                    assignment['candidate_id'],
                    assignment['filename'],
                    findings_by_id[assignment['candidate_id']]['hashed_secret'],
                ),
            }
            for assignment in assignments
            if reviewer_id in assignment['reviewers']
        ]
        manifest['seats'][token] = items
        seat_files[token] = {'seat': token, 'items': items}

    internal = {
        'required_seats_per_finding': roster.get('required_seats_per_finding', 2),
        'seat_directory': {token: rid for rid, token in seat_tokens.items()},
        'assignments': [
            {
                **assignment,
                'seats': [seat_tokens[rid] for rid in assignment['reviewers']],
            }
            for assignment in assignments
        ],
        'unassigned': unassigned,
    }
    return internal, manifest, seat_files


def write_outputs(output_dir, internal, manifest, seat_files):
    output_dir.mkdir(parents=True, exist_ok=True)
    seats_dir = output_dir / 'seats'
    seats_dir.mkdir(exist_ok=True)

    def dump(path, payload):
        with open(path, 'w') as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write('\n')

    dump(output_dir / 'plan_internal.json', internal)
    dump(output_dir / 'distribution_manifest.json', manifest)
    for token, payload in seat_files.items():
        dump(seats_dir / '{}.json'.format(token), payload)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, help='offline baseline JSON')
    parser.add_argument('--roster', required=True, help='reviewer roster JSON')
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args(argv)

    baseline = load_json(args.baseline)
    roster = load_json(args.roster)

    findings = build_findings(baseline)
    assignments, unassigned = assign_findings(findings, roster)
    internal, manifest, seat_files = build_outputs(
        assignments, unassigned, findings, roster,
    )
    write_outputs(Path(args.output_dir), internal, manifest, seat_files)

    print('candidates: {}'.format(len(findings)))
    print('assigned:   {}'.format(len(assignments)))
    print('unassigned: {}'.format(len(unassigned)))
    for entry in unassigned:
        print(
            '  {candidate_id} ({filename}): filled {seats_filled}/'
            '{seats_required} seats'.format(**entry),
        )
    return 0


if __name__ == '__main__':
    sys.exit(main())
