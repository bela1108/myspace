"""Offline intake checks for handing YARA rules over to an internal team."""
import hashlib
import pathlib

from plyara.core import Plyara


def _metadata_value(rule, key):
    """Return the first metadata value for key, or None when it is absent."""
    for entry in rule.get('metadata', list()):
        if key in entry:
            return entry[key]
    return None


def rule_identity(rule, source=None):
    """Build the canonical name, tag and scope identity for a parsed rule."""
    identity = {
        'rule_name': rule['rule_name'],
        'tags': sorted(rule.get('tags', list())),
        'scopes': sorted(rule.get('scopes', list())),
    }
    if source is not None:
        identity['source'] = source
    identity['identity_key'] = identity_key(identity)
    identity['identity_fingerprint'] = identity_fingerprint(identity['identity_key'])
    return identity


def identity_key(identity):
    """Return a stable textual key for a canonical rule identity."""
    parts = [identity['rule_name'], ' '.join(identity['scopes']), ' '.join(identity['tags'])]
    if identity.get('source') is not None:
        parts.insert(0, identity['source'])
    return '|'.join(parts)


def identity_fingerprint(value):
    """Return a stable fingerprint for an identity key."""
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def parse_rule_source(source, source_file):
    """Parse one offline ruleset and attach its publication-space label."""
    input_string = pathlib.Path(source_file).read_text(encoding='utf-8')
    rules = Plyara().parse_string(input_string)
    for rule in rules:
        rule['source'] = source
        rule['source_file'] = str(source_file)
    return rules


def _rule_without_intake_fields(rule):
    """Return a parsed rule copy without fields attached only for intake."""
    return {
        key: value for key, value in rule.items()
        if key not in ('source', 'source_file')
    }


def _allows(rule_values, restriction):
    """Check that all rule values are allowed by an optional roster restriction."""
    if not restriction:
        return True
    return set(rule_values).issubset(set(restriction))


def eligible_maintainers(rule, source, maintainers):
    """Return maintainers explicitly allowed to take over a rule."""
    eligible = list()
    identity = rule_identity(rule, source)

    for maintainer in maintainers or list():
        if 'name' not in maintainer:
            raise ValueError('Each maintainer must have a name.')

        allowed_sources = maintainer.get('sources', list())
        if allowed_sources and source not in allowed_sources:
            continue
        if not _allows(identity['scopes'], maintainer.get('scopes', list())):
            continue
        if not _allows(identity['tags'], maintainer.get('tags', list())):
            continue
        eligible.append(maintainer['name'])

    return eligible


def _normalise_known_identities(known_identities):
    """Normalise supported known-identity inputs into an identity registry."""
    if known_identities is None:
        return dict()
    if isinstance(known_identities, dict):
        return dict(known_identities)
    return {entry['identity_key']: entry for entry in known_identities}


def check_rule_identities(identities, known_identities=None):
    """Check canonical rule identities for duplicates and already-taken identities."""
    registry = _normalise_known_identities(known_identities)
    seen = dict()
    conflicts = list()
    registry_hits = list()
    new_identities = list()

    for identity in identities:
        key = identity['identity_key']
        if key in seen:
            conflicts.append({'identity_key': key, 'reason': 'duplicate_in_batch'})
        elif key in registry:
            seen[key] = registry[key]
            registry_hits.append(key)
        else:
            seen[key] = identity
            new_identities.append(key)

    return {
        'conflicts': conflicts,
        'registry_hits': registry_hits,
        'identity_registry': seen,
        'new_identities': new_identities,
    }


def build_rule_handoff_plan(source_files, maintainers=None, known_identities=None):
    """Build an offline handoff plan and pre/post identity mapping for rulesets."""
    parsed_rules = list()
    for source, source_file in source_files.items():
        parsed_rules.extend(parse_rule_source(source, source_file))

    plan = list()
    batch_identities = list()
    for rule in parsed_rules:
        source = rule['source']
        source_file = rule['source_file']
        rule_without_intake_fields = _rule_without_intake_fields(rule)
        pre_identity = rule_identity(rule_without_intake_fields, source)
        post_identity = rule_identity(rule_without_intake_fields)
        allowed_maintainers = eligible_maintainers(
            rule_without_intake_fields, source, maintainers
        )
        batch_identities.append(post_identity)

        plan.append({
            'pre_handoff_identity': pre_identity,
            'post_handoff_identity': post_identity,
            'publication_space': source,
            'source_file': source_file,
            'rule_name': rule['rule_name'],
            'tags': post_identity['tags'],
            'scopes': post_identity['scopes'],
            'author': _metadata_value(rule_without_intake_fields, 'author'),
            'eligible_maintainers': allowed_maintainers,
            'assigned_maintainer': allowed_maintainers[0] if allowed_maintainers else None,
            'status': 'ready' if allowed_maintainers else 'blocked',
        })

    duplicate_check = check_rule_identities(batch_identities, known_identities)
    conflict_keys = {entry['identity_key'] for entry in duplicate_check['conflicts']}
    registry_hit_keys = set(duplicate_check['registry_hits'])
    for entry in plan:
        identity_key = entry['post_handoff_identity']['identity_key']
        if identity_key in conflict_keys:
            entry['status'] = 'conflict'
        elif identity_key in registry_hit_keys:
            entry['status'] = 'registry_hit'

    return {
        'handoff_plan': plan,
        'conflicts': duplicate_check['conflicts'],
        'registry_hits': duplicate_check['registry_hits'],
        'identity_registry': duplicate_check['identity_registry'],
        'new_identities': duplicate_check['new_identities'],
    }
