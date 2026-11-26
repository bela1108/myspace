from detect_secrets.audit import io
from detect_secrets.types import SecretContext
from detect_secrets.util.code_snippet import REDACTED_MARKER
from detect_secrets.util.code_snippet import get_code_snippet
from testing.factories import potential_secret_factory


def format_line(line, secret, **kwargs):
    return io.format_context(
        SecretContext(
            current_index=1,
            num_total_secrets=1,
            secret=secret,
            snippet=get_code_snippet([line], 1, lines_of_context=0),
        ),
        **kwargs
    )


def test_duplicate_text_is_redacted_but_only_current_is_marked():
    line = 'x=TOKEN; y=TOKEN;'
    output = format_line(
        line,
        potential_secret_factory(secret='TOKEN', secret_span=(11, 16)),
    )

    assert 'TOKEN' not in output
    assert output.count('[') == 1
    assert output.count('*') == 10


def test_other_known_secret_on_the_same_line_is_redacted():
    line = 'a=AAA b=BBB'
    current = potential_secret_factory(secret='AAA')
    other = potential_secret_factory(secret='BBB')
    output = io.format_context(
        SecretContext(
            current_index=1,
            num_total_secrets=2,
            secret=current,
            known_secrets=[current, other],
            snippet=get_code_snippet([line], 1, lines_of_context=0),
        ),
    )

    assert 'AAA' not in output
    assert 'BBB' not in output


def test_mismatched_source_range_does_not_render_source_text():
    secret = potential_secret_factory(secret='OLD', secret_span=(2, 5))
    output = format_line('x=NEW', secret)

    assert 'NEW' not in output
    assert REDACTED_MARKER in output


def test_missing_source_range_does_not_render_source_text():
    secret = potential_secret_factory(secret='whatever')
    secret.secret_value = None
    output = format_line('a=whatever', secret)

    assert 'whatever' not in output
    assert REDACTED_MARKER in output


def test_plain_text_narrow_output_redacts_wide_and_combined_characters():
    for secret, line in (
        ('密码', 'prefix=密码:suffix'),
        ('e\u0301x', 'prefix=e\u0301x:suffix'),
    ):
        for width in (4, 8, 12):
            output = format_line(line, potential_secret_factory(secret=secret), width=width)
            assert secret not in output
            assert '\x1b[' not in output


def test_tabs_are_expanded_before_narrow_cropping():
    line = '\tprefix\tSECRET_VALUE_tail'
    output = format_line(
        line,
        potential_secret_factory(secret='SECRET_VALUE'),
        width=16,
    )

    assert 'SECRET_VALUE' not in output
    assert '\t' not in output


def test_formatting_does_not_mutate_the_snippet_across_candidates():
    snippet = get_code_snippet(['a=FIRST b=SECOND'], 1, lines_of_context=0)
    first = SecretContext(
        current_index=1,
        num_total_secrets=2,
        secret=potential_secret_factory(secret='FIRST'),
        snippet=snippet,
    )
    second = SecretContext(
        current_index=2,
        num_total_secrets=2,
        secret=potential_secret_factory(secret='SECOND'),
        snippet=snippet,
    )

    first_output = io.format_context(first)
    second_output = io.format_context(second)

    assert 'FIRST' not in first_output
    assert 'SECOND' not in second_output
    assert snippet.target_line == 'a=FIRST b=SECOND'
