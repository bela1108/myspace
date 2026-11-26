"""
Responsible for input/output for audit related functions.
"""
import os
import platform
import sys
from enum import Enum
from typing import Any
from typing import Optional
from typing import Sequence

from ..types import SecretContext
from ..util.code_snippet import CodeSnippet
from ..util.code_snippet import DEFAULT_TAB_WIDTH
from ..util.code_snippet import format_code_snippet
from ..util.code_snippet import get_code_snippet
from ..util.code_snippet import get_declared_secret_span
from ..util.code_snippet import mask_secret
from ..util.code_snippet import redact_secret
from ..util.code_snippet import render_redacted_line
from ..util.code_snippet import find_secret_occurrences
from ..util.color import AnsiColor
from ..util.color import colorize


_SECRET_NAMES = (
    'secret', 'current_secret', 'candidate', 'current_candidate',
    'current', 'secret_candidate',
)


def print_message(message: str) -> None:
    print(message)


def print_error(message: str) -> None:
    print(message, file=sys.stderr)


def clear_screen() -> None:     # pragma: no cover
    command = 'clear'
    if platform.system() == 'Windows':
        command = 'cls'
    os.system(command)


def print_context(context: SecretContext) -> None:
    if not context.snippet and _snippet_from_context(context) is None:     # pragma: no cover
        raise ValueError('You should be using `print_secret_not_found` instead.')

    print_message(format_context(context))


def print_secret_not_found(context: SecretContext) -> None:
    if context.snippet:     # pragma: no cover
        raise ValueError(
            'Are you sure you want to do this? The secret *was* found in this context. '
            'If you are certain you want to override this behavior, be sure to null out '
            'the `context.snippet` value.',
        )

    print_message(format_secret_not_found(context))


def format_context(
    context: Any,
    max_width: Optional[int] = None,
    use_color: Optional[bool] = None,
    **kwargs: Any,
) -> str:
    """Return a safe, printable representation of an audit context.

    This is intentionally side-effect free: the same ``CodeSnippet`` object may
    be formatted repeatedly (for example when an interactive reviewer steps
    backwards and forwards), and no mask or line-number decoration is written
    back into it.

    ``max_width`` applies to the source portion of each line (after the line
    number prefix). Long lines are masked *before* they are cropped, so a
    narrow viewport cannot reveal the tail of a secret.
    """
    if isinstance(context, CodeSnippet):
        secret = kwargs.pop('secret', None)
        return format_code_snippet(
            context,
            secret=secret if isinstance(secret, str) else None,
            current_secret=(
                secret if not isinstance(secret, str)
                else kwargs.pop('current_secret', None)
            ),
            known_secrets=_known_secrets(kwargs),
            declared_span=_declared_span(kwargs, secret, context),
            max_width=_max_width(max_width, kwargs),
            tab_width=kwargs.pop('tab_width', DEFAULT_TAB_WIDTH),
            use_color=_use_color(use_color, kwargs),
        )

    snippet = _context_value(context, ('snippet',))
    if snippet is None:
        snippet = _snippet_from_context(context)
    if snippet is None:
        return format_secret_not_found(context, max_width=max_width, use_color=use_color, **kwargs)

    secret = _context_value(context, _SECRET_NAMES)
    secret_value = None
    secret_override = kwargs.pop('secret', kwargs.pop('secret_value', None))
    if isinstance(secret_override, str):
        secret_value = secret_override
    elif secret_override is not None:
        secret = secret_override

    known_secrets = _known_secrets(kwargs, context)
    declared_span = _declared_span(kwargs, context, secret, snippet)

    body = format_code_snippet(
        snippet,
        secret=secret_value,
        current_secret=secret,
        known_secrets=known_secrets,
        declared_span=declared_span,
        max_width=_max_width(max_width, kwargs, context),
        tab_width=kwargs.pop(
            'tab_width',
            _context_value(context, ('tab_width',)) or DEFAULT_TAB_WIDTH,
        ),
        use_color=_use_color(use_color, kwargs, context),
    )

    header = _format_header(context)
    context_header = _context_value(context, ('header',))
    parts = [header]
    if context_header:
        parts.append(str(context_header))
    parts.append(body)
    parts.append('-' * 10)
    return '\n'.join(parts)


def format_secret_not_found(
    context: Any,
    max_width: Optional[int] = None,
    use_color: Optional[bool] = None,
    **kwargs: Any,
) -> str:
    error = _context_value(context, ('error',))
    return '\n'.join([
        _format_header(context),
        str(error),
        '-' * 10,
    ])


def format_snippet(
    context: Any,
    max_width: Optional[int] = None,
    use_color: Optional[bool] = None,
    **kwargs: Any,
) -> str:
    """Format only the snippet portion of an audit context."""
    if isinstance(context, CodeSnippet):
        return format_context(
            context,
            max_width=max_width,
            use_color=use_color,
            **kwargs
        )

    snippet = _context_value(context, ('snippet',))
    if snippet is None:
        snippet = _snippet_from_context(context)
    if snippet is None:
        return ''

    secret = _context_value(context, _SECRET_NAMES)
    return format_code_snippet(
        snippet,
        current_secret=secret,
        known_secrets=_known_secrets(kwargs, context),
        declared_span=_declared_span(kwargs, context, secret, snippet),
        max_width=_max_width(max_width, kwargs, context),
        tab_width=kwargs.pop(
            'tab_width',
            _context_value(context, ('tab_width',)) or DEFAULT_TAB_WIDTH,
        ),
        use_color=_use_color(use_color, kwargs, context),
    )


def _context_value(context: Any, names: Sequence[str]) -> Any:
    for name in names:
        if isinstance(context, dict):
            if name in context and context[name] is not None:
                return context[name]
        elif hasattr(context, name):
            value = getattr(context, name)
            if value is not None:
                return value

    return None


def _snippet_from_context(context: Any) -> Optional[CodeSnippet]:
    lines = _context_value(context, ('lines', 'raw_lines', 'source_lines'))
    line = _context_value(context, ('line', 'source_line', 'target_line'))
    line_number = _context_value(context, ('line_number',)) or 1

    if lines:
        return get_code_snippet(list(lines), int(line_number))

    if line is not None:
        target_index = max(0, int(line_number) - 1)
        return CodeSnippet([str(line)], start_line=target_index, target_index=0)

    return None


def _known_secrets(kwargs: Any, context: Any = None) -> Sequence[Any]:
    for name in (
        'known_secrets', 'line_secrets', 'all_secrets', 'secrets',
        'candidates', 'other_secrets', 'known_findings', 'findings',
    ):
        if name in kwargs and kwargs[name]:
            return _as_sequence(kwargs[name])

        if context is not None:
            value = _context_value(context, (name,))
            if value:
                return _as_sequence(value)

    return ()


def _as_sequence(value: Any) -> Sequence[Any]:
    is_collection = not isinstance(value, (str, bytes, dict)) and hasattr(value, '__iter__')
    if is_collection:
        return list(value)

    return [value]


def _declared_span(kwargs: Any, *sources: Any) -> Any:
    for name in (
        'declared_span', 'secret_span', 'span', 'current_span',
        'secret_range', 'source_span',
    ):
        if name in kwargs and kwargs[name] is not None:
            return kwargs[name]

    for source in sources:
        span = get_declared_secret_span(source)
        if span is not None:
            return span

        if source is not None:
            value = _context_value(source, ('secret_value', 'secret'))
            span = get_declared_secret_span(source, value if isinstance(value, str) else None)
            if span is not None:
                return span

    return None


def _max_width(max_width: Optional[int], kwargs: Any, context: Any = None) -> Optional[int]:
    if max_width is not None:
        return int(max_width)

    for name in (
        'max_width', 'width', 'line_width', 'terminal_width', 'terminal_columns',
        'columns', 'max_line_length', 'line_length',
    ):
        if name in kwargs and kwargs[name] is not None:
            return int(kwargs[name])

        if context is not None:
            value = _context_value(context, (name,))
            if value is not None:
                return int(value)

    return None


def _use_color(
    use_color: Optional[bool],
    kwargs: Any,
    context: Any = None,
) -> Optional[bool]:
    if use_color is not None:
        return bool(use_color)

    if kwargs.pop('plain', False) or kwargs.pop('plain_text', False):
        return False

    if kwargs.pop('no_color', False):
        return False

    for name in ('use_color', 'color', 'colors'):
        if name in kwargs and kwargs[name] is not None:
            return bool(kwargs[name])

        if context is not None:
            value = _context_value(context, (name,))
            if value is not None:
                return bool(value)

    return None


def _format_header(context: Any) -> str:
    secret = _context_value(context, _SECRET_NAMES)
    filename = _context_value(secret, ('filename',))
    secret_type = _context_value(secret, ('type', 'secret_type'))
    current_index = _context_value(context, ('current_index',))
    num_total_secrets = _context_value(context, ('num_total_secrets',))

    return '\n'.join([
        '{secret} {current_count} {of} {total_count}'.format(
            secret=colorize('Secret:     ', AnsiColor.BOLD),
            current_count=colorize(str(current_index), AnsiColor.PURPLE),
            of=colorize('of', AnsiColor.BOLD),
            total_count=colorize(str(num_total_secrets), AnsiColor.PURPLE),
        ),
        '{prefix} {filename}'.format(
            prefix=colorize('Filename:   ', AnsiColor.BOLD),
            filename=colorize(str(filename), AnsiColor.PURPLE),
        ),
        '{prefix} {secret_type}'.format(
            prefix=colorize('Secret Type:', AnsiColor.BOLD),
            secret_type=colorize(str(secret_type), AnsiColor.PURPLE),
        ),
        '-' * 10,
    ])


def _print_header(context: SecretContext) -> None:      # pragma: no cover
    print_message(_format_header(context))

    if context.header:      # pragma: no cover
        print_message(context.header)


def get_user_decision(
    prompt_secret_decision: bool = True,
    can_step_back: bool = False,
) -> 'InputOptions':
    """
    :param prompt_secret_decision: if False, won't ask to label secret.
        e.g. if the secret isn't found on the line
    """
    prompter = UserPrompt(allow_labelling=prompt_secret_decision, allow_backstep=can_step_back)

    user_input = None
    while user_input not in prompter.valid_input:
        if user_input:
            print('Invalid input.')     # type: ignore # Statement unreachable? Come on mypy...

        user_input = input(str(prompter))
        if user_input:
            user_input = user_input[0].upper()

    return InputOptions(user_input)


class InputOptions(Enum):
    YES = 'Y'
    NO = 'N'
    SKIP = 'S'
    BACK = 'B'
    QUIT = 'Q'


class UserPrompt:
    def __init__(self, allow_labelling: bool, allow_backstep: bool) -> None:
        options = []
        if allow_labelling:
            options += [InputOptions.YES, InputOptions.NO]

        options.append(InputOptions.SKIP)
        if allow_backstep:
            options.append(InputOptions.BACK)

        options.append(InputOptions.QUIT)

        self.valid_input = {option.name[0] for option in options}
        self.options = [option.name.lower() for option in options]

    def __str__(self) -> str:
        if 'Y' in self.valid_input:
            output = 'Should this string be committed to the repository?'
        else:
            output = 'What would you like to do?'

        options = ', '.join([f'({option[0]}){option[1:]}' for option in self.options])

        return output + ' ' + options + ': '


# Backend/UI callers use a few different names for the same pure formatter.
format_secret_context = format_context
format_audit_context = format_context
render_context = format_context
format_context_for_terminal = format_context
format_context_for_plaintext = format_context
