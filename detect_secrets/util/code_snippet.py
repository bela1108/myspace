import unicodedata
from typing import Any
from typing import Dict
from typing import Generator
from typing import Iterable
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Sequence
from typing import Tuple

from .color import AnsiColor
from .color import colorize
from .color import supports_ansi_colors
from detect_secrets.exceptions import SecretNotFoundOnSpecifiedLineError


# This is deliberately a plain-text token. Callers that want to make the marker
# more visible may colorize it, but the marker itself must never contain source
# text -- it is what we show when a precise source range cannot be trusted.
REDACTED_MARKER = '[REDACTED: secret location could not be verified]'

MASK_CHARACTER = '*'

DEFAULT_TAB_WIDTH = 8


class _Span(NamedTuple):
    start: int
    end: int
    current: bool = False
    ambiguous: bool = False


class _Token:
    __slots__ = ('text', 'width', 'index', 'current', 'marker')

    def __init__(
        self,
        text: str,
        width: int,
        index: Optional[int],
        current: bool = False,
        marker: bool = False,
    ) -> None:
        self.text = text
        self.width = width
        self.index = index
        self.current = current
        self.marker = marker


def get_code_snippet(
    lines: List[str],
    line_number: int,
    lines_of_context: int = 5,
) -> 'CodeSnippet':
    """
    :param lines: an iterator of lines in the file
    :param line_number: line which you want to focus on
    :param lines_of_context: how many lines to display around the line you want
        to focus on.
    """
    target_line_index = line_number - 1
    end_line_index = target_line_index + lines_of_context + 1

    if target_line_index <= lines_of_context:
        start_line_index = 0
    else:
        start_line_index = target_line_index - lines_of_context
        target_line_index = lines_of_context

    return CodeSnippet(
        snippet=lines[start_line_index:end_line_index],
        start_line=start_line_index,
        target_index=target_line_index,
    )


def display_width(text: str, tab_width: int = DEFAULT_TAB_WIDTH) -> int:
    """Return the number of terminal columns occupied by ``text``.

    Tabs are expanded relative to the start of the string. Wide (CJK) and
    full-width characters count as two columns, while combining marks and other
    zero-width code points count as zero.
    """
    column = 0
    for character in text:
        if character == '\t':
            column += tab_width - (column % tab_width)
        else:
            column += character_width(character)

    return column


def character_width(character: str) -> int:
    """Best-effort terminal width for a single code point."""
    if not character:
        return 0

    if character == '\t':
        return 0       # tabs are handled separately, since they are contextual

    category = unicodedata.category(character)
    if category in ('Mn', 'Me', 'Cf') or category.startswith('C'):
        return 0

    return 2 if unicodedata.east_asian_width(character) in ('W', 'F') else 1


def find_secret_occurrences(line: str, secret: Optional[str]) -> List[Tuple[int, int]]:
    """Find all exact, non-overlapping occurrences of ``secret`` in ``line``."""
    if not secret:
        return []

    occurrences: List[Tuple[int, int]] = []
    start = 0
    while True:
        index = line.find(secret, start)
        if index == -1:
            break

        occurrences.append((index, index + len(secret)))
        start = index + max(1, len(secret))

    return occurrences


def _get_value(source: Any, names: Iterable[str]) -> Any:
    if source is None:
        return None

    for name in names:
        if isinstance(source, dict):
            if name in source:
                return source[name]
        elif hasattr(source, name):
            value = getattr(source, name)
            if value is not None:
                return value

    return None


def _coerce_span(value: Any) -> Optional[Tuple[int, int]]:
    if isinstance(value, _Span):
        return value.start, value.end

    if isinstance(value, (tuple, list)) and len(value) >= 2:
        try:
            return int(value[0]), int(value[1])
        except (TypeError, ValueError):
            return None

    if isinstance(value, dict):
        try:
            return int(value['start']), int(value['end'])
        except (KeyError, TypeError, ValueError):
            return None

    return None


def get_declared_secret_span(
    source: Any,
    secret: Optional[str] = None,
) -> Optional[Tuple[int, int]]:
    """Extract a source-string range from a candidate or context object.

    Different callers represent ranges slightly differently, so this accepts a
    handful of conventional names. The returned range is *unvalidated* -- the
    formatter must still check it against the exact line snapshot it is about to
    display.
    """
    for name in (
        'secret_span', 'span', 'secret_range', 'source_span', 'location', 'loc',
        'current_span', 'current_range',
    ):
        value = _get_value(source, (name,))
        span = _coerce_span(value)
        if span is not None:
            return span

    start = _get_value(
        source,
        (
            'secret_start', 'secret_position', 'start', 'start_index',
            'offset', 'secret_offset', 'position', 'column', 'index',
            'char_offset', 'secret_value_start', 'value_start', 'match_start',
            'char_start', 'begin', 'current_start', 'candidate_start',
        ),
    )
    end = _get_value(
        source,
        (
            'secret_end', 'end', 'end_index', 'stop', 'character_end',
            'secret_value_end', 'value_end', 'match_end', 'char_end',
            'finish', 'current_end', 'candidate_end',
        ),
    )

    if isinstance(start, bool):
        return None

    if isinstance(start, int):
        if isinstance(end, int) and not isinstance(end, bool):
            return start, end
        if secret is not None:
            return start, start + len(secret)

    return None


def _validated_span(
    line: str,
    secret: Optional[str],
    declared_span: Optional[Tuple[int, int]],
) -> Optional[_Span]:
    if not secret or declared_span is None:
        return None

    start, end = declared_span
    if start < 0 or end < start or end > len(line):
        return None

    # This is the important part: the offsets are only trusted when they still
    # describe the line snapshot that will be rendered. A file that changed
    # after scanning must not silently shift a redaction range.
    if line[start:end] != secret:
        return None

    return _Span(start=start, end=end, current=True)


def resolve_secret_spans(
    line: str,
    secret: Optional[str],
    declared_span: Optional[Tuple[int, int]] = None,
) -> Tuple[List[_Span], bool]:
    """Resolve the ranges that must be redacted on ``line``.

    :returns: (spans, aligned). ``aligned`` is False when there is a candidate
        value but no trustworthy place for it on the supplied line. In that
        case callers must not render the source line at all.
    """
    if not secret:
        return [], False

    if declared_span is not None:
        span = _validated_span(line, secret, declared_span)
        if span is None:
            return [], False

        # Identical text on the same line is indistinguishable from the
        # reviewer's perspective. Even with a precise current range, every
        # occurrence of that value must be redacted; only the declared one is
        # marked as current.
        other_occurrences = [
            (start, end)
            for start, end in find_secret_occurrences(line, secret)
            if (start, end) != (span.start, span.end)
        ]
        return [span] + [
            _Span(start=start, end=end, current=False)
            for start, end in other_occurrences
        ], True

    occurrences = find_secret_occurrences(line, secret)
    if not occurrences:
        return [], False

    # If the same text occurs more than once and the caller did not give us a
    # precise range, all occurrences are marked as current/ambiguous. We cannot
    # safely pick "the first one": doing so would both highlight the wrong item
    # and leave the real one indistinguishable from an unrelated occurrence.
    ambiguous = len(occurrences) > 1
    return [
        _Span(start=start, end=end, current=True, ambiguous=ambiguous)
        for start, end in occurrences
    ], True


def _add_known_spans(
    line: str,
    spans: List[_Span],
    known_secrets: Sequence[Any],
    current_secret: Any = None,
) -> bool:
    """Add redaction ranges for other findings on the same line.

    :returns: False if a known finding claims this line but its range cannot be
        trusted. The caller should then redact the whole line rather than risk
        displaying it.
    """
    current_value = _get_value(current_secret, ('secret_value', 'secret'))

    for known in known_secrets or ():
        if known is current_secret:
            continue

        value = _get_value(known, ('secret_value', 'secret'))
        if not value:
            continue

        # The current candidate's value is already handled -- including every
        # duplicate occurrence of it.
        if value == current_value:
            continue

        declared = get_declared_secret_span(known, value)
        if declared is not None:
            span = _validated_span(line, value, declared)
            if span is None:
                return False
            spans.append(_Span(start=span.start, end=span.end, current=False))
            continue

        occurrences = find_secret_occurrences(line, value)
        if occurrences:
            spans.extend(
                _Span(start=start, end=end, current=False)
                for start, end in occurrences
            )

    return True


def _line_tokens(line: str, spans: Sequence[_Span], tab_width: int) -> List[_Token]:
    tokens: List[_Token] = []
    column = 0

    for index, character in enumerate(line):
        masked = any(span.start <= index < span.end for span in spans)
        current = masked and any(
            span.current and span.start <= index < span.end
            for span in spans
        )

        if character == '\t':
            width = tab_width - (column % tab_width)
            for _ in range(width):
                tokens.append(_Token(
                    MASK_CHARACTER if masked else ' ',
                    1,
                    index,
                    current=current,
                ))
            column += width
            continue

        width = character_width(character)
        if masked:
            text = MASK_CHARACTER * width
        else:
            text = character

        tokens.append(_Token(text, width, index, current=current))
        column += width

    return tokens


def _insert_current_markers(
    tokens: List[_Token],
    spans: Sequence[_Span],
    use_color: bool,
) -> List[_Token]:
    before: Dict[int, List[str]] = {}
    after: Dict[int, List[str]] = {}

    for span in spans:
        if not span.current:
            continue

        indexes = [
            position for position, token in enumerate(tokens)
            if token.index is not None and span.start <= token.index < span.end
        ]
        if not indexes:
            continue

        start_marker = '['
        end_marker = ']'
        if use_color:
            highlight = '\x1b{}'.format(AnsiColor.RED_BACKGROUND.value)
            reset = '\x1b{}'.format(AnsiColor.RESET.value)
            start_marker = highlight + start_marker
            end_marker = end_marker + reset

        before.setdefault(indexes[0], []).append(start_marker)
        after.setdefault(indexes[-1], []).append(end_marker)

    output: List[_Token] = []
    for position, token in enumerate(tokens):
        for marker in before.get(position, []):
            output.append(_Token(marker, 1, None, current=True, marker=True))
        output.append(token)
        for marker in after.get(position, []):
            output.append(_Token(marker, 1, None, current=True, marker=True))

    return output


def _crop_tokens(tokens: List[_Token], max_width: Optional[int]) -> str:
    if max_width is None or max_width <= 0:
        return ''.join(token.text for token in tokens)

    columns = []
    total_width = 0
    for token in tokens:
        columns.append((total_width, total_width + token.width))
        total_width += token.width

    if total_width <= max_width:
        return ''.join(token.text for token in tokens)

    current_ranges = [
        columns[index]
        for index, token in enumerate(tokens)
        if token.current and not token.marker and token.width
    ]

    start_column = 0
    if current_ranges:
        current_start = min(start for start, _ in current_ranges)
        current_end = max(end for _, end in current_ranges)
        if current_end > max_width:
            start_column = max(0, current_end - max_width)
            # Prefer keeping a little leading context, but never at the expense
            # of cutting off the current (already masked) item.
            start_column = min(
                start_column,
                max(0, current_start - max_width // 3),
            )

    prefix = '...' if start_column > 0 else ''
    visible_budget = max(0, max_width - display_width(prefix))
    end_column = start_column + visible_budget
    suffix = '...' if end_column < total_width else ''
    if suffix:
        visible_budget = max(0, visible_budget - len(suffix))
        end_column = start_column + visible_budget

    rendered = []
    for position, token in enumerate(tokens):
        token_start, token_end = columns[position]
        # Do not render half of a wide character/token. Every masked token is
        # already composed solely of mask characters, so dropping the edge is
        # safe from both an alignment and a disclosure standpoint.
        if token_start < start_column or token_end > end_column:
            continue
        rendered.append(token.text)

    return prefix + ''.join(rendered) + suffix


def render_redacted_line(
    line: str,
    secret: Optional[str] = None,
    *,
    declared_span: Optional[Tuple[int, int]] = None,
    known_secrets: Sequence[Any] = (),
    current_secret: Any = None,
    max_width: Optional[int] = None,
    tab_width: int = DEFAULT_TAB_WIDTH,
    use_color: Optional[bool] = None,
    require_secret: bool = True,
) -> Tuple[str, bool]:
    """Render one line after redacting every known secret range.

    :returns: (rendered line, aligned). If ``aligned`` is False, ``rendered``
        is a marker and the original line must not be shown.
    """
    if secret or require_secret:
        spans, aligned = resolve_secret_spans(line, secret, declared_span)
        if not aligned:
            return REDACTED_MARKER, False
    else:
        spans = []

    if not _add_known_spans(line, spans, known_secrets, current_secret):
        return REDACTED_MARKER, False

    if use_color is None:
        use_color = supports_ansi_colors()

    tokens = _line_tokens(line, spans, tab_width)
    tokens = _insert_current_markers(tokens, spans, bool(use_color))
    rendered = _crop_tokens(tokens, max_width)

    # Cropping can remove the closing highlight marker while keeping the
    # opening one. Always leave the terminal in a reset state in that case.
    if use_color and '\x1b[41m' in rendered and '\x1b[0m' not in rendered:
        rendered += '\x1b[0m'

    return rendered, True


def mask_secret(
    secret: str,
    preserve_width: bool = True,
) -> str:
    """Return a redaction mask for ``secret``.

    By default the mask occupies the same number of terminal columns as the
    original value, so redaction does not move surrounding text around.
    """
    if not secret:
        return ''

    if not preserve_width:
        return MASK_CHARACTER * len(secret)

    return ''.join(
        MASK_CHARACTER * max(0, character_width(character))
        for character in secret
    )


def redact_secret(secret: str) -> str:
    return mask_secret(secret)


class CodeSnippet:

    def __init__(self, snippet: List[str], start_line: int, target_index: int) -> None:
        """
        :param snippet: lines of code extracted from file
        :param start_line: first line number in segment
        :param target_index: index in snippet of target line
        """
        self.lines = snippet
        self.start_line = start_line
        self.target_index = target_index

    @property
    def target_line(self) -> str:
        return self.lines[self.target_index]

    @target_line.setter
    def target_line(self, value: str) -> None:
        self.lines[self.target_index] = value

    @property
    def previous_line(self) -> str:
        if self.target_index == 0 or len(self.lines) < self.target_index:
            return ''
        return self.lines[self.target_index - 1]

    def add_line_numbers(self) -> 'CodeSnippet':
        for index, line in enumerate(self.lines):
            self.lines[index] = u'{}:{}'.format(
                self.get_line_number(self.start_line + index + 1),
                line,
            )

        return self

    def with_line_numbers(self) -> List[str]:
        """Return numbered lines without mutating this object."""
        return [
            u'{}:{}'.format(
                self.get_line_number(self.start_line + index + 1),
                line,
            )
            for index, line in enumerate(self.lines)
        ]

    def highlight_line(self, payload: str, **kwargs: Any) -> 'CodeSnippet':
        """Highlight the target line, masking the highlighted payload.

        Historically this only added ANSI colors; that is not a confidentiality
        boundary (plain-text output and narrow terminals can still reveal the
        value). The default now redacts the matched source range as well.
        """
        try:
            declared_span = kwargs.pop('declared_span', kwargs.pop('span', None))
            start = kwargs.pop('start', None)
            end = kwargs.pop('end', None)
            if declared_span is None and isinstance(start, int) and not isinstance(start, bool):
                declared_span = (start, end if isinstance(end, int) else start + len(payload))

            rendered, aligned = render_redacted_line(
                self.target_line,
                payload,
                declared_span=declared_span,
                known_secrets=kwargs.pop('known_secrets', ()),
                current_secret=kwargs.pop('current_secret', None),
                max_width=kwargs.pop('max_width', kwargs.pop('width', None)),
                tab_width=kwargs.pop('tab_width', DEFAULT_TAB_WIDTH),
                use_color=kwargs.pop('use_color', kwargs.pop('color', None)),
            )
            if not aligned:
                raise SecretNotFoundOnSpecifiedLineError(self.target_index)

            self.target_line = rendered
            return self
        except ValueError:
            raise SecretNotFoundOnSpecifiedLineError(self.target_index)

    def mask_line(self, *args: Any, **kwargs: Any) -> 'CodeSnippet':
        return self.highlight_line(*args, **kwargs)

    def redact_line(self, *args: Any, **kwargs: Any) -> 'CodeSnippet':
        return self.highlight_line(*args, **kwargs)

    def get_line_number(self, line_number: int) -> str:
        """Broken out, for custom colorization."""
        return colorize(str(line_number), AnsiColor.LIGHT_GREEN)

    def apply_highlight(self, payload: str) -> str:
        """Broken out, for custom colorization."""
        return colorize(payload, AnsiColor.RED_BACKGROUND)

    def format(
        self,
        secret: Optional[str] = None,
        *,
        current_secret: Any = None,
        known_secrets: Sequence[Any] = (),
        declared_span: Optional[Tuple[int, int]] = None,
        max_width: Optional[int] = None,
        tab_width: int = DEFAULT_TAB_WIDTH,
        use_color: Optional[bool] = None,
    ) -> str:
        return format_code_snippet(
            self,
            secret=secret,
            current_secret=current_secret,
            known_secrets=known_secrets,
            declared_span=declared_span,
            max_width=max_width,
            tab_width=tab_width,
            use_color=use_color,
        )

    def __str__(self) -> str:
        return '\n'.join(self.lines)

    def __iter__(self) -> Generator[str, None, None]:
        yield from self.lines


def format_code_snippet(
    snippet: CodeSnippet,
    secret: Optional[str] = None,
    *,
    current_secret: Any = None,
    known_secrets: Sequence[Any] = (),
    declared_span: Optional[Tuple[int, int]] = None,
    max_width: Optional[int] = None,
    tab_width: int = DEFAULT_TAB_WIDTH,
    use_color: Optional[bool] = None,
) -> str:
    """Format a snippet without mutating it or falling back to plaintext.

    The source lines are treated as one immutable snapshot: the same strings
    are used to validate source ranges and to render output.
    """
    if current_secret is not None and secret is None:
        secret = _get_value(current_secret, ('secret_value', 'secret'))

    if declared_span is None:
        declared_span = get_declared_secret_span(current_secret, secret)

    known = list(known_secrets or ())

    output: List[str] = []
    for index, line in enumerate(snippet.lines):
        is_target = index == snippet.target_index
        known_for_line = list(known)
        if not is_target and current_secret is not None:
            known_for_line.append(current_secret)

        rendered, aligned = render_redacted_line(
            line,
            secret if is_target else None,
            declared_span=declared_span if is_target else None,
            known_secrets=known_for_line,
            current_secret=current_secret if is_target else None,
            max_width=max_width,
            tab_width=tab_width,
            use_color=use_color,
            require_secret=is_target,
        )

        if is_target and not aligned:
            rendered = REDACTED_MARKER

        output.append(u'{}:{}'.format(
            snippet.get_line_number(snippet.start_line + index + 1),
            rendered,
        ))

    return '\n'.join(output)


# Convenience aliases used by different callers (notably audit and backend
# integrations), while keeping one implementation behind them.
format_snippet = format_code_snippet
format_redacted_snippet = format_code_snippet
format_masked_snippet = format_code_snippet
redact_line = render_redacted_line
mask_line = render_redacted_line


def format_context(context: Any, **kwargs: Any) -> str:
    """Compatibility entry point for backend callers.

    The implementation lives in the audit I/O module so this utility module does
    not need to depend on ``SecretContext`` at import time.
    """
    from ..audit.io import format_context as _format_context

    return _format_context(context, **kwargs)


format_secret_context = format_context
