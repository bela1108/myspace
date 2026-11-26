from io import TextIOBase
from typing import Any
from typing import NamedTuple
from typing import NoReturn
from typing import Optional
from typing import Sequence
from typing import Set

from .core.potential_secret import PotentialSecret
from .exceptions import SecretNotFoundOnSpecifiedLineError
from .util.code_snippet import CodeSnippet


class SelfAwareCallable:
    """
    This distinguishes itself from a normal callable, since it knows things about itself.
    """
    # The import path of the function
    path: str

    # The variable names for its inputs
    injectable_variables: Set[str]

    def __call__(self, *args: Any, **kwargs: Any) -> NoReturn:
        """
        This is needed, since you can't inherit Callable.
        Source: https://stackoverflow.com/a/52654516/13340678
        """
        pass


class SecretContext(NamedTuple):
    # Keeps track of the current secret in the process
    current_index: int
    num_total_secrets: int

    secret: PotentialSecret
    header: Optional[str] = None

    # Either secret context is provided...
    snippet: Optional[CodeSnippet] = None

    # ...or error information. But it has an XOR relationship.
    error: Optional[SecretNotFoundOnSpecifiedLineError] = None

    # Optional context used by backend/UI integrations. These are intentionally
    # additive so older callers can keep constructing SecretContext positionally.
    known_secrets: Sequence[Any] = ()
    line_secrets: Sequence[Any] = ()
    candidates: Sequence[Any] = ()
    all_secrets: Sequence[Any] = ()
    secrets: Sequence[Any] = ()
    known_findings: Sequence[Any] = ()
    findings: Sequence[Any] = ()

    # A validated source-string range for the current candidate, if the caller
    # has one. When omitted, formatting falls back to exact text lookup and
    # refuses to render the line if that lookup is not unambiguous enough.
    secret_span: Optional[Any] = None
    current_span: Optional[Any] = None

    # Display options (also accepted as keyword arguments to format_context).
    max_width: Optional[int] = None
    width: Optional[int] = None
    use_color: Optional[bool] = None
    tab_width: int = 8
    line: Optional[str] = None
    lines: Optional[Sequence[str]] = None
    line_number: Optional[int] = None

    # Some callers name the active item explicitly instead of using `secret`.
    candidate: Optional[PotentialSecret] = None
    current_candidate: Optional[PotentialSecret] = None
    current: Optional[PotentialSecret] = None
    secret_candidate: Optional[PotentialSecret] = None


class NamedIO(TextIOBase):
    name: str
