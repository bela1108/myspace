"""
The audit module allows analysts to easily scan the baseline, and verify whether
the secrets flagged are actually secrets.
"""
from typing import Any
from typing import List

from . import io
from ..core import baseline
from ..exceptions import NoLineNumberError
from ..exceptions import SecretNotFoundOnSpecifiedLineError
from ..types import SecretContext
from ..util.code_snippet import get_code_snippet
from .common import get_baseline_from_file
from .common import get_raw_secret_from_file
from .common import open_file
from .iterator import BidirectionalIterator
from .iterator import get_secret_iterator


def audit_baseline(filename: str) -> None:
    """
    :raises: InvalidBaselineError
    """
    secrets = get_baseline_from_file(filename)

    secrets.trim()
    if _classify_secrets(get_secret_iterator(secrets), secrets):
        io.print_message('Saving progress...')
        baseline.save_to_file(secrets, filename)


def _classify_secrets(iterator: BidirectionalIterator, collection: Any = None) -> bool:
    """
    :returns: True if changes were made.
    """
    # NOTE: Technically, this is a conservative estimate. If an entry was changed to the same
    # value, we would return True as well.
    has_changes = False

    for secret in iterator:
        try:
            # Use one LineGetter for both locating the value and rendering the
            # snippet. This prevents a mid-review file change from producing a
            # value/range decision based on one snapshot and a display based on
            # another.
            line_getter = open_file(secret.filename)
            secret.secret_value = get_raw_secret_from_file(
                secret,
                line_getter_factory=lambda filename: line_getter,
            )
            known_secrets = _get_secrets_on_same_line(collection, secret)
            io.clear_screen()
            io.print_context(
                SecretContext(
                    current_index=iterator.index + 1,
                    num_total_secrets=len(iterator.collection),
                    secret=secret,
                    known_secrets=known_secrets,
                    snippet=get_code_snippet(
                        lines=line_getter.raw_lines,
                        line_number=secret.line_number,
                    ),
                ),
            )

            decision = io.get_user_decision(can_step_back=iterator.can_step_back())
        except SecretNotFoundOnSpecifiedLineError as e:
            io.clear_screen()
            io.print_secret_not_found(
                SecretContext(
                    current_index=iterator.index + 1,
                    num_total_secrets=len(iterator.collection),
                    secret=secret,
                    error=e,
                ),
            )

            decision = io.get_user_decision(
                prompt_secret_decision=False,
                can_step_back=iterator.can_step_back(),
            )
        except NoLineNumberError as e:
            io.print_error(str(e))
            break

        if decision == io.InputOptions.QUIT:
            io.print_message('Quitting...')
            break

        if decision == io.InputOptions.BACK:
            iterator.step_back_on_next_iteration()

        # The question asked is: "Should this string be committed to the repository?"
        elif decision == io.InputOptions.NO:
            secret.is_secret = True
            has_changes = True
        elif decision == io.InputOptions.YES:
            secret.is_secret = False
            has_changes = True
        elif decision == io.InputOptions.SKIP and secret.is_secret is not None:
            # This handles the case of back-stepping to clear a mistake.
            # This is not triggered for pre-labelled secrets, as pre-labelled secrets will be
            # excluded from this iterator.
            secret.is_secret = None
            has_changes = True

    return has_changes


def _get_secrets_on_same_line(collection: Any, secret: Any) -> List[Any]:
    """Return all known findings sharing this file/line, for redaction."""
    if collection is None:
        return [secret]

    try:
        candidates = collection[secret.filename]
    except (AttributeError, KeyError, TypeError):     # pragma: no cover
        return [secret]

    return [
        candidate
        for candidate in candidates
        if candidate.filename == secret.filename
        if candidate.line_number == secret.line_number
    ]
