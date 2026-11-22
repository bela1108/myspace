"""
Resumable, offline scanning for individual files.

Checkpoints are intentionally small and non-sensitive. They contain only:

* a schema version,
* verification metadata for the input file (size and a bounded content digest),
* a fingerprint of the active scan settings, and
* cursor progress (source byte offset, next line number, result log offset).

They never contain source content, transformed lines, or matched secret values.
Results, when requested, are kept in a separate append-only result log so that a
checkpoint can be committed after the results it describes are durable.
"""

import hashlib
import json
import locale
import os
import tempfile
from dataclasses import dataclass
from dataclasses import replace
from typing import Any
from typing import BinaryIO
from typing import Callable
from typing import Dict
from typing import Generator
from typing import Iterable
from typing import Iterator
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import cast

from ..exceptions import CheckpointInvalidError
from ..exceptions import SimulatedCheckpointInterruption
from ..settings import get_plugins
from ..settings import get_settings
from ..transformers import get_transformed_file
from ..types import NamedIO
from ..util.code_snippet import CodeSnippet
from .log import log
from .potential_secret import PotentialSecret
from .scan import _is_filtered_out
from .scan import _scan_line


CHECKPOINT_VERSION = 1
DEFAULT_BATCH_SIZE = 1024 * 1024
CONTEXT_LINES = 5

PHASE_PRIMARY = 'primary'
PHASE_EAGER = 'eager'
PHASE_COMPLETE = 'complete'

MODE_RAW = 'raw'
MODE_TRANSFORMED = 'transformed'
MODE_EAGER = 'eager'

REASON_CORRUPT = 'checkpoint_corrupt'
REASON_VERSION_MISMATCH = 'checkpoint_version_mismatch'
REASON_SOURCE_MISSING = 'source_missing'
REASON_SOURCE_UNREADABLE = 'source_unreadable'
REASON_SOURCE_CHANGED = 'source_changed'
REASON_SETTINGS_CHANGED = 'settings_changed'
REASON_RESULT_LOG_MISSING = 'result_log_missing'
REASON_RESULT_LOG_CHANGED = 'result_log_changed'
REASON_RESULT_LOG_CORRUPT = 'result_log_corrupt'


class CheckpointInvalidationReason:
    """Named constants for CheckpointInvalidError.reason values."""

    CORRUPT = REASON_CORRUPT
    VERSION_MISMATCH = REASON_VERSION_MISMATCH
    SOURCE_MISSING = REASON_SOURCE_MISSING
    SOURCE_UNREADABLE = REASON_SOURCE_UNREADABLE
    SOURCE_CHANGED = REASON_SOURCE_CHANGED
    SETTINGS_CHANGED = REASON_SETTINGS_CHANGED
    RESULT_LOG_MISSING = REASON_RESULT_LOG_MISSING
    RESULT_LOG_CHANGED = REASON_RESULT_LOG_CHANGED
    RESULT_LOG_CORRUPT = REASON_RESULT_LOG_CORRUPT


InvalidationReason = CheckpointInvalidationReason

# This is a bound on how much input is read to verify a checkpoint on resume.
# For small files (the common case for config files) this covers the entire
# file. For large files, evenly spaced samples catch in-place edits without
# re-reading the scanned prefix.
_DIGEST_BLOCK_BYTES = 8 * 1024
_DIGEST_BLOCK_COUNT = 8
_READ_BACK_CHUNK_BYTES = 4096

CheckpointHook = Callable[['ScanCheckpoint'], None]


def _get_encoding() -> str:
    return locale.getpreferredencoding(False) or 'utf-8'


def _sample_digest(filename: str, size: int) -> str:
    digest = hashlib.sha256()
    digest.update(str(size).encode('ascii'))

    with open(filename, 'rb') as f:
        sample_budget = _DIGEST_BLOCK_BYTES * _DIGEST_BLOCK_COUNT
        if size <= sample_budget:
            digest.update(f.read())
        else:
            last_offset = size - _DIGEST_BLOCK_BYTES
            for index in range(_DIGEST_BLOCK_COUNT):
                offset = last_offset * index // (_DIGEST_BLOCK_COUNT - 1)
                f.seek(offset)
                digest.update(f.read(_DIGEST_BLOCK_BYTES))

    return digest.hexdigest()


@dataclass(frozen=True)
class SourceFingerprint:
    """Non-sensitive verification information for the scanned input."""

    path: str
    size: int
    mtime_ns: int
    ctime_ns: int
    inode: int
    digest: str

    @classmethod
    def from_path(cls, filename: str) -> 'SourceFingerprint':
        path = os.path.realpath(filename)
        stat = os.stat(path)
        if not os.path.isfile(path):
            raise IsADirectoryError(path)

        return cls(
            path=path,
            size=stat.st_size,
            mtime_ns=getattr(stat, 'st_mtime_ns', int(stat.st_mtime * 1e9)),
            ctime_ns=getattr(stat, 'st_ctime_ns', int(stat.st_ctime * 1e9)),
            inode=getattr(stat, 'st_ino', 0),
            digest=_sample_digest(path, stat.st_size),
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SourceFingerprint':
        return cls(
            path=str(data['path']),
            size=int(data['size']),
            mtime_ns=int(data.get('mtime_ns', 0)),
            ctime_ns=int(data.get('ctime_ns', 0)),
            inode=int(data.get('inode', 0)),
            digest=str(data['digest']),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            'path': self.path,
            'size': self.size,
            'mtime_ns': self.mtime_ns,
            'ctime_ns': self.ctime_ns,
            'inode': self.inode,
            'digest': self.digest,
        }


@dataclass
class ScanCursor:
    """Progress only: no source content or matched values belong here."""

    # Byte offset of the next line to scan. Always a line boundary.
    offset: int = 0

    # 1-based line number of the next line to scan.
    line_number: int = 1

    # Byte offset in the append-only result log that is known to be durable.
    output_offset: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanCursor':
        return cls(
            offset=int(data.get('offset', 0)),
            line_number=int(data.get('line_number', 1)),
            output_offset=int(data.get('output_offset', 0)),
        )

    def to_dict(self) -> Dict[str, int]:
        return {
            'offset': self.offset,
            'line_number': self.line_number,
            'output_offset': self.output_offset,
        }


@dataclass
class ScanCheckpoint:
    """Serializable state for one resumable file scan."""

    source: SourceFingerprint
    settings: str
    cursor: ScanCursor
    version: int = CHECKPOINT_VERSION
    phase: str = PHASE_PRIMARY
    mode: Optional[str] = None
    found_any: bool = False
    result_path: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanCheckpoint':
        if not isinstance(data, dict):
            raise ValueError('Checkpoint must be a JSON object.')

        return cls(
            source=SourceFingerprint.from_dict(data['source']),
            settings=str(data['settings']),
            cursor=ScanCursor.from_dict(data['cursor']),
            version=int(data['version']),
            phase=str(data.get('phase', PHASE_PRIMARY)),
            mode=data.get('mode'),
            found_any=bool(data.get('found_any', False)),
            result_path=data.get('result_path'),
        )

    @property
    def source_fingerprint(self) -> SourceFingerprint:
        return self.source

    @property
    def settings_fingerprint(self) -> str:
        return self.settings

    def to_dict(self) -> Dict[str, Any]:
        return {
            'version': self.version,
            'source': self.source.to_dict(),
            'settings': self.settings,
            'cursor': self.cursor.to_dict(),
            'phase': self.phase,
            'mode': self.mode,
            'found_any': self.found_any,
            'result_path': self.result_path,
        }


def get_settings_fingerprint() -> str:
    """A stable fingerprint of plugins and filters, without any scan results."""
    payload = json.dumps(
        get_settings().json(),
        sort_keys=True,
        separators=(',', ':'),
        default=str,
    )
    return 'sha256:' + hashlib.sha256(payload.encode('utf-8')).hexdigest()


def load_checkpoint(filename: str) -> Optional[ScanCheckpoint]:
    """
    Load a checkpoint, or return ``None`` if it does not exist.

    :raises: CheckpointInvalidError if the checkpoint is unreadable or corrupt.
    """
    if not os.path.exists(filename):
        return None

    try:
        with open(filename, encoding='utf-8') as f:
            payload = json.load(f)
    except (OSError, ValueError) as e:
        raise CheckpointInvalidError(
            REASON_CORRUPT,
            f'Unable to read checkpoint {filename}: {e}',
        )

    try:
        checkpoint = ScanCheckpoint.from_dict(payload)
    except (KeyError, TypeError, ValueError) as e:
        raise CheckpointInvalidError(
            REASON_CORRUPT,
            f'Invalid checkpoint {filename}: {e}',
        )

    if checkpoint.version != CHECKPOINT_VERSION:
        raise CheckpointInvalidError(
            REASON_VERSION_MISMATCH,
            'Checkpoint version {} is not supported (expected {}).'.format(
                checkpoint.version,
                CHECKPOINT_VERSION,
            ),
            version=checkpoint.version,
            expected=CHECKPOINT_VERSION,
        )

    return checkpoint


def save_checkpoint(filename: str, checkpoint: ScanCheckpoint) -> None:
    """Atomically persist a checkpoint. No content or matches are included."""
    directory = os.path.dirname(os.path.abspath(filename))
    os.makedirs(directory, exist_ok=True)

    payload = json.dumps(
        checkpoint.to_dict(),
        sort_keys=True,
        indent=2,
    ) + '\n'

    descriptor, temporary_filename = tempfile.mkstemp(
        prefix='.detect-secrets-checkpoint-',
        dir=directory,
    )
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())

        os.replace(temporary_filename, filename)
    except BaseException:
        try:
            os.unlink(temporary_filename)
        except OSError:
            pass
        raise


# Common alternate names, kept explicit so callers can use either vocabulary.
read_checkpoint = load_checkpoint
write_checkpoint = save_checkpoint


def validate_checkpoint(
    checkpoint: ScanCheckpoint,
    filename: str,
    settings_fingerprint: Optional[str] = None,
) -> None:
    """
    Ensure a checkpoint still describes the requested input and settings.

    :raises: CheckpointInvalidError with a machine-readable ``reason``.
    """
    try:
        current_source = SourceFingerprint.from_path(filename)
    except FileNotFoundError:
        raise CheckpointInvalidError(
            REASON_SOURCE_MISSING,
            f'Source file no longer exists: {filename}',
        )
    except (OSError, IsADirectoryError) as e:
        raise CheckpointInvalidError(
            REASON_SOURCE_UNREADABLE,
            f'Unable to read source file {filename}: {e}',
        )

    if (
        current_source.path != checkpoint.source.path
        or current_source.size != checkpoint.source.size
        or current_source.digest != checkpoint.source.digest
    ):
        raise CheckpointInvalidError(
            REASON_SOURCE_CHANGED,
            'Source file changed since the checkpoint was written.',
            expected_path=checkpoint.source.path,
            actual_path=current_source.path,
        )

    current_settings = settings_fingerprint or get_settings_fingerprint()
    if current_settings != checkpoint.settings:
        raise CheckpointInvalidError(
            REASON_SETTINGS_CHANGED,
            'Scan settings changed since the checkpoint was written.',
        )


def get_checkpoint_invalidation_reason(
    checkpoint_filename: str,
    source_filename: str,
    settings_fingerprint: Optional[str] = None,
) -> Optional[str]:
    """
    Return ``None`` for a usable cursor, or the reason it cannot be resumed.

    This is a non-throwing companion to :func:`validate_checkpoint`.
    """
    try:
        checkpoint = load_checkpoint(checkpoint_filename)
        if checkpoint is None:
            return None

        validate_checkpoint(checkpoint, source_filename, settings_fingerprint)
    except CheckpointInvalidError as e:
        return e.reason

    return None


def _decode_line(raw: bytes) -> str:
    line = raw.decode(_get_encoding())
    return line.replace('\r\n', '\n').replace('\r', '\n')


def _read_previous_lines(filename: str, offset: int, count: int) -> List[str]:
    """
    Read up to ``count`` complete lines immediately before ``offset``.

    The read is bounded, so resuming does not require re-reading the prefix.
    """
    if offset <= 0 or count <= 0:
        return []

    with open(filename, 'rb') as f:
        position = offset
        data = b''
        while position > 0 and data.count(b'\n') <= count:
            step = min(_READ_BACK_CHUNK_BYTES, position)
            position -= step
            f.seek(position)
            data = f.read(step) + data

    raw_lines = data.splitlines(keepends=True)
    return [_decode_line(line) for line in raw_lines[-count:]]


def _get_code_snippet_window(
    lines: Sequence[str],
    start_line: int,
    line_number: int,
) -> CodeSnippet:
    """Build the same snippet ``get_code_snippet`` would build for a full file."""
    target_index = line_number - start_line
    snippet_start = max(0, target_index - CONTEXT_LINES)
    snippet_end = min(len(lines), target_index + CONTEXT_LINES + 1)

    return CodeSnippet(
        snippet=list(lines[snippet_start:snippet_end]),
        start_line=start_line - 1 + snippet_start,
        target_index=target_index - snippet_start,
    )


def _process_lines(
    target_lines: Sequence[Tuple[int, str]],
    window: Sequence[str],
    window_start_line: int,
    filename: str,
) -> Generator[PotentialSecret, None, None]:
    for line_number, line in target_lines:
        log.debug(f'Processing {filename}:{line_number}')
        stripped_line = line.rstrip()
        code_snippet = _get_code_snippet_window(
            lines=window,
            start_line=window_start_line,
            line_number=line_number,
        )

        if _is_filtered_out(
            required_filter_parameters=['line'],
            filename=filename,
            line=stripped_line,
            context=code_snippet,
        ):
            continue

        for plugin in get_plugins():
            for secret in _scan_line(
                plugin=plugin,
                filename=filename,
                line=stripped_line,
                line_number=line_number,
                context=code_snippet,
            ):
                if not _is_filtered_out(
                    required_filter_parameters=['context'],
                    filename=secret.filename,
                    secret=secret.secret_value,
                    plugin=plugin,
                    line=stripped_line,
                    context=code_snippet,
                ):
                    yield secret


class _Batch(NamedTuple):
    secrets: List[PotentialSecret]
    cursor: ScanCursor
    found_any: bool
    complete: bool


class _ResultLog:
    def __init__(self, fileobj: BinaryIO, committed: List[PotentialSecret]) -> None:
        self.fileobj = fileobj
        self.committed = committed

    def append(self, secrets: Iterable[PotentialSecret]) -> int:
        for secret in secrets:
            self.fileobj.write(_serialize_secret(secret))

        self.fileobj.flush()
        os.fsync(self.fileobj.fileno())
        return self.fileobj.tell()

    def close(self) -> None:
        self.fileobj.close()


def _serialize_secret(secret: PotentialSecret) -> bytes:
    # PotentialSecret.json() only contains a hash, never the plaintext value.
    payload = json.dumps(
        secret.json(),
        sort_keys=True,
        separators=(',', ':'),
    )
    return (payload + '\n').encode('utf-8')


def _deserialize_secret(line: bytes) -> PotentialSecret:
    payload = json.loads(line.decode('utf-8'))
    return PotentialSecret.load_secret_from_dict(payload)


class ResumableScan:
    """
    Scan one file in resumable batches.

    The checkpoint is committed only after batch results have been durably
    appended to ``result_path`` (when supplied). On resume, bytes beyond the
    checkpoint's ``output_offset`` are discarded before scanning continues, so
    an interruption before the checkpoint cannot duplicate results, and an
    interruption after the checkpoint cannot lose them.
    """

    def __init__(
        self,
        filename: str,
        checkpoint_path: str,
        *,
        batch_size: int = DEFAULT_BATCH_SIZE,
        result_path: Optional[str] = None,
        settings_fingerprint: Optional[str] = None,
        restart_on_invalid: bool = False,
        before_checkpoint: Optional[CheckpointHook] = None,
        after_checkpoint: Optional[CheckpointHook] = None,
        crash_before_checkpoint_at: Optional[int] = None,
        crash_after_checkpoint_at: Optional[int] = None,
    ) -> None:
        self.filename = filename
        self.checkpoint_path = os.path.abspath(checkpoint_path)
        self.batch_size = max(1, int(batch_size))
        self._explicit_result_path = result_path is not None
        self.result_path = os.path.abspath(
            result_path or (self.checkpoint_path + '.results.jsonl'),
        )
        self.settings_fingerprint = settings_fingerprint
        self.restart_on_invalid = restart_on_invalid
        self.before_checkpoint = before_checkpoint
        self.after_checkpoint = after_checkpoint
        self.crash_before_checkpoint_at = crash_before_checkpoint_at
        self.crash_after_checkpoint_at = crash_after_checkpoint_at
        self._commit_count = 0

    def run(self) -> 'SecretsCollection':  # type: ignore[name-defined]  # noqa: F821
        from .secrets_collection import SecretsCollection

        collection = SecretsCollection()
        for secret in self.scan():
            collection[secret.filename].add(secret)
        return collection

    def scan(self) -> Generator[PotentialSecret, None, None]:
        try:
            if not get_plugins():  # pragma: no cover
                log.error('No plugins to scan with!')
                return
        except FileNotFoundError:
            log.error('Unable to load plugins!')
            return

        if _is_filtered_out(
            required_filter_parameters=['filename'],
            filename=self.filename,
        ):
            return

        try:
            checkpoint = self._load_or_create_checkpoint()
        except FileNotFoundError:
            log.warning(f'Unable to open file: {self.filename}')
            return

        result_log = self._prepare_result_log(checkpoint)
        try:
            yield from (result_log.committed if result_log else [])

            if checkpoint.phase == PHASE_COMPLETE:
                return

            yield from self._scan_phases(checkpoint, result_log)
        finally:
            if result_log:
                result_log.close()

    def _scan_phases(
        self,
        checkpoint: ScanCheckpoint,
        result_log: Optional[_ResultLog],
    ) -> Generator[PotentialSecret, None, None]:
        mode, transformed_lines = self._prepare_mode(checkpoint)
        if mode == 'binary':
            checkpoint = replace(checkpoint, phase=PHASE_COMPLETE, mode=mode)
            self._commit(checkpoint)
            return

        checkpoint = replace(checkpoint, mode=mode)

        if checkpoint.phase == PHASE_PRIMARY:
            for batch in self._iter_batches(checkpoint, mode, transformed_lines):
                if result_log:
                    checkpoint = self._persist_batch(checkpoint, batch, result_log)
                    yield from batch.secrets
                else:
                    yield from batch.secrets
                    checkpoint = self._persist_batch(checkpoint, batch, result_log)

                if batch.complete:
                    break

            if checkpoint.found_any:
                checkpoint = replace(checkpoint, phase=PHASE_COMPLETE)
                self._commit(checkpoint)
                return

            checkpoint = replace(
                checkpoint,
                phase=PHASE_EAGER,
                mode=MODE_EAGER,
                found_any=False,
                cursor=ScanCursor(
                    offset=0,
                    line_number=1,
                    output_offset=checkpoint.cursor.output_offset,
                ),
            )
            self._commit(checkpoint)

        if checkpoint.phase == PHASE_EAGER:
            eager_lines = self._get_transformed_lines(use_eager_transformers=True)
            if not eager_lines:
                checkpoint = replace(checkpoint, phase=PHASE_COMPLETE)
                self._commit(checkpoint)
                return

            for batch in self._iter_batches(checkpoint, MODE_EAGER, eager_lines):
                if result_log:
                    checkpoint = self._persist_batch(checkpoint, batch, result_log)
                    yield from batch.secrets
                else:
                    yield from batch.secrets
                    checkpoint = self._persist_batch(checkpoint, batch, result_log)

                if batch.complete:
                    break

            checkpoint = replace(checkpoint, phase=PHASE_COMPLETE)
            self._commit(checkpoint)

    def _load_or_create_checkpoint(self) -> ScanCheckpoint:
        try:
            checkpoint = load_checkpoint(self.checkpoint_path)
        except CheckpointInvalidError as e:
            if not self.restart_on_invalid:
                raise

            log.warning(f'Ignoring checkpoint because {e.reason}: {e}')
            return self._fresh_checkpoint()

        if checkpoint is None:
            return self._fresh_checkpoint()

        if checkpoint.result_path:
            if (
                self._explicit_result_path
                and os.path.abspath(checkpoint.result_path) != self.result_path
            ):
                raise CheckpointInvalidError(
                    REASON_RESULT_LOG_CHANGED,
                    'Result log changed since the checkpoint was written.',
                )
            self.result_path = checkpoint.result_path
        elif self.result_path:
            if checkpoint.cursor.output_offset:
                raise CheckpointInvalidError(
                    REASON_RESULT_LOG_MISSING,
                    'Checkpoint has progress but no result log to recover.',
                )
            checkpoint.result_path = self.result_path

        try:
            validate_checkpoint(
                checkpoint,
                self.filename,
                self.settings_fingerprint,
            )
        except CheckpointInvalidError as e:
            if not self.restart_on_invalid:
                raise

            log.warning(
                f'Ignoring checkpoint because {e.reason}: {e}',
            )
            return self._fresh_checkpoint()

        return checkpoint

    def _fresh_checkpoint(self) -> ScanCheckpoint:
        return ScanCheckpoint(
            source=SourceFingerprint.from_path(self.filename),
            settings=self.settings_fingerprint or get_settings_fingerprint(),
            cursor=ScanCursor(),
            result_path=self.result_path,
        )

    def _prepare_result_log(
        self,
        checkpoint: ScanCheckpoint,
    ) -> Optional[_ResultLog]:
        if not checkpoint.result_path:
            return None

        path = checkpoint.result_path
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)

        try:
            fileobj = open(path, 'r+b')
        except FileNotFoundError:
            if checkpoint.cursor.output_offset:
                raise CheckpointInvalidError(
                    REASON_RESULT_LOG_MISSING,
                    f'Result log no longer exists: {path}',
                )
            fileobj = open(path, 'w+b')

        fileobj.seek(0, os.SEEK_END)
        size = fileobj.tell()
        committed_offset = checkpoint.cursor.output_offset
        if size < committed_offset:
            fileobj.close()
            raise CheckpointInvalidError(
                REASON_RESULT_LOG_CHANGED,
                'Result log is shorter than the committed checkpoint offset.',
            )

        # Any bytes past the checkpoint are from a batch that was not committed.
        fileobj.truncate(committed_offset)
        fileobj.seek(0)
        committed_bytes = fileobj.read(committed_offset)

        committed: List[PotentialSecret] = []
        try:
            for line in committed_bytes.splitlines():
                if line.strip():
                    committed.append(_deserialize_secret(line))
        except (KeyError, TypeError, ValueError) as e:
            fileobj.close()
            raise CheckpointInvalidError(
                REASON_RESULT_LOG_CORRUPT,
                f'Unable to read committed results: {e}',
            )

        fileobj.seek(committed_offset)
        return _ResultLog(fileobj, committed)

    def _prepare_mode(
        self,
        checkpoint: ScanCheckpoint,
    ) -> Tuple[str, Optional[List[str]]]:
        if checkpoint.mode == MODE_RAW:
            return MODE_RAW, None

        if checkpoint.mode == MODE_TRANSFORMED:
            return MODE_TRANSFORMED, self._get_transformed_lines() or []

        if checkpoint.mode == MODE_EAGER:
            return MODE_EAGER, self._get_transformed_lines(use_eager_transformers=True) or []

        # Fresh scans follow the same ordering as `scan.scan_file`: the normal
        # transformer first, then raw lines, then the eager transformer only if
        # the first pass produced no secrets.
        try:
            with open(self.filename, encoding=_get_encoding()) as f:
                transformed = get_transformed_file(cast(NamedIO, f))
                if not transformed:
                    f.seek(0)
                    f.readlines()
        except UnicodeDecodeError:
            return 'binary', None

        if transformed:
            return MODE_TRANSFORMED, transformed

        return MODE_RAW, None

    def _get_transformed_lines(
        self,
        use_eager_transformers: bool = False,
    ) -> Optional[List[str]]:
        try:
            with open(self.filename, encoding=_get_encoding()) as f:
                return get_transformed_file(
                    cast(NamedIO, f),
                    use_eager_transformers=use_eager_transformers,
                )
        except (OSError, UnicodeDecodeError):
            return None

    def _iter_batches(
        self,
        checkpoint: ScanCheckpoint,
        mode: str,
        transformed_lines: Optional[List[str]],
    ) -> Iterator[_Batch]:
        if mode == MODE_RAW:
            yield from self._iter_raw_batches(checkpoint)
        else:
            yield from self._iter_transformed_batches(
                checkpoint,
                transformed_lines or [],
            )

    def _iter_raw_batches(self, checkpoint: ScanCheckpoint) -> Iterator[_Batch]:
        cursor = checkpoint.cursor
        found_any = checkpoint.found_any

        try:
            f = open(self.filename, 'rb')
        except OSError:
            log.warning(f'Unable to open file: {self.filename}')
            yield _Batch([], cursor, found_any, True)
            return

        with f:
            f.seek(cursor.offset)
            previous_lines = _read_previous_lines(
                self.filename,
                cursor.offset,
                CONTEXT_LINES,
            )

            while True:
                target_lines: List[Tuple[int, str]] = []
                target_end_offset = f.tell()
                next_line_number = cursor.line_number
                bytes_read = 0
                eof = False

                while bytes_read < self.batch_size:
                    raw_line = f.readline()
                    if not raw_line:
                        eof = True
                        break

                    target_lines.append(
                        (next_line_number, _decode_line(raw_line)),
                    )
                    next_line_number += 1
                    bytes_read += len(raw_line)
                    target_end_offset = f.tell()

                if not target_lines:
                    break

                lookahead_lines: List[str] = []
                for _ in range(CONTEXT_LINES):
                    raw_line = f.readline()
                    if not raw_line:
                        break
                    lookahead_lines.append(_decode_line(raw_line))

                # Lookahead belongs to the next batch; leave it uncommitted.
                f.seek(target_end_offset)

                window = (
                    previous_lines
                    + [line for _, line in target_lines]
                    + lookahead_lines
                )
                window_start_line = cursor.line_number - len(previous_lines)

                secrets = list(
                    _process_lines(
                        target_lines,
                        window,
                        window_start_line,
                        self.filename,
                    ),
                )
                found_any = found_any or bool(secrets)

                previous_lines = (
                    previous_lines
                    + [line for _, line in target_lines]
                )[-CONTEXT_LINES:]
                cursor = ScanCursor(
                    offset=target_end_offset,
                    line_number=next_line_number,
                    output_offset=cursor.output_offset,
                )

                yield _Batch(secrets, cursor, found_any, eof)
                if eof:
                    break

    def _iter_transformed_batches(
        self,
        checkpoint: ScanCheckpoint,
        lines: List[str],
    ) -> Iterator[_Batch]:
        cursor = checkpoint.cursor
        found_any = checkpoint.found_any
        index = max(0, cursor.line_number - 1)

        while index < len(lines):
            target_lines: List[Tuple[int, str]] = []
            bytes_read = 0

            while index < len(lines) and (bytes_read < self.batch_size or not target_lines):
                line = lines[index]
                target_lines.append((index + 1, line))
                bytes_read += len(line.encode(_get_encoding()))
                index += 1

            secrets = list(
                _process_lines(
                    target_lines,
                    lines,
                    1,
                    self.filename,
                ),
            )
            found_any = found_any or bool(secrets)
            cursor = ScanCursor(
                offset=0,
                line_number=index + 1,
                output_offset=cursor.output_offset,
            )
            yield _Batch(secrets, cursor, found_any, index >= len(lines))

    def _persist_batch(
        self,
        checkpoint: ScanCheckpoint,
        batch: _Batch,
        result_log: Optional[_ResultLog],
    ) -> ScanCheckpoint:
        output_offset = checkpoint.cursor.output_offset

        if result_log:
            output_offset = result_log.append(batch.secrets)

        new_checkpoint = replace(
            checkpoint,
            cursor=replace(
                batch.cursor,
                output_offset=output_offset,
            ),
            found_any=batch.found_any,
        )

        # When a result log is supplied, callers append results before this
        # method is called, so the checkpoint never advances past durable
        # results. Without a result log the caller yields first, then commits.
        self._commit(new_checkpoint)

        return new_checkpoint

    def _commit(self, checkpoint: ScanCheckpoint) -> None:
        self._commit_count += 1

        if self.before_checkpoint:
            self.before_checkpoint(checkpoint)
        if self._commit_count == self.crash_before_checkpoint_at:
            raise SimulatedCheckpointInterruption(
                'Stopped before writing checkpoint.',
            )

        save_checkpoint(self.checkpoint_path, checkpoint)

        if self.after_checkpoint:
            self.after_checkpoint(checkpoint)
        if self._commit_count == self.crash_after_checkpoint_at:
            raise SimulatedCheckpointInterruption(
                'Stopped after writing checkpoint.',
            )


def scan_file_resumable(
    filename: str,
    checkpoint_path: str,
    **kwargs: Any,
) -> Generator[PotentialSecret, None, None]:
    """Yield results for a file, resuming from a checkpoint when available."""
    yield from ResumableScan(
        filename=filename,
        checkpoint_path=checkpoint_path,
        **kwargs,
    ).scan()


def run_resumable_scan(
    filename: str,
    checkpoint_path: str,
    **kwargs: Any,
) -> 'SecretsCollection':  # type: ignore[name-defined]  # noqa: F821
    """Run a resumable scan and return the recovered collection."""
    return ResumableScan(
        filename=filename,
        checkpoint_path=checkpoint_path,
        **kwargs,
    ).run()


# Alternate entry-point spellings for callers that use batch/cursor vocabulary.
resumable_scan_file = scan_file_resumable
scan_file_with_checkpoint = scan_file_resumable
scan_file_from_checkpoint = scan_file_resumable
ResumableFileScanner = ResumableScan
ResumableScanner = ResumableScan
BatchScanner = ResumableScan
Checkpoint = ScanCheckpoint
ScanState = ScanCheckpoint
Cursor = ScanCursor
read_cursor = load_checkpoint
write_cursor = save_checkpoint
CheckpointInvalidatedError = CheckpointInvalidError
StaleCursorError = CheckpointInvalidError
