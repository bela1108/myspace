import io
import contextlib
import tempfile


class RelativeStream(io.BufferedIOBase):
    """Present a stream segment as a standalone, seekable stream."""

    def __init__(self, stream, start_offset, end_offset=None):
        self.stream = stream
        self.start_offset = start_offset
        self.end_offset = end_offset
        self._position = 0

    def _limit(self, size=-1):
        if size is None or size < 0:
            if self.end_offset is None:
                return -1
            return max(0, self.end_offset - self.start_offset - self._position)
        if self.end_offset is None:
            return size
        return min(size, max(0, self.end_offset - self.start_offset - self._position))

    def seekable(self):
        return True

    def readable(self):
        return True

    def writable(self):
        return False

    def tell(self):
        return self._position

    def seek(self, offset, whence=0):
        if whence == 0:
            position = offset
        elif whence == 1:
            position = self._position + offset
        elif whence == 2:
            if self.end_offset is None:
                self.stream.seek(0, 2)
                position = self.stream.tell() - self.start_offset + offset
            else:
                position = self.end_offset - self.start_offset + offset
        else:
            raise ValueError("invalid whence ({})".format(whence))

        if position < 0:
            raise ValueError("negative seek position {}".format(position))

        self._position = position
        self.stream.seek(self.start_offset + position)
        return self._position

    def read(self, size=-1):
        limited_size = self._limit(size)
        if limited_size == 0:
            return b""
        value = self.stream.read(limited_size)
        self._position += len(value)
        return value

    def read1(self, size=-1):
        return self.read(size)

    def readinto(self, buffer):
        value = self.read(len(buffer))
        count = min(len(value), len(buffer))
        buffer[:count] = value
        return count

    @property
    def closed(self):
        return self.stream.closed


class InputContract:
    """Ownership and replay contract for one office document input."""

    def __init__(self, stream, copy_budget=None):
        self.external_stream = stream
        self.copy_budget = copy_budget
        self.owns_stream = False
        self.replayable = True
        self.closed = False

        try:
            if not stream.seekable():
                raise OSError("input is not seekable")
            self.start_offset = stream.tell()
            stream.seek(self.start_offset)
        except (AttributeError, OSError, ValueError):
            self._copy_stream()
        else:
            self.stream = RelativeStream(stream, self.start_offset)

    def _copy_stream(self):
        if self.copy_budget is None:
            raise OSError("non-seekable input requires copy_budget")
        if self.copy_budget < 0:
            raise ValueError("copy_budget must be non-negative")

        copy = tempfile.SpooledTemporaryFile(max_size=1024 * 1024)
        try:
            remaining = self.copy_budget
            while True:
                chunk_size = min(1024 * 1024, remaining)
                chunk = self.external_stream.read(chunk_size)
                if not chunk:
                    break
                if len(chunk) > remaining:
                    raise ValueError("input exceeds copy_budget")
                copy.write(chunk)
                remaining -= len(chunk)
                if remaining == 0:
                    if self.external_stream.read(1):
                        raise ValueError("input exceeds copy_budget")
                    break

            copy.seek(0)
            self.stream = copy
            self.owns_stream = True
            self.replayable = False
            self.start_offset = 0
        except Exception:
            copy.close()
            raise

    def restore(self):
        self.stream.seek(0)

    @contextlib.contextmanager
    def review(self):
        position = self.stream.tell()
        try:
            self.stream.seek(0)
            yield self.stream
        finally:
            self.stream.seek(position)
            if isinstance(self.stream, RelativeStream):
                self.external_stream.seek(self.start_offset)

    def close(self):
        if self.closed:
            return
        if self.owns_stream:
            self.stream.close()
            self.owns_stream = False
        elif not getattr(self.external_stream, "closed", False):
            self.external_stream.seek(self.start_offset)
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def ensure_input_contract(file, copy_budget=None):
    if isinstance(file, InputContract):
        return file
    return InputContract(file, copy_budget=copy_budget)
