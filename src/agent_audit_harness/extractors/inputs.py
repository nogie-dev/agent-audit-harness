"""Shared source boundary for extractor configuration inputs."""

import hashlib
import os
import stat
from pathlib import Path

from ..pipeline import MAX_FILE_BYTES, Source


def read_input(target: Path, relative: str) -> Source:
    path = target / relative
    if Path(relative).is_absolute() or not path.resolve().is_relative_to(target):
        raise ValueError("extractor input is outside target")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("extractor input is not a regular file")
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES or b"\0" in data:
        raise ValueError("extractor input is oversized or binary")
    return Source(relative, data.decode("utf-8"), hashlib.sha256(data).hexdigest())
