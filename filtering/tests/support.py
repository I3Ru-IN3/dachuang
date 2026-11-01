"""Test helpers shared by the dns_filter test modules."""

from __future__ import annotations

import shutil
import uuid
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path

_ARTIFACT_ROOT = Path(__file__).resolve().parent / "_artifacts"


@contextmanager
def temporary_directory() -> Iterator[Path]:
    """Create a throw-away directory inside the workspace.

    ``tempfile.TemporaryDirectory`` is intentionally avoided because the
    execution sandbox treats its private temp directories as read-only.  Test
    artifacts stay under the repository and are removed afterwards.
    """

    path = _ARTIFACT_ROOT / uuid.uuid4().hex
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
        if _ARTIFACT_ROOT.exists() and not any(_ARTIFACT_ROOT.iterdir()):
            _ARTIFACT_ROOT.rmdir()
