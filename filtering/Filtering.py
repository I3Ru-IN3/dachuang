"""Compatibility entry point for the original ``Filtering.py`` command.

The implementation now lives in the :mod:`dns_filter` package.  This module is
kept as a thin script so ``python Filtering.py`` and ``python -m
filtering.Filtering`` continue to work, and the public helpers are re-exported
from one place.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__:
    from .dns_filter import *  # noqa: F401,F403
    from .dns_filter import __all__ as _package_all
    from .dns_filter.cli import main
else:
    # Direct script execution adds the script's directory to sys.path, but
    # being explicit also covers unusual launchers.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from dns_filter import *  # noqa: F401,F403
    from dns_filter import __all__ as _package_all
    from dns_filter.cli import main

__all__ = [*_package_all, "main"]


if __name__ == "__main__":
    raise SystemExit(main())
