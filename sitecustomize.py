"""Compatibility shim for older third-party code.

Provides inspect.getargspec for libraries that still import it
directly (for example, parsimonious). This adapts
inspect.getfullargspec into the legacy return shape.

Remove this shim once all dependencies support Python 3.11+.
"""
from __future__ import annotations

import inspect
from collections import namedtuple

try:
    # If an implementation already exists, leave it alone.
    getargspec = inspect.getargspec  # type: ignore[attr-defined]
except Exception:
    # Create a legacy ArgSpec compatible with older code.
    ARGSPEC_FIELDS = ("args", "varargs", "keywords", "defaults")
    ArgSpec = namedtuple("ArgSpec", ARGSPEC_FIELDS)

    def _getargspec(func):
        """Return ArgSpec(args, varargs, keywords, defaults).

        Uses inspect.getfullargspec and maps its fields to the
        older ArgSpec tuple.
        """
        fs = inspect.getfullargspec(func)
        return ArgSpec(
            args=fs.args,
            varargs=fs.varargs,
            keywords=fs.varkw,
            defaults=fs.defaults,
        )

    # Monkeypatch so 'from inspect import getargspec' works.
    inspect.getargspec = _getargspec  # type: ignore[attr-defined]
