from __future__ import annotations

import pytest

from cli import _ensure_local_path


def test_ensure_local_path_rejects_url() -> None:
    """
    The CLI should never accept remote URLs as dataset paths. This is a
    basic SSRF hardening control.
    """
    with pytest.raises(Exception):
        _ensure_local_path("http://example.com/data.csv")


def test_ensure_local_path_accepts_local() -> None:
    """
    Local file paths that do not look like URLs should be accepted.
    """
    _ensure_local_path("/tmp/data.csv")
    _ensure_local_path("relative.csv")


