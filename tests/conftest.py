from __future__ import annotations

import os
from typing import Generator

import pytest

from web_app import app as flask_app


@pytest.fixture(autouse=True)
def _set_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure required secrets are present for tests.

    This keeps tests deterministic and avoids failures caused by missing
    ANONYMIZER_SECRET / APP_SECRET_KEY.
    """
    monkeypatch.setenv("ANONYMIZER_SECRET", "test-secret")
    monkeypatch.setenv("APP_SECRET_KEY", "test-app-secret")


@pytest.fixture
def app() -> Generator:
    """
    Provide the Flask app for tests.
    """
    yield flask_app


@pytest.fixture
def client(app) -> Generator:
    """
    Provide a Flask test client.
    """
    with app.test_client() as client:
        yield client


