from __future__ import annotations

import os

import pandas as pd
import pytest

from anonymizer_tool import AnonymizationPipeline
from anonymizer_tool.config import ToolConfig


def test_irreversible_requires_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    When irreversible=True, ANONYMIZER_SECRET must be set or the pipeline
    should refuse to run.
    """
    monkeypatch.delenv("ANONYMIZER_SECRET", raising=False)
    cfg = ToolConfig()
    with pytest.raises(RuntimeError):
        AnonymizationPipeline(cfg, irreversible=True)


def test_reversible_does_not_require_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Reversible mode should not require ANONYMIZER_SECRET.
    """
    monkeypatch.delenv("ANONYMIZER_SECRET", raising=False)
    cfg = ToolConfig()
    pipeline = AnonymizationPipeline(cfg, irreversible=False)
    assert pipeline.irreversible is False


def test_l_diversity_suppresses_small_condition_groups(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """
    In irreversible mode, small homogeneous groups of Medical Condition
    should be suppressed according to the l-diversity helper.
    """
    monkeypatch.setenv("ANONYMIZER_SECRET", "test-secret")
    cfg = ToolConfig()
    pipeline = AnonymizationPipeline(cfg, irreversible=True)

    df = pd.DataFrame(
        {
            "Age": ["30-39", "30-39", "30-39"],
            "Gender": ["M", "M", "M"],
            "Hospital": ["H1", "H1", "H1"],
            "Date of Admission": ["2024-01", "2024-01", "2024-01"],
            "Medical Condition": ["Cancer", "Cancer", "Cancer"],
        }
    )
    path = tmp_path / "small_group.csv"
    df.to_csv(path, index=False)

    result = pipeline.anonymize(str(path), inspect_only=False)
    assert (result.dataframe["Medical Condition"] == "Suppressed").all()


