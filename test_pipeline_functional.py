from __future__ import annotations

import os

import numpy as np
import pandas as pd
import pytest

from anonymizer_tool import AnonymizationPipeline
from anonymizer_tool.config import ToolConfig


def _make_small_df() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "Name": ["Alice Smith", "Bob Jones", "Charlie Doe"],
            "Age": [30, 52, 41],
            "Date of Admission": ["2024-01-10", "2023-12-01", "2022-05-05"],
            "Hospital": ["H1", "H1", "H2"],
            "Billing Amount": [1000.0, 2000.0, 1500.0],
            "Notes": ["ok", "ok", "ok"],
        }
    )


def test_inspect_detects_expected_sensitive_columns(tmp_path) -> None:
    """
    Pipeline.inspect should identify obvious sensitive columns like Name,
    Date of Admission and Billing Amount on a small synthetic dataset.
    """
    df = _make_small_df()
    path = tmp_path / "demo.csv"
    df.to_csv(path, index=False)

    cfg = ToolConfig()
    pipeline = AnonymizationPipeline(cfg, irreversible=False)
    result = pipeline.inspect(str(path))

    detected_cols = {d.column for d in result.detections}
    assert "Name" in detected_cols
    assert "Date of Admission" in detected_cols
    assert "Billing Amount" in detected_cols


def test_reversible_anonymization_preserves_shape_and_changes_identifiers(tmp_path) -> None:
    """
    Reversible mode should keep the same number of rows/columns while
    changing direct identifiers like Name.
    """
    df = _make_small_df()
    path = tmp_path / "demo.csv"
    df.to_csv(path, index=False)

    cfg = ToolConfig()
    pipeline = AnonymizationPipeline(cfg, irreversible=False)
    result = pipeline.anonymize(str(path), inspect_only=False)

    anon_df = result.dataframe
    assert anon_df.shape == df.shape
    # Name column should be different from original.
    assert not anon_df["Name"].equals(df["Name"])
    # Non-sensitive column should remain identical.
    assert anon_df["Notes"].equals(df["Notes"])


def test_irreversible_anonymization_hashes_identifiers_and_preserves_numeric_distribution(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """
    In irreversible mode, identifiers like Name should be hashed while
    numeric columns like Billing Amount keep the same distribution via
    shuffling.
    """
    monkeypatch.setenv("ANONYMIZER_SECRET", "test-secret")
    df = _make_small_df()
    path = tmp_path / "demo.csv"
    df.to_csv(path, index=False)

    cfg = ToolConfig()
    pipeline = AnonymizationPipeline(cfg, irreversible=True)
    result = pipeline.anonymize(str(path), inspect_only=False)
    anon_df = result.dataframe

    # Identifiers should change and look like hex hashes.
    assert not anon_df["Name"].equals(df["Name"])
    assert anon_df["Name"].str.match(r"[0-9a-f]{32}").all()

    # Billing Amount values should be a permutation of the original.
    assert np.all(np.sort(df["Billing Amount"].values) == np.sort(anon_df["Billing Amount"].values))


def test_anonymize_on_empty_dataset(tmp_path) -> None:
    """
    An empty dataset (0 rows) should not cause errors and should round-trip
    through anonymize with the same schema.
    """
    df = pd.DataFrame(columns=["Name", "Age"])
    path = tmp_path / "empty.csv"
    df.to_csv(path, index=False)

    cfg = ToolConfig()
    pipeline = AnonymizationPipeline(cfg, irreversible=False)
    result = pipeline.anonymize(str(path), inspect_only=False)

    anon_df = result.dataframe
    assert list(anon_df.columns) == ["Name", "Age"]
    assert len(anon_df) == 0


