from __future__ import annotations

from pathlib import Path
from typing import Literal

import pandas as pd


SUPPORTED_FORMATS = ("csv", "xlsx")


def detect_format(path: str) -> str:
    suffix = Path(path).suffix.lower().lstrip(".")
    if suffix not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported file type: {suffix}")
    return suffix


def load_dataset(path: str) -> pd.DataFrame:
    file_format = detect_format(path)
    if file_format == "csv":
        return pd.read_csv(path)
    return pd.read_excel(path)


def save_dataset(df: pd.DataFrame, path: str) -> None:
    file_format = detect_format(path)
    if file_format == "csv":
        df.to_csv(path, index=False)
    else:
        df.to_excel(path, index=False)

