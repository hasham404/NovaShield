from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

import pandas as pd
from tabulate import tabulate

from .detectors import DetectionResult
from .strategies import StrategySelection


@dataclass
class Report:
    detections: List[DetectionResult]
    selections: List[StrategySelection]

    def to_table(self) -> str:
        rows = []
        selection_map = {sel.column: sel for sel in self.selections}
        for det in self.detections:
            applied = selection_map.get(det.column)
            technique = applied.technique if applied else "-"
            rows.append(
                [
                    det.column,
                    det.detector,
                    f"{det.confidence:.2f}",
                    technique,
                ]
            )
        headers = ["Column", "Detector", "Confidence", "Technique"]
        return tabulate(rows, headers=headers, tablefmt="github")


def summarize(detections: Iterable[DetectionResult], selections: Iterable[StrategySelection]) -> str:
    report = Report(list(detections), list(selections))
    if not report.detections:
        return "No sensitive columns detected."
    return report.to_table()


def compute_utility_report(original: pd.DataFrame, anonymized: pd.DataFrame) -> str:
    """
    Compare key statistics before and after anonymization and return
    a small human-readable report.

    This is not a full-fledged utility metric, but it gives a quick view
    of how much the anonymization has perturbed the data.
    """
    lines: List[str] = []
    if original.shape != anonymized.shape:
        lines.append(
            f"WARNING: Shape changed from {original.shape} to {anonymized.shape} during anonymization."
        )

    # Only consider columns that are numeric in both versions. This skips
    # columns like Age that may have been converted into buckets such as
    # "30-39" during anonymization.
    numeric_cols = []
    for col in original.columns:
        if col not in anonymized.columns:
            continue
        if not pd.api.types.is_numeric_dtype(original[col]):
            continue
        if not pd.api.types.is_numeric_dtype(anonymized[col]):
            continue
        numeric_cols.append(col)
    if not numeric_cols:
        return "Utility report: no numeric columns to compare."

    rows = []
    for col in numeric_cols:
        o = original[col].astype("float64")
        a = anonymized[col].astype("float64")
        o_mean = o.mean()
        a_mean = a.mean()
        o_std = o.std(ddof=0)
        a_std = a.std(ddof=0)
        mean_delta_pct = (
            abs(a_mean - o_mean) / max(abs(o_mean), 1e-9) * 100.0 if o_mean != 0 else 0.0
        )
        std_delta_pct = (
            abs(a_std - o_std) / max(abs(o_std), 1e-9) * 100.0 if o_std != 0 else 0.0
        )
        rows.append(
            [
                col,
                f"{o_mean:.2f}",
                f"{a_mean:.2f}",
                f"{mean_delta_pct:.1f}%",
                f"{o_std:.2f}",
                f"{a_std:.2f}",
                f"{std_delta_pct:.1f}%",
            ]
        )

    table = tabulate(
        rows,
        headers=[
            "Column",
            "Mean (orig)",
            "Mean (anon)",
            "Δ mean",
            "Std (orig)",
            "Std (anon)",
            "Δ std",
        ],
        tablefmt="github",
    )

    # Simple aggregate "score": the closer to 0 the deltas, the closer to 100.
    if rows:
        avg_mean_delta = sum(float(r[3].strip("%")) for r in rows) / len(rows)
        utility_score = max(0.0, 100.0 - avg_mean_delta)
        lines.append(f"Approximate data utility score (0–100): {utility_score:.1f}")

    lines.append("")
    lines.append(table)
    return "\n".join(lines)

