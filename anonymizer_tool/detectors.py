from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import pandas as pd


NAME_HINT = re.compile(r"(name|full[_\s]?name|first|last)", re.I)
EMAIL_HINT = re.compile(r"(email|e[-_\s]?mail)", re.I)
PHONE_HINT = re.compile(r"(phone|mobile|contact|tel)", re.I)
ADDRESS_HINT = re.compile(r"(address|addr|street|city|state|zip)", re.I)
DOB_HINT = re.compile(r"(birth|dob|date[-_\s]?of[-_\s]?birth|age|date)", re.I)
ID_HINT = re.compile(r"(ssn|national|id|passport|credit|card|account|iban)", re.I)
SALARY_HINT = re.compile(r"(income|salary|compensation|pay|revenue|billing|amount|cost|price|fee)", re.I)


@dataclass
class DetectionResult:
    column: str
    detector: str
    confidence: float


def _match_pattern(name: str, pattern: re.Pattern[str]) -> bool:
    return bool(pattern.search(name))


def _value_ratio(series: pd.Series, pattern: re.Pattern[str]) -> float:
    if series.empty:
        return 0.0
    str_values = series.dropna().astype(str)
    if str_values.empty:
        return 0.0
    # Use regex=False to avoid warnings, or escape the pattern
    hits = str_values.str.contains(pattern, regex=True, na=False).sum()
    return hits / len(str_values)


VALUE_PATTERNS = {
    "email": re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$"),
    "phone": re.compile(r"\+?\d[\d\-\s]{7,}\d"),  # Removed capture group
    "address": re.compile(r"\d+\s+\w+"),
    "dob": re.compile(r"\d{4}-\d{2}-\d{2}"),
    "credit_card": re.compile(r"^\d{13,16}$"),
}

NAME_DETECTOR = lambda name, series: (
    _match_pattern(name, NAME_HINT) or _value_ratio(series, re.compile(r"\s")) > 0.8
)

DETECTOR_RULES = {
    "name": NAME_DETECTOR,
    "email": lambda name, series: _match_pattern(name, EMAIL_HINT)
    or _value_ratio(series, VALUE_PATTERNS["email"]) > 0.5,
    "phone": lambda name, series: (
        _match_pattern(name, PHONE_HINT)
        and not _match_pattern(name, SALARY_HINT)  # Don't match financial columns
    ) or (
        _value_ratio(series, VALUE_PATTERNS["phone"]) > 0.4
        and not _match_pattern(name, SALARY_HINT)
        and series.dtype == "object"  # Phone numbers are usually strings, not numeric
    ),
    "address": lambda name, series: _match_pattern(name, ADDRESS_HINT)
    or _value_ratio(series, VALUE_PATTERNS["address"]) > 0.6,
    "dob": lambda name, series: _match_pattern(name, DOB_HINT)
    or _value_ratio(series, VALUE_PATTERNS["dob"]) > 0.5,
    "numeric_id": lambda name, series: _match_pattern(name, ID_HINT)
    or _value_ratio(series.astype(str), VALUE_PATTERNS["credit_card"]) > 0.3,
    "salary": lambda name, series: _match_pattern(name, SALARY_HINT)
    or (series.dtype in ["float64", "int64"] and _match_pattern(name, SALARY_HINT)),
}


def detect_sensitive_columns(
    df: pd.DataFrame,
    allowlist: Iterable[str],
    override_hints: Dict[str, str],
) -> List[DetectionResult]:
    results: List[DetectionResult] = []
    allowset = {col.lower() for col in allowlist}
    for column in df.columns:
        if column.lower() in allowset:
            continue
        override = override_hints.get(column)
        if override:
            results.append(
                DetectionResult(column=column, detector=override, confidence=1.0)
            )
            continue
        series = df[column]
        best_label: Optional[str] = None
        best_score = 0.0
        # Prioritize certain detectors based on column name hints
        priority_order = ["dob", "email", "salary", "phone", "name", "address", "numeric_id"]
        ordered_rules = sorted(
            DETECTOR_RULES.items(),
            key=lambda x: priority_order.index(x[0]) if x[0] in priority_order else 999
        )
        for label, fn in ordered_rules:
            try:
                matched = fn(column, series)
            except Exception:
                matched = False
            if matched:
                score = 0.8
                if label in {"email", "phone"}:
                    score = 0.9
                # Boost score if column name strongly matches
                if label == "dob" and _match_pattern(column, DOB_HINT):
                    score = 0.95
                if score > best_score:
                    best_score = score
                    best_label = label
                    # Break early if we have a high-confidence match
                    if score >= 0.95:
                        break
        if best_label:
            results.append(
                DetectionResult(
                    column=column,
                    detector=best_label,
                    confidence=best_score,
                )
            )
    return results

