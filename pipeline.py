from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import os
import pandas as pd

from .config import ToolConfig
from .detectors import DetectionResult, detect_sensitive_columns
from .logging_utils import get_logger
from .report import summarize, compute_utility_report
from .strategies import StrategySelection, apply_strategy
from .utils import load_dataset, save_dataset


REVERSIBLE_TECHNIQUES: Dict[str, str] = {
    # Direct identifiers and quasi-identifiers - reversible / linkable
    "name": "pseudonym",       # keeps 1–1 mapping possible with external key
    "email": "pseudonym",
    "phone": "mask",
    "address": "generalize",
    "dob": "generalize",       # e.g. age ranges / year/month
    "numeric_id": "tokenize",  # stable tokens, conceptually reversible with a lookup
    "salary": "noise",         # slight noise, good for exploratory analysis
}

IRREVERSIBLE_TECHNIQUES: Dict[str, str] = {
    # Direct identifiers - fully irreversible
    "name": "hash",
    "email": "hash",
    "numeric_id": "hash",
    # Other sensitive attributes - anonymize while preserving analytical value
    "phone": "mask",
    "address": "generalize",
    "dob": "generalize",       # still aggregated (e.g. to month/year)
    # Metrics where we want to keep distribution nearly identical
    # but break the link to individuals (e.g. billing amount, income)
    "salary": "shuffle",
}


@dataclass
class PipelineResult:
    dataframe: pd.DataFrame
    detections: List[DetectionResult]
    selections: List[StrategySelection]
    report: str


class AnonymizationPipeline:
    def __init__(self, config: ToolConfig, irreversible: bool = False):
        self.config = config
        self.irreversible = irreversible

        # Process-wide secret for hashing. In a production system this should
        # come from a proper secret manager or environment variable.
        self._secret_salt = os.getenv("ANONYMIZER_SECRET", "")
        if self.irreversible and not self._secret_salt:
            raise RuntimeError(
                "Irreversible anonymization requires ANONYMIZER_SECRET to be set."
            )

        self._logger = get_logger("anonymizer.pipeline")

    def _with_hash_params(self, column: str, base: Dict[str, object]) -> Dict[str, object]:
        """
        Enrich hash strategy parameters with a secret salt and column name.

        By including both a secret and the column name in the hash input we
        approximate an HMAC-style construction, which makes cross-dataset
        linkage attacks significantly harder.
        """
        params: Dict[str, object] = dict(base)
        params.setdefault("column", column)
        if self._secret_salt and "salt" not in params:
            params["salt"] = self._secret_salt
        return params

    def _build_override_map(self) -> Dict[str, StrategySelection]:
        overrides = {}
        for rule in self.config.overrides:
            # In reversible mode we respect the explicit technique from the config.
            # In irreversible mode, for strong identifiers we override the technique
            # to whatever the irreversible policy dictates (typically hashing).
            technique = rule.technique
            params: Dict[str, object] = rule.params
            if self.irreversible and rule.detector_hint in {"name", "email", "numeric_id"}:
                technique = self._choose_technique(rule.detector_hint)
            if technique == "hash":
                params = self._with_hash_params(rule.column, params)
            overrides[rule.column] = StrategySelection(
                column=rule.column,
                technique=technique,
                params=params,
            )
        return overrides

    def _choose_technique(self, detector_label: str) -> str:
        """
        Choose an anonymization technique given a semantic detector label.

        - In reversible mode we favor techniques that could, in principle,
          be reversed via an external mapping (pseudonyms, tokens, mild
          generalization).
        - In irreversible mode, direct identifiers are hashed and metrics
          like salaries are shuffled so that dataset-level statistics and
          distributions are preserved while individual records cannot be
          reconstructed.
        """
        if self.irreversible:
            technique = IRREVERSIBLE_TECHNIQUES.get(detector_label)
            if technique:
                return technique
            return self.config.default_strategy.irreversible

        technique = REVERSIBLE_TECHNIQUES.get(detector_label)
        if technique:
            return technique
        return self.config.default_strategy.reversible

    def _build_selections(
        self, detections: List[DetectionResult]
    ) -> List[StrategySelection]:
        overrides = self._build_override_map()
        selections: List[StrategySelection] = []
        for detection in detections:
            if detection.column in overrides:
                selections.append(overrides[detection.column])
                continue
            technique = self._choose_technique(detection.detector)
            params: Dict[str, object] = {}
            if technique == "hash":
                params = self._with_hash_params(detection.column, params)
            selections.append(
                StrategySelection(
                    column=detection.column,
                    technique=technique,
                    params=params,
                )
            )
        return selections

    def _apply_l_diversity(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply a simple l-diversity safeguard for highly sensitive attributes.

        For the healthcare dataset we treat "Medical Condition" as the
        sensitive attribute and group by a small set of quasi-identifiers.
        If a group has fewer than `l` distinct conditions, we suppress the
        condition in that group to avoid near-certain inference.
        """
        sensitive_col = "Medical Condition"
        quasi_cols = [
            col
            for col in ["Age", "Gender", "Hospital", "Date of Admission"]
            if col in df.columns
        ]
        if sensitive_col not in df.columns or not quasi_cols:
            return df

        l = 3  # minimum number of distinct conditions in each quasi-ID group
        groups = df.groupby(quasi_cols)[sensitive_col]
        for _, idx in groups.groups.items():
            values = df.loc[idx, sensitive_col]
            if values.nunique(dropna=True) < l:
                df.loc[idx, sensitive_col] = "Suppressed"
        return df

    def inspect(self, dataset_path: str) -> PipelineResult:
        df = load_dataset(dataset_path)
        detections = detect_sensitive_columns(
            df,
            allowlist=self.config.allowlist,
            override_hints={rule.column: rule.detector_hint for rule in self.config.overrides},
        )
        selections = self._build_selections(detections)
        report = summarize(detections, selections)
        return PipelineResult(df, detections, selections, report)

    def anonymize(
        self,
        dataset_path: str,
        output_path: Optional[str] = None,
        inspect_only: bool = False,
        sample_rows: Optional[int] = None,
    ) -> PipelineResult:
        """
        Run anonymization on a dataset.

        - When inspect_only=True, this only runs detection and returns
          a PipelineResult with the original dataframe and report.
        - When sample_rows is set and no output_path is provided, a random
          subset of at most sample_rows rows is used for anonymization
          and utility calculation. This is intended for fast UI previews.
        """
        # First pass: compute detections and selections on the original data
        self._logger.info(
            "starting anonymization run",
            extra={"dataset_path": dataset_path, "irreversible": self.irreversible},
        )
        result = self.inspect(dataset_path)
        if inspect_only:
            return result

        original_df = result.dataframe.copy(deep=True)
        df = original_df.copy()
        utility_orig = original_df

        # For preview / inspect scenarios (no file output), we can work on a
        # sampled subset to keep response times snappy on large datasets.
        if sample_rows is not None and output_path is None and len(df) > sample_rows:
            df = df.sample(n=sample_rows, random_state=42).reset_index(drop=True)
            utility_orig = df.copy(deep=True)
        for selection in result.selections:
            if selection.column not in df.columns:
                continue
            df[selection.column] = apply_strategy(df[selection.column], selection)

        # Strengthen protection of sensitive attributes in irreversible mode
        # by enforcing a simple l-diversity constraint on medical conditions.
        if self.irreversible:
            df = self._apply_l_diversity(df)

        # Compute a basic utility report comparing key statistics between
        # the original and anonymized datasets.
        utility_report = compute_utility_report(utility_orig, df)
        if result.report:
            result.report = result.report + "\n\n" + utility_report
        else:
            result.report = utility_report

        result.dataframe = df
        if output_path:
            save_dataset(df, output_path)
            self._logger.info(
                "anonymization run completed",
                extra={
                    "dataset_path": dataset_path,
                    "output_path": output_path,
                    "irreversible": self.irreversible,
                    "rows": len(df),
                    "columns": list(df.columns),
                    "techniques": {s.column: s.technique for s in result.selections},
                },
            )
        return result

