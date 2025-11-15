from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Callable, Dict

import numpy as np
import pandas as pd
from Crypto.Hash import SHA256
from faker import Faker

faker = Faker()


StrategyFunc = Callable[[pd.Series, Dict[str, Any]], pd.Series]


def _ensure_seed(params: Dict[str, Any]) -> int:
    seed = params.get("seed")
    if seed is None:
        seed = random.randint(0, 2**32 - 1)
        params["seed"] = seed
    return seed


def pseudonym_strategy(series: pd.Series, params: Dict[str, Any]) -> pd.Series:
    locale = params.get("locale")
    fake = Faker(locale) if locale else faker
    seed = _ensure_seed(params)
    fake.seed_instance(seed)
    mapping: Dict[Any, str] = {}
    mode = params.get("mode", "name")

    def generate(value: Any) -> Any:
        if pd.isna(value):
            return value
        if value in mapping:
            return mapping[value]
        if mode == "email":
            token = fake.unique.email()
        elif mode == "phone":
            token = fake.unique.phone_number()
        else:
            token = fake.unique.name()
        mapping[value] = token
        return token

    return series.map(generate)


def mask_strategy(series: pd.Series, params: Dict[str, Any]) -> pd.Series:
    mask_char = params.get("mask_char", "*")
    show_last = params.get("show_last", 2)

    def mask_value(value: Any) -> Any:
        if pd.isna(value):
            return value
        text = str(value)
        if len(text) <= show_last:
            return mask_char * len(text)
        return mask_char * (len(text) - show_last) + text[-show_last:]

    return series.map(mask_value)


def hash_strategy(series: pd.Series, params: Dict[str, Any]) -> pd.Series:
    """
    Irreversible hashing strategy.

    We approximate an HMAC-style construction by combining:
    - a secret salt (ideally provided via config or environment),
    - the column name,
    - and the raw value.

    This makes it much harder to link the same identifier across
    different datasets that might use different salts or schemas.
    """
    salt = params.get("salt", "")
    column_name = params.get("column", "")
    digest_size = params.get("length", 32)

    def compute(value: Any) -> Any:
        if pd.isna(value):
            return value
        h = SHA256.new()
        # Order: salt -> column -> value
        if salt:
            h.update(str(salt).encode("utf-8"))
        if column_name:
            h.update(str(column_name).encode("utf-8"))
        h.update(str(value).encode("utf-8"))
        hex_digest = h.hexdigest()
        return hex_digest[:digest_size]

    return series.map(compute)


def shuffle_strategy(series: pd.Series, params: Dict[str, Any]) -> pd.Series:
    seed = _ensure_seed(params)
    rng = np.random.default_rng(seed)
    values = series.copy()
    mask = ~values.isna()
    shuffled = values[mask].sample(frac=1, random_state=seed).reset_index(drop=True)
    values.loc[mask] = shuffled.values
    return values


def generalize_strategy(series: pd.Series, params: Dict[str, Any]) -> pd.Series:
    granularity = params.get("granularity", "year")

    def generalize(value: Any) -> Any:
        if pd.isna(value):
            return value
        if isinstance(value, (int, float)):
            bucket = params.get("bucket_size", 10)
            start = (int(value) // bucket) * bucket
            return f"{start}-{start + bucket - 1}"
        try:
            dt = pd.to_datetime(value, errors="coerce")
        except Exception:
            dt = None
        if pd.notna(dt):
            if granularity == "decade":
                decade = (dt.year // 10) * 10
                return f"{decade}s"
            if granularity == "month":
                return f"{dt.year}-{dt.month:02d}"
            return str(dt.year)
        return params.get("fallback_label", "generalized")

    return series.map(generalize)


def noise_strategy(series: pd.Series, params: Dict[str, Any]) -> pd.Series:
    epsilon = params.get("epsilon", 1.0)
    sensitivity = params.get("sensitivity", 1.0)
    seed = _ensure_seed(params)
    rng = np.random.default_rng(seed)

    def apply_noise(value: Any) -> Any:
        if pd.isna(value):
            return value
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return value
        scale = sensitivity / max(epsilon, 1e-6)
        noise = rng.laplace(0, scale)
        return numeric + noise

    return series.map(apply_noise)


def tokenize_strategy(series: pd.Series, params: Dict[str, Any]) -> pd.Series:
    mapping: Dict[Any, str] = {}

    def assign(value: Any) -> Any:
        if pd.isna(value):
            return value
        if value not in mapping:
            mapping[value] = f"TOK-{len(mapping)+1:06d}"
        return mapping[value]

    return series.map(assign)


STRATEGIES: Dict[str, StrategyFunc] = {
    "pseudonym": pseudonym_strategy,
    "mask": mask_strategy,
    "hash": hash_strategy,
    "shuffle": shuffle_strategy,
    "generalize": generalize_strategy,
    "noise": noise_strategy,
    "tokenize": tokenize_strategy,
}


@dataclass
class StrategySelection:
    column: str
    technique: str
    params: Dict[str, Any]


def apply_strategy(series: pd.Series, selection: StrategySelection) -> pd.Series:
    func = STRATEGIES.get(selection.technique)
    if not func:
        raise ValueError(f"Unsupported technique: {selection.technique}")
    return func(series, selection.params)

