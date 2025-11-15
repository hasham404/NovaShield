from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class OverrideRule:
    column: str
    detector_hint: str
    technique: str
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DefaultStrategy:
    reversible: str = "pseudonym"
    irreversible: str = "hash"


@dataclass
class ToolConfig:
    overrides: List[OverrideRule] = field(default_factory=list)
    allowlist: List[str] = field(default_factory=list)
    default_strategy: DefaultStrategy = field(default_factory=DefaultStrategy)

    @staticmethod
    def from_dict(raw: Dict[str, Any]) -> "ToolConfig":
        overrides = [
            OverrideRule(
                column=item["column"],
                detector_hint=item.get("detector_hint", "custom"),
                technique=item["technique"],
                params=item.get("params", {}),
            )
            for item in raw.get("overrides", [])
        ]
        allowlist = raw.get("allowlist") or []
        default_strategy = DefaultStrategy(
            **raw.get("default_strategy", {})  # type: ignore[arg-type]
        )
        return ToolConfig(
            overrides=overrides,
            allowlist=allowlist,
            default_strategy=default_strategy,
        )


def load_config(path: Optional[str]) -> ToolConfig:
    if not path:
        return ToolConfig()
    data = yaml.safe_load(Path(path).read_text())
    if not data:
        return ToolConfig()
    return ToolConfig.from_dict(data)

