from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
import yaml
from dotenv import load_dotenv

from anonymizer_tool import AnonymizationPipeline
from anonymizer_tool.config import ToolConfig, load_config

app = typer.Typer(help="Data anonymization CLI")


@app.command()
def anonymize(
    input: str = typer.Option(..., "--input", "-i", help="Input CSV/XLSX dataset"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Destination path for anonymized dataset"
    ),
    config: Optional[str] = typer.Option(
        None, "--config", "-c", help="YAML config with overrides"
    ),
    irreversible: bool = typer.Option(
        False, "--irreversible", help="Force irreversible techniques"
    ),
    inspect: bool = typer.Option(
        False, "--inspect", help="Only inspect, do not write output"
    ),
) -> None:
    # Load environment variables from a .env file if present (for secrets like ANONYMIZER_SECRET)
    load_dotenv()
    cfg = load_config(config)
    pipeline = AnonymizationPipeline(cfg, irreversible=irreversible)
    result = pipeline.anonymize(
        dataset_path=input,
        output_path=None if inspect else output or _derive_output_path(input),
        inspect_only=inspect,
    )
    typer.echo(result.report)
    if not inspect:
        typer.echo(f"Anonymized dataset written to {output or _derive_output_path(input)}")


@app.command()
def suggest_config(
    input: str = typer.Option(..., "--input", "-i", help="Input CSV/XLSX dataset"),
    output: str = typer.Option(
        "configs/generated_config.yaml",
        "--output",
        "-o",
        help="Path to write suggested YAML config",
    ),
    irreversible: bool = typer.Option(
        False,
        "--irreversible",
        help="Suggest techniques for irreversible anonymization mode",
    ),
) -> None:
    """
    Analyze a dataset and emit a YAML config template with suggested
    overrides and allowlist entries. You can review and tweak this file
    before running anonymization.
    """
    load_dotenv()

    cfg = ToolConfig()  # start from an empty/default config
    pipeline = AnonymizationPipeline(cfg, irreversible=irreversible)
    result = pipeline.inspect(dataset_path=input)

    detected_columns = {det.column for det in result.detections}
    overrides = []
    for det, sel in zip(result.detections, result.selections):
        overrides.append(
            {
                "column": det.column,
                "detector_hint": det.detector,
                "technique": sel.technique,
                "params": sel.params or {},
            }
        )

    # Any column that was not detected as sensitive becomes part of the allowlist.
    allowlist = [col for col in result.dataframe.columns if col not in detected_columns]

    config_dict = {
        "overrides": overrides,
        "allowlist": allowlist,
        "default_strategy": {
            "reversible": cfg.default_strategy.reversible,
            "irreversible": cfg.default_strategy.irreversible,
        },
    }

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump(config_dict, sort_keys=False), encoding="utf-8")

    typer.echo(f"Suggested config written to {out_path}")


def _derive_output_path(input_path: str) -> str:
    original = Path(input_path)
    return str(original.with_name(f"{original.stem}_anonymized{original.suffix}"))


if __name__ == "__main__":
    app()

