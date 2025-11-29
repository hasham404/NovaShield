## Data Anonymization Tool

This repository contains a reference implementation of the anonymization platform. The goal is to ingest structured datasets (CSV/Excel), detect sensitive columns, and apply configurable anonymization techniques while preserving analytical utility.

### Key Features
- Automatic sensitive-column detection using pattern- and semantic-based heuristics
- Multiple anonymization techniques: pseudonymization, tokenization, shuffling, generalization, hashing, and differential-privacy-style noise
- Rule overrides via YAML config for tight operator control
- Re-usable pipeline component plus Typer-powered CLI
- Re-identification risk report summarizing the actions taken

### Project Layout
```
.
├── README.md                  # This guide
├── requirements.txt           # Python dependencies
├── cli.py                     # Entry point for the CLI tool
├── configs/
│   └── sample_config.yaml     # Example override rules
├── data/
│   └── sample_customers.csv   # Example dataset for experimentation
└── anonymizer_tool/
    ├── __init__.py
    ├── config.py              # Config dataclasses and loaders
    ├── detectors.py           # Sensitive data detectors
    ├── strategies.py          # Individual anonymization techniques
    ├── pipeline.py            # End-to-end orchestration logic
    ├── report.py              # Reporting helpers
    └── utils.py               # Shared helpers
```

### Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Usage
```bash
python cli.py anonymize \
  --input data/sample_customers.csv \
  --output data/sample_customers_anonymized.csv \
  --config configs/sample_config.yaml \
  --irreversible
```

### Flask Web UI

For a simple browser-based interface:

```bash
python web_app.py
```

Then open `http://127.0.0.1:5000` in your browser, upload a CSV/Excel file, choose whether to inspect only or download an anonymized copy, and (optionally) enable irreversible anonymization.

Command options:
- `--input`: CSV or XLSX dataset
- `--output`: Destination CSV/XLSX (inferred from extension)
- `--config`: Optional YAML rule overrides
- `--irreversible`: Force irreversible techniques (hashing/noise) for all identifiers
- `--inspect`: Only show detection report without emitting a dataset

Additional details on configuration and extensibility live inside `docs/` (coming soon) and inline module docstrings.

### Testing
Run lint/tests after activating the virtual environment:
```bash
pytest
```
(A minimal smoke test is included; extend as needed for your datasets.)

For static security analysis, see `SAST_REPORT.md` and run:

```bash
bandit -r anonymizer_tool cli.py web_app.py
```

### Next Steps
- Extend detectors with ML models or dataset-specific dictionaries
- Integrate with Flask UI or workflow orchestrators
- Hook audit logs into your preferred SIEM

Contributions welcome—open an issue or PR to discuss new ideas.

