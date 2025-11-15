from __future__ import annotations

import os
import tempfile
from pathlib import Path
from zipfile import ZipFile

import yaml
from dotenv import load_dotenv
from flask import Flask, render_template_string, request, send_file, redirect, url_for, flash
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from anonymizer_tool import AnonymizationPipeline
from anonymizer_tool.config import ToolConfig, load_config


load_dotenv()  # Load secrets like ANONYMIZER_SECRET from a .env file if present

app = Flask(__name__)
app.secret_key = "change-me-in-production"


BASE_DIR = Path(__file__).resolve().parent


PAGE_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>NovaShield Anonymization Studio</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />
    <style>
      :root {
        --bg-gradient: radial-gradient(circle at top left, #0f172a, #020617 45%, #111827);
        --accent-primary: #38bdf8;
        --accent-secondary: #a855f7;
      }
      body {
        min-height: 100vh;
        background: var(--bg-gradient);
        color: #e5e7eb;
        display: flex;
        align-items: flex-start;
        justify-content: center;
        padding: 32px 12px;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      }
      .app-shell {
        width: 100%;
        max-width: 1280px;
      }
      .glass-card {
        background: radial-gradient(circle at top left, rgba(56, 189, 248, 0.03), transparent 60%),
                    radial-gradient(circle at bottom right, rgba(168, 85, 247, 0.08), transparent 60%),
                    rgba(15, 23, 42, 0.94);
        border-radius: 18px;
        border: 1px solid rgba(148, 163, 184, 0.4);
        box-shadow:
          0 24px 60px rgba(15, 23, 42, 0.8),
          0 0 0 1px rgba(15, 23, 42, 0.8);
        backdrop-filter: blur(16px);
      }
      .hero-title {
        letter-spacing: 0.04em;
      }
      .pill {
        border-radius: 999px;
        padding: 4px 12px;
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }
      pre {
        white-space: pre-wrap;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono",
          "Courier New", monospace;
        font-size: 0.78rem;
        max-height: 420px;
        overflow: auto;
      }
      .form-label small {
        color: #9ca3af;
        font-weight: 400;
      }
      .btn-primary {
        background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
        border: none;
      }
      .btn-primary:focus,
      .btn-primary:hover {
        background: linear-gradient(135deg, #0ea5e9, #8b5cf6);
      }
      .mode-card {
        background: rgba(15, 23, 42, 0.96);
        border-radius: 14px;
        border: 1px solid rgba(75, 85, 99, 0.7);
      }
      .stat-card {
        background: rgba(15, 23, 42, 0.9);
        border-radius: 12px;
        border: 1px solid rgba(31, 41, 55, 0.9);
        padding: 10px 12px;
      }
      .stat-label {
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: .08em;
        color: #9ca3af;
      }
      .stat-value {
        font-size: 1.05rem;
        font-weight: 600;
      }
      .check-pill {
        font-size: 0.78rem;
        border-radius: 999px;
        padding: 4px 10px;
        background: rgba(16, 185, 129, 0.12);
        border: 1px solid rgba(16, 185, 129, 0.4);
        color: #6ee7b7;
      }
      @media (max-width: 768px) {
        body {
          padding-top: 20px;
        }
        .glass-card {
          margin-top: 12px;
        }
      }
    </style>
  </head>
  <body>
    <main class="app-shell">
      <header class="d-flex flex-wrap justify-content-between align-items-center mb-4">
        <div class="d-flex align-items-center gap-3">
          <div
            class="pill bg-dark border border-info text-info fw-semibold d-inline-flex align-items-center"
          >
            <span class="rounded-circle bg-success me-2" style="width:8px;height:8px;"></span>
            Secure SDLC · Privacy by Design
          </div>
        </div>
        <span class="pill bg-dark border border-secondary text-secondary d-none d-sm-inline">
          Reversible &amp; Irreversible anonymization · Utility-aware masking
        </span>
      </header>

      <section class="glass-card p-4 p-md-5 mb-4">
        <div class="row g-4 align-items-start">
          <div class="col-lg-6">
            <h1 class="hero-title h3 text-light mb-2">
              NovaShield Data Anonymization Studio
            </h1>
            <p class="text-secondary mb-3">
              Upload a structured dataset, inspect detected sensitive fields, and generate a
              privacy-preserving copy that retains analytical value for BI, ML and research.
            </p>

            <div class="row g-3 mb-3">
              <div class="col-6 col-md-4">
                <div class="stat-card h-100">
                  <div class="stat-label mb-1">Techniques</div>
                  <div class="stat-value">7+</div>
                  <small class="text-muted">Mask, hash, shuffle, noise, and more.</small>
                </div>
              </div>
              <div class="col-6 col-md-4">
                <div class="stat-card h-100">
                  <div class="stat-label mb-1">Modes</div>
                  <div class="stat-value">2</div>
                  <small class="text-muted">Reversible &amp; irreversible flows.</small>
                </div>
              </div>
              <div class="col-12 col-md-4">
                <div class="stat-card h-100 d-flex flex-column justify-content-between">
                  <div>
                    <div class="stat-label mb-1">Compliance</div>
                    <div class="stat-value">HIPAA / GDPR</div>
                  </div>
                  <small class="text-muted">Supports k-style grouping &amp; utility checks.</small>
                </div>
              </div>
            </div>

            <div class="row g-3">
              <div class="col-sm-6">
                <div class="mode-card p-3 h-100">
                  <div class="d-flex align-items-center mb-1">
                    <span class="badge bg-primary-subtle text-primary me-2">Reversible</span>
                    <small class="text-muted">Pseudonyms &amp; tokens</small>
                  </div>
                  <small class="text-secondary">
                    Keep a conceptual mapping to real identities for internal use-cases while
                    hiding direct identifiers in the exported dataset.
                  </small>
                </div>
              </div>
              <div class="col-sm-6">
                <div class="mode-card p-3 h-100">
                  <div class="d-flex align-items-center mb-1">
                    <span class="badge bg-danger-subtle text-danger me-2">Irreversible</span>
                    <small class="text-muted">Hash &amp; shuffle</small>
                  </div>
                  <small class="text-secondary">
                    Break all links to real people while preserving statistical properties and
                    distributions for research and reporting.
                  </small>
                </div>
              </div>
            </div>
          </div>

          <div class="col-lg-6">
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert alert-warning py-2 mb-3">
                  {{ messages[0] }}
                </div>
              {% endif %}
            {% endwith %}

            <form
              id="anonymizer-form"
              method="post"
              enctype="multipart/form-data"
              class="bg-dark border border-secondary rounded-3 p-3"
            >
              <div class="mb-3">
                <label for="dataset" class="form-label">
                  Dataset file
                  <small>(CSV or Excel)</small>
                </label>
                <input
                  class="form-control form-control-sm"
                  type="file"
                  id="dataset"
                  name="dataset"
                  accept=".csv, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet, application/vnd.ms-excel"
                  required
                />
              </div>

              <div class="d-flex flex-column flex-sm-row gap-3 mb-3">
                <div class="form-check form-switch">
                  <input
                    class="form-check-input"
                    type="checkbox"
                    id="inspect"
                    name="inspect"
                  />
                  <label class="form-check-label small" for="inspect">
                    Inspect only
                    <span class="text-muted d-block">Show detection report, no download</span>
                  </label>
                </div>
                <div class="form-check form-switch">
                  <input
                    class="form-check-input"
                    type="checkbox"
                    id="irreversible"
                    name="irreversible"
                  />
                  <label class="form-check-label small" for="irreversible">
                    Irreversible mode
                    <span class="text-muted d-block">Hash IDs &amp; shuffle metrics</span>
                  </label>
                </div>
              </div>

              <div class="d-flex align-items-center justify-content-between">
                <button
                  id="run-btn"
                  type="submit"
                  class="btn btn-primary btn-sm px-3 d-inline-flex align-items-center"
                >
                  <span class="spinner-border spinner-border-sm me-2 d-none" id="run-spinner"></span>
                  Run anonymization
                </button>
                <div class="d-none d-sm-flex flex-column align-items-end">
                  <small class="text-muted">
                    Processing happens locally on this machine.
                  </small>
                  <small class="text-muted">
                    Inspect mode uses a sample for faster previews.
                  </small>
                </div>
              </div>
            </form>
          </div>
        </div>
      </section>

      {% if report %}
        <section class="glass-card p-3 p-md-4">
          <div class="d-flex flex-wrap justify-content-between align-items-center mb-2 gap-2">
            <div class="d-flex align-items-center gap-2">
              <h2 class="h6 mb-0 text-light">Detection &amp; Anonymization Report</h2>
              {% if ldiv_note %}
                <span class="badge bg-warning-subtle text-warning">l-diversity applied</span>
              {% endif %}
            </div>
            {% if utility_line %}
              <span class="badge bg-success-subtle text-success small">
                {{ utility_line }}
              </span>
            {% endif %}
          </div>
          {% if ldiv_note %}
            <p class="text-muted small mb-2">
              {{ ldiv_note }}
            </p>
          {% endif %}
          <pre class="bg-black text-light border border-secondary rounded-3 p-3">{{ report }}</pre>
        </section>
      {% endif %}
    </main>

    <script>
      (function () {
        const form = document.getElementById("anonymizer-form");
        const btn = document.getElementById("run-btn");
        const spinner = document.getElementById("run-spinner");
        if (!form || !btn || !spinner) return;

        form.addEventListener("submit", function () {
          btn.disabled = true;
          spinner.classList.remove("d-none");
        });
      })();
    </script>
  </body>
</html>
"""


def _load_default_config():
    # Prefer healthcare-specific config if present, otherwise fall back to sample/default
    healthcare_cfg = BASE_DIR / "configs" / "healthcare_config.yaml"
    sample_cfg = BASE_DIR / "configs" / "sample_config.yaml"
    if healthcare_cfg.exists():
        return load_config(str(healthcare_cfg))
    if sample_cfg.exists():
        return load_config(str(sample_cfg))
    return load_config(None)


def _generate_config_for_dataset(dataset_path: str, irreversible: bool) -> ToolConfig:
    """
    Inspect the uploaded dataset and automatically build a YAML config
    tailored to its schema. The generated config is written to
    configs/generated/<dataset_name>_config.yaml and also returned as a
    ToolConfig object for immediate use by the pipeline.
    """
    base_cfg = ToolConfig()
    pipeline = AnonymizationPipeline(base_cfg, irreversible=irreversible)
    result = pipeline.inspect(dataset_path=dataset_path)

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

    allowlist = [col for col in result.dataframe.columns if col not in detected_columns]

    config_dict = {
        "overrides": overrides,
        "allowlist": allowlist,
        "default_strategy": {
            "reversible": base_cfg.default_strategy.reversible,
            "irreversible": base_cfg.default_strategy.irreversible,
        },
    }

    # Persist the generated config so it can be inspected or reused later.
    out_dir = BASE_DIR / "configs" / "generated"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{Path(dataset_path).stem}_config.yaml"
    out_path.write_text(yaml.safe_dump(config_dict, sort_keys=False), encoding="utf-8")

    # Build a ToolConfig instance from the generated dictionary.
    return ToolConfig.from_dict(config_dict)


@app.route("/", methods=["GET", "POST"])
def index():
    report_text = None
    utility_line = None
    ldiv_note = None

    if request.method == "POST":
        file = request.files.get("dataset")
        inspect_only = bool(request.form.get("inspect"))
        irreversible = bool(request.form.get("irreversible"))

        if not file or file.filename == "":
            flash("Please choose a dataset file.")
            return redirect(url_for("index"))

        # Use a temporary directory for processing
        tmpdir = tempfile.mkdtemp(prefix="anonymizer_")
        input_path = os.path.join(tmpdir, file.filename)
        file.save(input_path)

        # Automatically generate a dataset-specific config based on the
        # uploaded file, then use it for anonymization.
        cfg = _generate_config_for_dataset(input_path, irreversible=irreversible)
        pipeline = AnonymizationPipeline(cfg, irreversible=irreversible)

        if inspect_only:
            # Run anonymization in-memory (no file download) on a sampled
            # subset so that the preview stays responsive even for large
            # datasets. The report still reflects the full-column detection
            # plus approximate utility on the sample.
            result = pipeline.anonymize(
                dataset_path=input_path,
                output_path=None,
                inspect_only=False,
                sample_rows=5000,
            )
            report_text = result.report or ""

            for line in report_text.splitlines():
                if line.strip().startswith("Approximate data utility score"):
                    utility_line = line.strip()
                    break

            if "Suppressed" in report_text:
                ldiv_note = (
                    "Some 'Medical Condition' values were suppressed to satisfy "
                    "a basic l-diversity constraint."
                )

            return render_template_string(
                PAGE_TEMPLATE,
                report=report_text,
                utility_line=utility_line,
                ldiv_note=ldiv_note,
            )

        output_filename = f"anonymized_{file.filename}"
        output_path = os.path.join(tmpdir, output_filename)
        result = pipeline.anonymize(
            dataset_path=input_path,
            output_path=output_path,
            inspect_only=False,
        )

        # Build a human-readable PDF report alongside the anonymized dataset.
        report_text = result.report or ""
        report_name = "anonymization_report.pdf"
        report_path = os.path.join(tmpdir, report_name)

        header_lines = [
            "Anonymization Report",
            "====================",
            "",
            f"Source file: {file.filename}",
            f"Irreversible mode: {'yes' if irreversible else 'no'}",
            "",
        ]
        full_text = "\n".join(header_lines) + report_text

        c = canvas.Canvas(report_path, pagesize=letter)
        width, height = letter
        x_margin = 40
        y = height - 50
        for line in full_text.splitlines():
            if y < 60:  # start new page if we reach the bottom
                c.showPage()
                y = height - 50
            c.drawString(x_margin, y, line)
            y -= 12
        c.showPage()
        c.save()

        # Package dataset + report into a single ZIP for download.
        bundle_name = f"anonymized_{Path(file.filename).stem}_bundle.zip"
        bundle_path = os.path.join(tmpdir, bundle_name)
        with ZipFile(bundle_path, "w") as zf:
            zf.write(output_path, arcname=output_filename)
            zf.write(report_path, arcname=report_name)

        return send_file(bundle_path, as_attachment=True, download_name=bundle_name)

    return render_template_string(PAGE_TEMPLATE, report=report_text, utility_line=utility_line, ldiv_note=ldiv_note)


if __name__ == "__main__":
    app.run(debug=True)


