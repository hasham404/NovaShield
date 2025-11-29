from __future__ import annotations

import os
import re
import secrets
import shutil
import tempfile
from pathlib import Path
from zipfile import ZipFile

import yaml
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    after_this_request,
    flash,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from anonymizer_tool import AnonymizationPipeline
from anonymizer_tool.config import ToolConfig, load_config


load_dotenv()  # Load secrets like ANONYMIZER_SECRET / APP_SECRET_KEY from a .env file if present

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY") or os.getenv("ANONYMIZER_SECRET") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit


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
        /* Default (dark) theme tokens */
        --bg-color: #000000;
        --card-bg: #050814;
        --accent-primary: #6366f1;
        --accent-secondary: #22c55e;
        --text-main: #f9fafb;
      }
      [data-theme="light"] {
        /* Light theme overrides */
        --bg-color: #f9fafb;
        --card-bg: #ffffff;
        --accent-primary: #2563eb;
        --accent-secondary: #22c55e;
        --text-main: #111827;
      }
      body {
        min-height: 100vh;
        background: radial-gradient(circle at top left, #111827, transparent 55%),
                    radial-gradient(circle at bottom right, #020617, transparent 55%),
                    var(--bg-color);
        color: var(--text-main);
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
        background: var(--card-bg);
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
        background: #020617;
        border-radius: 14px;
        border: 1px solid rgba(75, 85, 99, 0.7);
        color: #f9fafb;  /* ensure text is light on dark card in both themes */
      }
      .stat-card {
        background: #020617;
        border-radius: 12px;
        border: 1px solid rgba(31, 41, 55, 0.9);
        padding: 10px 12px;
        color: #f9fafb;  /* ensure text is light on dark card in both themes */
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
      .stat-card small {
        color: #e5e7eb;  /* lighter text for readability on dark background */
      }
      /* Ensure dark panels keep light text in both themes */
      .bg-dark {
        color: #f9fafb;
      }
      .bg-dark .form-label,
      .bg-dark .form-check-label,
      .bg-dark .text-secondary {
        color: #e5e7eb;
      }
      /* Ensure text that is white in dark mode becomes dark in light mode */
      [data-theme="light"] .text-light {
        color: #111827 !important;
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
  <body data-theme="dark">
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
        <div class="d-flex align-items-center gap-2">
          <span class="pill bg-dark border border-secondary text-secondary d-none d-sm-inline">
            Reversible &amp; Irreversible anonymization · Utility-aware masking
          </span>
          <button
            id="theme-toggle"
            type="button"
            class="btn btn-sm btn-outline-light"
            style="border-radius: 999px; font-size: 0.7rem;"
          >
            Light theme
          </button>
        </div>
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

            {% if num_columns is not none %}
              <div class="d-flex flex-wrap gap-2 align-items-center mb-2">
                <span class="check-pill">
                  Columns: {{ num_columns }}
                </span>
                <span class="check-pill">
                  Sensitive: {{ num_sensitive or 0 }}
                </span>
                <span class="check-pill">
                  Mode: {{ mode_label or 'Reversible' }}
                </span>
                {% if utility_score is not none %}
                  <span class="check-pill">
                    Utility: {{ '%.1f' % utility_score }}/100
                  </span>
                {% endif %}
              </div>
            {% endif %}

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
              <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
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
          {% if column_chips %}
            <div class="mb-2 d-flex flex-wrap gap-1">
              {% for chip in column_chips %}
                <span class="badge bg-secondary-subtle text-secondary">
                  {{ chip.name }} · {{ chip.technique }}
                </span>
              {% endfor %}
            </div>
          {% endif %}
          {% if ldiv_note %}
            <p class="text-muted small mb-2">
              {{ ldiv_note }}
            </p>
          {% endif %}
          <div class="position-relative">
            <button
              id="report-fullscreen-toggle"
              type="button"
              class="btn btn-sm btn-outline-light position-absolute"
              style="top: 8px; right: 8px; z-index: 2; font-size: 0.7rem;"
            >
              Toggle full screen
            </button>
            <pre
              id="report-block"
              class="bg-black text-light border border-secondary rounded-3 p-3"
              style="transition: max-height 0.2s ease;"
            >{{ report }}</pre>
          </div>

          {% if cfg_name %}
            <div class="mt-3 d-flex flex-wrap align-items-center gap-2">
              <p class="small text-muted mb-0">
                A dataset-specific YAML config was generated for this run:
                <code class="small">configs/generated/{{ cfg_name }}</code>
              </p>
              <a
                class="btn btn-sm btn-outline-info"
                href="{{ url_for('download_config', name=cfg_name) }}"
              >
                Download YAML config
              </a>
            </div>
          {% endif %}
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

      // Theme toggle (dark / light) persisted in localStorage.
      (function () {
        const root = document.body;
        const toggle = document.getElementById("theme-toggle");
        if (!root || !toggle) return;

        const stored = window.localStorage.getItem("nova-theme") || "dark";
        root.setAttribute("data-theme", stored);
        toggle.textContent = stored === "light" ? "Dark theme" : "Light theme";

        toggle.addEventListener("click", function () {
          const current = root.getAttribute("data-theme") || "dark";
          const next = current === "dark" ? "light" : "dark";
          root.setAttribute("data-theme", next);
          window.localStorage.setItem("nova-theme", next);
          toggle.textContent = next === "light" ? "Dark theme" : "Light theme";
        });
      })();

      // Full-screen toggle for the report area.
      (function () {
        const btn = document.getElementById("report-fullscreen-toggle");
        const block = document.getElementById("report-block");
        if (!btn || !block) return;

        btn.addEventListener("click", function () {
          if (block.classList.contains("report-fullscreen")) {
            block.classList.remove("report-fullscreen");
            block.style.maxHeight = "420px";
          } else {
            block.classList.add("report-fullscreen");
            block.style.maxHeight = "80vh";
          }
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


def _generate_config_for_dataset(dataset_path: str, irreversible: bool) -> tuple[ToolConfig, Path]:
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

    # Build a ToolConfig instance from the generated dictionary and return
    # it together with the path so the UI can offer the YAML for download.
    return ToolConfig.from_dict(config_dict), out_path


@app.after_request
def set_security_headers(response):
    """
    Set a small set of security-related HTTP headers to harden the UI.
    """
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    # Content-Security-Policy allows our inline styles/scripts and Bootstrap CDN.
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    return response


@app.route("/", methods=["GET", "POST"])
def index():
    report_text = None
    utility_line = None
    ldiv_note = None

    if request.method == "POST":
        # Basic CSRF protection: verify a token stored in the session.
        token = request.form.get("csrf_token")
        if not token or token != session.get("csrf_token"):
            abort(400)

        file = request.files.get("dataset")
        inspect_only = bool(request.form.get("inspect"))
        irreversible = bool(request.form.get("irreversible"))

        if not file or file.filename == "":
            flash("Please choose a dataset file.")
            return redirect(url_for("index"))

        # Validate file extension to avoid unsupported types.
        filename = file.filename or ""
        ext = os.path.splitext(filename)[1].lower()
        if ext not in {".csv", ".xlsx"}:
            flash("Unsupported file type. Please upload a CSV or Excel file.")
            return redirect(url_for("index"))

        # Use a temporary directory for processing. We register a cleanup
        # handler so that raw uploads and intermediate artifacts do not
        # accumulate on disk.
        tmpdir = tempfile.mkdtemp(prefix="anonymizer_")

        @after_this_request
        def _cleanup(response):
            shutil.rmtree(tmpdir, ignore_errors=True)
            return response

        # Sanitize the filename to avoid any path components or unexpected
        # characters. This name is only used within the temporary directory
        # and in user-facing downloads.
        safe_name = re.sub(r"[^A-Za-z0-9_.\\-]", "_", os.path.basename(filename))
        input_path = os.path.join(tmpdir, safe_name)
        file.save(input_path)

        # Automatically generate a dataset-specific config based on the
        # uploaded file, then use it for anonymization.
        cfg, cfg_path = _generate_config_for_dataset(input_path, irreversible=irreversible)
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

            # Build lightweight structured metadata for the UI summary.
            columns = list(result.dataframe.columns)
            num_columns = len(columns)
            num_sensitive = len(result.detections)
            mode_label = "Irreversible" if irreversible else "Reversible"

            column_chips = []
            sel_map = {sel.column: sel for sel in result.selections}
            for det in result.detections:
                sel = sel_map.get(det.column)
                technique = sel.technique if sel else "-"
                column_chips.append(
                    {
                        "name": det.column,
                        "detector": det.detector,
                        "technique": technique,
                    }
                )

            # Try to extract numeric utility score from the text line.
            utility_score = None
            if utility_line:
                try:
                    utility_score = float(utility_line.split(":")[-1].strip())
                except Exception:
                    utility_score = None

            return render_template_string(
                PAGE_TEMPLATE,
                report=report_text,
                utility_line=utility_line,
                ldiv_note=ldiv_note,
                cfg_name=cfg_path.name,
                columns=columns,
                num_columns=num_columns,
                num_sensitive=num_sensitive,
                mode_label=mode_label,
                utility_score=utility_score,
                column_chips=column_chips,
            )

        output_filename = f"anonymized_{safe_name}"
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

    # Initial GET or fall-through: render page with empty/default metadata.
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return render_template_string(
        PAGE_TEMPLATE,
        report=report_text,
        utility_line=utility_line,
        ldiv_note=ldiv_note,
        cfg_name=None,
        columns=None,
        num_columns=None,
        num_sensitive=None,
        mode_label=None,
        utility_score=None,
        column_chips=None,
        csrf_token=session["csrf_token"],
    )


@app.route("/download-config")
def download_config():
    """
    Download a generated YAML config from configs/generated by filename.
    """
    name = request.args.get("name")
    if not name:
        abort(400)
    # Only allow simple filenames to prevent path traversal.
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
        abort(400)
    cfg_path = BASE_DIR / "configs" / "generated" / name
    if not cfg_path.exists():
        abort(404)
    return send_file(str(cfg_path), as_attachment=True, download_name=name)


if __name__ == "__main__":
    # Debug mode should only be enabled explicitly for local development by
    # setting FLASK_DEBUG=1 in the environment.
    debug = os.getenv("FLASK_DEBUG") == "1"
    app.run(debug=debug)


