from __future__ import annotations

import io
import zipfile


def _get_csrf_token(html: str) -> str:
    marker = 'name="csrf_token" value="'
    start = html.find(marker)
    assert start != -1
    start += len(marker)
    end = html.find('"', start)
    assert end != -1
    return html[start:end]


def test_inspect_flow_shows_report(client) -> None:
    """
    Full inspect-only flow: upload a tiny CSV and verify that the response
    contains the Detection & Anonymization Report section.
    """
    get_resp = client.get("/")
    token = _get_csrf_token(get_resp.get_data(as_text=True))

    csv_bytes = b"Name,Age\nAlice,30\nBob,40\n"
    resp = client.post(
        "/",
        data={
            "csrf_token": token,
            "inspect": "on",
            "dataset": (io.BytesIO(csv_bytes), "demo.csv"),
        },
        content_type="multipart/form-data",
    )
    text = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "Detection &amp; Anonymization Report" in text
    assert "Name" in text


def test_full_anonymization_downloads_bundle(client, tmp_path) -> None:
    """
    End-to-end: upload a CSV for full anonymization and verify that the
    response is a ZIP bundle containing a CSV and a PDF report.
    """
    get_resp = client.get("/")
    token = _get_csrf_token(get_resp.get_data(as_text=True))

    csv_bytes = b"Name,Age\nAlice,30\nBob,40\n"
    resp = client.post(
        "/",
        data={
            "csrf_token": token,
            "dataset": (io.BytesIO(csv_bytes), "demo.csv"),
        },
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    # Response should be a ZIP archive.
    bundle_path = tmp_path / "bundle.zip"
    bundle_path.write_bytes(resp.data)
    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = zf.namelist()
        assert any(name.endswith(".csv") for name in names)
        assert any(name.endswith(".pdf") for name in names)


