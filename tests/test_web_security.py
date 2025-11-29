from __future__ import annotations

import io


def _get_csrf_token(html: str) -> str:
    # Very small helper to pull the csrf token value out of the form.
    marker = 'name="csrf_token" value="'
    start = html.find(marker)
    assert start != -1
    start += len(marker)
    end = html.find('"', start)
    assert end != -1
    return html[start:end]


def test_csrf_token_required(client) -> None:
    """
    POST without a valid CSRF token should be rejected.
    """
    # Missing token
    resp = client.post("/", data={})
    assert resp.status_code == 400


def test_upload_rejects_unsupported_extension(client) -> None:
    """
    The backend should enforce allowed file extensions.
    """
    get_resp = client.get("/")
    token = _get_csrf_token(get_resp.get_data(as_text=True))

    data = {
        "csrf_token": token,
        "inspect": "on",
    }
    # Upload a .txt file which is not allowed.
    resp = client.post(
        "/",
        data={
            **data,
            "dataset": (io.BytesIO(b"not,csv"), "bad.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    # Expect a redirect back to index with a flash message.
    assert resp.status_code in (302, 303)


def test_xss_payload_is_escaped_in_report(client) -> None:
    """
    If a cell contains characters that look like HTML/JS, they must be
    HTML-escaped in the rendered report, so that they are not executed in
    the browser.
    """
    get_resp = client.get("/")
    token = _get_csrf_token(get_resp.get_data(as_text=True))

    # Craft a tiny CSV where one value contains a script tag.
    csv_bytes = b"Name,Age\n<script>alert(1)</script>,30\n"

    resp = client.post(
        "/",
        data={
            "csrf_token": token,
            "inspect": "on",
            "dataset": (io.BytesIO(csv_bytes), "xss.csv"),
        },
        content_type="multipart/form-data",
    )
    text = resp.get_data(as_text=True)
    assert resp.status_code == 200
    # Jinja should have escaped the payload inside the <pre> block.
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


def test_security_headers_set(client) -> None:
    """
    Basic security headers should be present on responses.
    """
    resp = client.get("/")
    headers = resp.headers
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("Content-Security-Policy") is not None


def test_download_config_name_validation(client) -> None:
    """
    The download-config route should reject invalid filenames.
    """
    # Invalid name with path traversal characters.
    resp = client.get("/download-config?name=../../secret.yaml")
    assert resp.status_code == 400


