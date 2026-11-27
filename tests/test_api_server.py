"""Tests for Secret Wards HTTP API wrapper."""
from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path

import api_server


def _req(url: str, method: str = "GET", payload: dict | None = None) -> tuple[int, bytes, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as err:
        return err.code, err.read(), dict(err.headers)


def test_api_health_wards_snippet_and_custom_pipeline(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("RAKSHA_SECRET", "test-secret-for-unit-api-server")
    monkeypatch.setattr(api_server, "RUNS_DIR", tmp_path / "runs")
    srv = api_server.create_server("127.0.0.1", 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    try:
        code, raw, _ = _req(f"{base}/api/health")
        assert code == 200
        health = json.loads(raw)
        assert health["ok"] is True
        assert health["secret_configured"] is True
        assert set(health["wards_supported"]) == {"sanjeevani", "arogya", "jeevanjyoti", "dhh"}

        code, raw, _ = _req(f"{base}/api/wards/sanjeevani")
        assert code == 200
        ward = json.loads(raw)["ward"]
        assert ward["name"] == "Sanjeevani Hospital"
        assert ward["input_files_count"] > 0

        code, raw, _ = _req(
            f"{base}/api/sanitize-snippet",
            method="POST",
            payload={
                "filename": "opd_note.txt",
                "text": "Patient: Ramesh Verma\nAge: 42\nMob: 9811223344\nDx: Dengue fever, Plt 68000",
            },
        )
        assert code == 200
        snip = json.loads(raw)
        assert snip["ok"] is True
        assert snip["verified_clean"] is True
        assert "Ramesh Verma" not in snip["sanitized_text"]
        assert "9811223344" not in snip["sanitized_text"]
        assert "Dengue fever" in snip["sanitized_text"]
        assert "PSN-" in snip["psn_assigned"]

        code, raw, _ = _req(
            f"{base}/api/pipeline/run",
            method="POST",
            payload={
                "mode": "custom",
                "files": [
                    {
                        "path": "notes/ward_01.txt",
                        "content": "Name: Sunita Devi\nAadhaar: 2345 6789 0123\nDOB: 1984-05-12\nRx: Azithromycin 500mg",
                    }
                ],
            },
        )
        assert code == 200
        run = json.loads(raw)
        assert run["contract_ok"] is True
        assert run["report"]["counts"]["files_sanitized"] == 1
        assert "Azithromycin 500mg" in run["sanitized_preview"][0]["preview"]

        code, rep_raw, _ = _req(f"{base}{run['report_url']}")
        assert code == 200
        assert json.loads(rep_raw)["schema"] == "raksha-report/1"

        code, zip_raw, zip_hdrs = _req(f"{base}{run['download_url']}")
        assert code == 200
        assert zip_hdrs.get("Content-Type") == "application/zip"
        assert len(zip_raw) > 50
    finally:
        srv.shutdown()
        srv.server_close()


def test_api_fails_closed_without_secret(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("RAKSHA_SECRET", raising=False)
    monkeypatch.setattr(api_server, "RUNS_DIR", tmp_path / "runs")
    srv = api_server.create_server("127.0.0.1", 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        code, raw, _ = _req(f"http://127.0.0.1:{port}/api/sanitize-snippet", method="POST", payload={"text": "hello"})
        assert code == 503
        assert json.loads(raw)["ok"] is False
    finally:
        srv.shutdown()
        srv.server_close()
