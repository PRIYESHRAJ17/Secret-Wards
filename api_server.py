#!/usr/bin/env python3
"""HTTP API server exposing the Track 3 Secret Wards (Raksha) pipeline.

Uses Python standard library only (`http.server.ThreadingHTTPServer`) so
Track 3 offline/dependency constraints remain intact and `main.py` is unchanged.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

BACKEND_ROOT = Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import main as pipeline_main
from src.privacy import shift_days_for_key
from src.pseudonym import issue_psn
from src.sanitize.text import sanitize_text_doc
from src.secure import MissingSecretError, derive_keys
from src.verify import verify_sanitized_file

DEFAULT_HOST = os.environ.get("BACKEND_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("BACKEND_PORT", "8000"))
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_SNIPPET_BYTES = 256 * 1024
MAX_CUSTOM_FILES = 20
MAX_RECENT_RUNS = 12
RUN_ID_RE = re.compile(r"^[0-9a-f]{12,32}$")

RUNS_DIR = Path(os.environ.get("SECRET_WARDS_RUNS_DIR", str(BACKEND_ROOT / ".api_runs")))
DEV_INPUT_DIR = BACKEND_ROOT / "kit" / "dev" / "input"
DEV_TRUTH_PATH = BACKEND_ROOT / "kit" / "dev" / "truth" / "truth.json"
DEV_RAW_ATTACK_PATH = BACKEND_ROOT / "kit" / "dev" / "truth" / "raw_attack.json"
DEV_ATTACKER_DIR = BACKEND_ROOT / "kit" / "dev" / "attacker"
DEV_MANIFEST_PATH = BACKEND_ROOT / "kit" / "dev" / "dataset_manifest.json"
SCORING_TOML_PATH = BACKEND_ROOT / "kit" / "scoring.toml"
POLICY_PATH = BACKEND_ROOT / "config" / "policy.yaml"

WARDS_CATALOG: dict[str, dict[str, Any]] = {
    "sanjeevani": {
        "id": "sanjeevani",
        "name": "Sanjeevani Hospital",
        "code": "SNJ",
        "location": "Lucknow Urban Registry",
        "patterns": ("sanjeevani", "snj-"),
        "focus": "UHID + Aadhaar CSV/Discharge Bilingual Pipeline",
        "summary": "High-volume urban IPD/OPD discharge notes & registration exports linking UHID, Aadhaar, phone, and Hindi/Hinglish kinship headers.",
    },
    "arogya": {
        "id": "arogya",
        "name": "Arogya Kendra",
        "code": "ARG",
        "location": "Primary Care Clinic Node",
        "patterns": ("arogya",),
        "focus": "Legacy CSV Exports & Multi-script Clinic Notes",
        "summary": "Legacy clinic tabular exports with compound demographic columns, pincode prefixes, and Hinglish clinical remarks.",
    },
    "jeevanjyoti": {
        "id": "jeevanjyoti",
        "name": "Jeevan Jyoti Hospital",
        "code": "JJH",
        "location": "District Referral Center",
        "patterns": ("jeevan", "jjh-"),
        "focus": "TSV Ward Registries & Mixed-Script Summaries",
        "summary": "Tab-delimited ward registries (`jeevanjyoti_patients.tsv`) and referral summaries requiring deterministic HMAC pseudonyms across visits.",
    },
    "dhh": {
        "id": "dhh",
        "name": "District HQ Hospital (DHH)",
        "code": "DHH",
        "location": "Hardoi District Hub",
        "patterns": ("dhh",),
        "focus": "Nested JSON Patients, Claims & Diagnostic Labs",
        "summary": "Nested JSON patient trees (`dhh_patients.json`), billing claims, and FHIR/lab JSON bundles preserving schema integrity.",
    },
}

_PIPELINE_LOCK = threading.Lock()
_RUN_ORDER: list[str] = []


def _load_dotenv_if_present() -> None:
    """Populate unset environment variables from backend/.env if it exists."""
    env_file = BACKEND_ROOT / ".env"
    if not env_file.is_file():
        return
    for raw in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        key = k.strip()
        val = v.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


def _allowed_origin(req_origin: str | None) -> str:
    configured = os.environ.get("CORS_ALLOW_ORIGIN", "http://localhost:3000,http://127.0.0.1:3000").strip()
    if configured == "*":
        return "*"
    origins = [o.strip() for o in configured.split(",") if o.strip()]
    if req_origin and req_origin in origins:
        return req_origin
    return origins[0] if origins else "http://localhost:3000"


def _secret_bytes() -> bytes:
    return os.environ.get("RAKSHA_SECRET", "").encode("utf-8")


def _safe_rel_path(raw: str) -> str:
    norm = raw.replace("\\", "/").strip().lstrip("/")
    parts = [p for p in norm.split("/") if p and p not in (".", "..")]
    if not parts:
        raise ValueError("Invalid filename")
    return "/".join(parts)


def _prune_old_runs() -> None:
    while len(_RUN_ORDER) > MAX_RECENT_RUNS:
        oldest = _RUN_ORDER.pop(0)
        shutil.rmtree(RUNS_DIR / oldest, ignore_errors=True)


def _ward_files(ward_key: str) -> list[Path]:
    meta = WARDS_CATALOG.get(ward_key)
    if not meta or not DEV_INPUT_DIR.is_dir():
        return []
    pats = tuple(meta["patterns"])
    matched: list[Path] = []
    for p in sorted(DEV_INPUT_DIR.rglob("*")):
        if not p.is_file():
            continue
        low = p.name.casefold()
        if any(pat in low for pat in pats):
            matched.append(p)
    return matched


def _preview_sanitized(out_dir: Path, limit: int = 8) -> list[dict[str, Any]]:
    san_dir = out_dir / "sanitized"
    if not san_dir.is_dir():
        return []
    previews: list[dict[str, Any]] = []
    for f in sorted(san_dir.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(san_dir).as_posix()
        raw = f.read_text(encoding="utf-8", errors="replace")
        snippet = raw[:1200] + ("\n... [truncated]" if len(raw) > 1200 else "")
        previews.append({"path": f"sanitized/{rel}", "size_bytes": f.stat().st_size, "preview": snippet})
        if len(previews) >= limit:
            break
    return previews


def _validate_contract(inp_dir: Path, out_dir: Path) -> tuple[bool, list[str]]:
    errors: list[str] = []
    san = out_dir / "sanitized"
    if not san.is_dir():
        errors.append("missing output/sanitized/")
    report_path = out_dir / "report.json"
    if not report_path.is_file():
        errors.append("missing output/report.json")
    else:
        try:
            rep = json.loads(report_path.read_text(encoding="utf-8"))
            if rep.get("schema") != "raksha-report/1":
                errors.append("unexpected report schema")
        except ValueError as exc:
            errors.append(f"invalid report.json: {exc}")
    rj = out_dir / "records.jsonl"
    if not rj.is_file():
        errors.append("missing output/records.jsonl")
    return (len(errors) == 0, errors)


def _execute_dev_score(inp_dir: Path, out_dir: Path) -> dict[str, Any] | None:
    if not (DEV_TRUTH_PATH.is_file() and SCORING_TOML_PATH.is_file()):
        return None
    try:
        from tools.eval.score_local import score_output
        truth = json.loads(DEV_TRUTH_PATH.read_text(encoding="utf-8"))
        return score_output(
            inp_dir,
            out_dir,
            truth,
            SCORING_TOML_PATH,
            attacker_dir=DEV_ATTACKER_DIR if DEV_ATTACKER_DIR.is_dir() else None,
            raw_attack_path=DEV_RAW_ATTACK_PATH if DEV_RAW_ATTACK_PATH.is_file() else None,
            profile="small",
        )
    except Exception as exc:
        return {"error": f"scoring_unavailable: {type(exc).__name__}"}


def handle_health() -> tuple[int, dict[str, Any]]:
    policy = pipeline_main._load_policy(POLICY_PATH)
    secret_ok = bool(_secret_bytes())
    manifest = {}
    if DEV_MANIFEST_PATH.is_file():
        try:
            manifest = json.loads(DEV_MANIFEST_PATH.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}
    return 200, {
        "ok": True,
        "service": "secret-wards-api",
        "secret_configured": secret_ok,
        "dev_dataset_available": DEV_INPUT_DIR.is_dir(),
        "dataset_counts": manifest.get("counts"),
        "policy": policy,
        "wards_supported": list(WARDS_CATALOG.keys()),
    }


def handle_ward_detail(ward_key: str) -> tuple[int, dict[str, Any]]:
    meta = WARDS_CATALOG.get(ward_key)
    if not meta:
        return 404, {"ok": False, "error": f"Unknown hospital ward '{ward_key}'."}
    files = _ward_files(ward_key)
    by_channel: dict[str, int] = {}
    samples: list[dict[str, Any]] = []
    for p in files:
        rel = p.relative_to(DEV_INPUT_DIR).as_posix()
        ch = rel.split("/")[0] if "/" in rel else "root"
        by_channel[ch] = by_channel.get(ch, 0) + 1
        if len(samples) < 8:
            samples.append({"channel": ch, "file": p.name, "bytes": p.stat().st_size})
    return 200, {
        "ok": True,
        "ward": {
            "id": meta["id"],
            "name": meta["name"],
            "code": meta["code"],
            "location": meta["location"],
            "focus": meta["focus"],
            "summary": meta["summary"],
            "input_files_count": len(files),
            "channels": by_channel,
            "sample_files": samples,
        },
    }


def handle_sanitize_snippet(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    secret_raw = _secret_bytes()
    if not secret_raw:
        return 503, {"ok": False, "error": "RAKSHA_SECRET environment variable is not configured on the backend."}

    text = payload.get("text")
    if not isinstance(text, str) or not text.strip():
        return 400, {"ok": False, "error": "'text' must be a non-empty string."}
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_SNIPPET_BYTES:
        return 413, {"ok": False, "error": f"Snippet exceeds {MAX_SNIPPET_BYTES} byte limit."}

    filename = str(payload.get("filename") or "ward_note.txt").strip() or "ward_note.txt"
    try:
        rel_name = _safe_rel_path(filename)
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}

    ext = Path(rel_name).suffix.lower()
    t0 = time.monotonic()

    if ext in (".csv", ".tsv", ".json"):
        with tempfile.TemporaryDirectory(prefix="sw_snip_") as td:
            td_path = Path(td)
            inp_dir = td_path / "in"
            out_dir = td_path / "out"
            inp_dir.mkdir()
            (inp_dir / Path(rel_name).name).write_bytes(encoded)
            with _PIPELINE_LOCK:
                pipeline_main.run_pipeline(inp_dir, out_dir, POLICY_PATH)
            rep = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            previews = _preview_sanitized(out_dir, limit=1)
            status = "sanitized" if rep["counts"]["files_sanitized"] > 0 else "quarantined"
            san_text = ""
            if previews:
                san_file = out_dir / previews[0]["path"]
                san_text = san_file.read_text(encoding="utf-8", errors="replace")
            return 200, {
                "ok": True,
                "filename": rel_name,
                "format": ext.lstrip("."),
                "status": status,
                "sanitized_text": san_text,
                "counts": rep["counts"],
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
                "verified_clean": status == "sanitized",
            }

    keys = derive_keys(secret_raw)
    policy = pipeline_main._load_policy(POLICY_PATH)
    used_psns: set[str] = set()
    anchor = f"snippet:{rel_name}"
    psn = issue_psn(
        keys.pseudonym,
        anchor,
        used_psns,
        prefix=str(policy.get("psn_prefix", "PSN-")),
        n_chars=int(policy.get("psn_chars", 10)),
    )
    min_shift = int(policy.get("date_shift_min_days", 30))
    max_shift = int(policy.get("date_shift_max_days", 365))

    def shift_fn(key_str: str) -> int:
        return shift_days_for_key(keys.dateshift, key_str, min_days=min_shift, max_days=max_shift)

    sanitized_text, recs, idents, gen = sanitize_text_doc(text, rel_name, psn, shift_fn, policy)
    verified, reason = verify_sanitized_file("txt", None, None, None, rel_name, sanitized_text, secret_raw)
    return 200, {
        "ok": True,
        "filename": rel_name,
        "format": "txt",
        "status": "sanitized" if verified else "quarantined",
        "verification_reason": reason,
        "psn_assigned": psn,
        "sanitized_text": sanitized_text,
        "identifiers_detected": idents,
        "fields_generalized": gen,
        "records": recs,
        "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
        "verified_clean": verified,
    }


def handle_pipeline_run(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    secret_raw = _secret_bytes()
    if not secret_raw:
        return 503, {"ok": False, "error": "RAKSHA_SECRET environment variable is not configured on the backend."}

    mode = str(payload.get("mode") or "dev").strip().lower()
    include_score = bool(payload.get("include_score", True))
    if mode not in ("dev", "ward", "custom"):
        return 400, {"ok": False, "error": "mode must be 'dev', 'ward', or 'custom'."}

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:16]
    run_dir = RUNS_DIR / run_id
    out_dir = run_dir / "out"
    run_dir.mkdir(parents=True, exist_ok=True)

    temp_inp_ctx: tempfile.TemporaryDirectory[str] | None = None
    score_data: dict[str, Any] | None = None
    try:
        if mode == "dev":
            if not DEV_INPUT_DIR.is_dir():
                return 404, {"ok": False, "error": "kit/dev/input dataset is not present in backend."}
            inp_dir = DEV_INPUT_DIR
        elif mode == "ward":
            ward_key = str(payload.get("ward") or "").strip().lower()
            ward_files = _ward_files(ward_key)
            if not ward_files:
                return 404, {"ok": False, "error": f"No dataset files found for ward '{ward_key}'."}
            temp_inp_ctx = tempfile.TemporaryDirectory(prefix="sw_ward_")
            inp_dir = Path(temp_inp_ctx.name)
            for src in ward_files:
                rel = src.relative_to(DEV_INPUT_DIR)
                dst = inp_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        else:
            files_in = payload.get("files")
            if not isinstance(files_in, list) or not files_in:
                return 400, {"ok": False, "error": "custom mode requires a non-empty 'files' array."}
            if len(files_in) > MAX_CUSTOM_FILES:
                return 400, {"ok": False, "error": f"At most {MAX_CUSTOM_FILES} files allowed per request."}
            temp_inp_ctx = tempfile.TemporaryDirectory(prefix="sw_custom_")
            inp_dir = Path(temp_inp_ctx.name)
            for idx, item in enumerate(files_in):
                if not isinstance(item, dict):
                    return 400, {"ok": False, "error": f"files[{idx}] must be an object."}
                raw_path = str(item.get("path") or f"record_{idx + 1}.txt")
                content = item.get("content")
                if not isinstance(content, str):
                    return 400, {"ok": False, "error": f"files[{idx}].content must be a string."}
                rel = _safe_rel_path(raw_path)
                dst = inp_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(content, encoding="utf-8")

        with _PIPELINE_LOCK:
            rc = pipeline_main.run_pipeline(inp_dir, out_dir, POLICY_PATH)

        contract_ok, contract_errors = _validate_contract(inp_dir, out_dir)
        report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        records_lines = (out_dir / "records.jsonl").read_text(encoding="utf-8").splitlines()
        records_preview = [json.loads(line) for line in records_lines[:10] if line.strip()]
        quarantined_files = [ent for ent in report.get("files", []) if ent.get("status") != "sanitized"][:10]
        sanitized_previews = _preview_sanitized(out_dir, limit=6)

        if mode == "dev" and include_score:
            score_data = _execute_dev_score(inp_dir, out_dir)

        _RUN_ORDER.append(run_id)
        _prune_old_runs()

        return 200, {
            "ok": rc == 0 and contract_ok,
            "run_id": run_id,
            "mode": mode,
            "contract_ok": contract_ok,
            "contract_errors": contract_errors,
            "report": report,
            "score": score_data,
            "sanitized_preview": sanitized_previews,
            "quarantined_files": quarantined_files,
            "records_preview": records_preview,
            "download_url": f"/api/outputs/{run_id}/bundle.zip",
            "report_url": f"/api/outputs/{run_id}/report.json",
        }
    except MissingSecretError:
        shutil.rmtree(run_dir, ignore_errors=True)
        return 503, {"ok": False, "error": "RAKSHA_SECRET environment variable is not configured on the backend."}
    except Exception as exc:
        shutil.rmtree(run_dir, ignore_errors=True)
        return 500, {"ok": False, "error": f"Pipeline failed: {type(exc).__name__}"}
    finally:
        if temp_inp_ctx is not None:
            temp_inp_ctx.cleanup()


class SecretWardsHandler(BaseHTTPRequestHandler):
    server_version = "SecretWardsAPI/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_cors_headers(self) -> None:
        origin = _allowed_origin(self.headers.get("Origin"))
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Expose-Headers", "Content-Disposition")
        self.send_header("Vary", "Origin")

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("Request body empty or too large")
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            code, body = handle_health()
            self._send_json(code, body)
            return

        if path == "/api/wards":
            wards = [handle_ward_detail(k)[1]["ward"] for k in WARDS_CATALOG]
            self._send_json(200, {"ok": True, "wards": wards})
            return

        if path.startswith("/api/wards/"):
            ward_key = path[len("/api/wards/"):].strip("/").lower()
            code, body = handle_ward_detail(ward_key)
            self._send_json(code, body)
            return

        m_rep = re.fullmatch(r"/api/outputs/([0-9a-f]{12,32})/report\.json", path)
        if m_rep:
            run_id = m_rep.group(1)
            rep_file = RUNS_DIR / run_id / "out" / "report.json"
            if not rep_file.is_file():
                self._send_json(404, {"ok": False, "error": "Run report not found."})
                return
            data = rep_file.read_bytes()
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        m_zip = re.fullmatch(r"/api/outputs/([0-9a-f]{12,32})/bundle\.zip", path)
        if m_zip:
            run_id = m_zip.group(1)
            out_dir = RUNS_DIR / run_id / "out"
            if not out_dir.is_dir():
                self._send_json(404, {"ok": False, "error": "Run output bundle not found."})
                return
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
                tmp_zip = Path(tf.name)
            try:
                with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for p in sorted(out_dir.rglob("*")):
                        if p.is_file():
                            zf.write(p, p.relative_to(out_dir).as_posix())
                data = tmp_zip.read_bytes()
            finally:
                tmp_zip.unlink(missing_ok=True)
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="secret-wards-{run_id}.zip"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self._send_json(404, {"ok": False, "error": f"Unknown endpoint: {path}"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            payload = self._read_json_body()
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": f"Invalid JSON payload: {exc}"})
            return

        if path == "/api/sanitize-snippet":
            code, body = handle_sanitize_snippet(payload)
            self._send_json(code, body)
            return

        if path == "/api/pipeline/run":
            code, body = handle_pipeline_run(payload)
            self._send_json(code, body)
            return

        self._send_json(404, {"ok": False, "error": f"Unknown endpoint: {path}"})


def create_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    _load_dotenv_if_present()
    return ThreadingHTTPServer((host, port), SecretWardsHandler)


def main() -> int:
    _load_dotenv_if_present()
    srv = create_server(DEFAULT_HOST, DEFAULT_PORT)
    print(f"Secret Wards API server listening on http://{DEFAULT_HOST}:{DEFAULT_PORT}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
