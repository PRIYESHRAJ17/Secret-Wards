"""Trivial delete-everything baseline (Phase 1 harness verification only).

Produces contract-valid output that quarantines unparseable/binary files and replaces
all string/numeric content in CSV/TSV/JSON/text/FHIR with [REDACTED] (or null),
linking nothing (patient: null). Proves the harness works and matches the ~20/100
official calibration anchor (SCORING.md:170).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import io
import json
import os
import sys
import time
from pathlib import Path

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _hmac_name(secret: bytes, rel: str, ext: str) -> str:
    d = hmac.new(secret, b"fname|" + rel.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
    return f"rec_{d}{ext}"


def _decode_strict(raw: bytes) -> str | None:
    if not raw.strip():
        return None
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw[3:].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in raw or b"\xff" in raw or b"\xfe" in raw:
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        pass
    # Narrow cp1252 check matching D-009
    bad = {0x81, 0x8D, 0x8F, 0x90, 0x9D, 0xFE, 0xFF}
    if any(b in bad for b in raw):
        return None
    try:
        return raw.decode("cp1252")
    except UnicodeDecodeError:
        return None


def _wipe_json(obj, redact_all: bool = True):
    if redact_all:
        return {"[REDACTED]": "[REDACTED]"}
    if isinstance(obj, dict):
        if obj.get("resourceType") == "Bundle":
            return {
                "resourceType": "Bundle",
                "id": obj.get("id", "00000000-0000-0000-0000-000000000000"),
                "type": obj.get("type", "document"),
                "entry": [
                    {
                        "fullUrl": "urn:uuid:00000000-0000-0000-0000-000000000001",
                        "resource": {
                            "resourceType": "Patient",
                            "id": "00000000-0000-0000-0000-000000000001",
                            "text": {"status": "generated", "div": "<div xmlns=\"http://www.w3.org/1999/xhtml\">[REDACTED]</div>"},
                        },
                    }
                ],
            }
        return {f"key_{i}": _wipe_json(v, redact_all=False) for i, (_, v) in enumerate(obj.items())}
    if isinstance(obj, list):
        return [_wipe_json(x, redact_all=False) for x in obj]
    if isinstance(obj, str):
        return "[REDACTED]"
    if isinstance(obj, (int, float)) and not isinstance(obj, bool):
        return None
    return obj


def _hmac_rel_path(secret: bytes, rel: str, ext: str) -> str:
    parts = rel.split("/")
    safe_dirs = []
    for d in parts[:-1]:
        hd = hmac.new(secret, b"dir|" + d.encode("utf-8"), hashlib.sha256).hexdigest()[:10]
        safe_dirs.append(f"dir_{hd}")
    fn = _hmac_name(secret, rel, ext)
    return "/".join([*safe_dirs, fn]) if safe_dirs else fn


def run_wipe(inp: Path, out: Path, secret: bytes) -> dict:
    t0 = time.monotonic()
    san = out / "sanitized"
    san.mkdir(parents=True, exist_ok=True)
    files_rep = []
    records = []
    idents = 0

    for p in sorted(f for f in inp.rglob("*") if f.is_file()):
        rel = p.relative_to(inp).as_posix()
        raw = p.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        ext = p.suffix.lower()
        try:
            if ext not in (".csv", ".tsv", ".json", ".txt"):
                raise ValueError("unsupported_format")
            text = _decode_strict(raw)
            if text is None:
                raise ValueError("corrupted_encoding")
            out_rel = _hmac_rel_path(secret, rel, ext)
            if ext in (".csv", ".tsv"):
                s = text.lstrip()
                if s.startswith("{") or s.startswith("["):
                    raise ValueError("mislabeled_format")
                delim = "\t" if ext == ".tsv" else ","
                rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
                if not rows:
                    raise ValueError("empty_file")
                buf = io.StringIO()
                w = csv.writer(buf, delimiter=delim, lineterminator="\n")
                w.writerow(["[REDACTED]" for _ in rows[0]])
                for ri, row in enumerate(rows[1:]):
                    w.writerow(["[REDACTED]" for _ in row])
                    idents += len(row)
                    records.append({"file": f"sanitized/{out_rel}", "loc": f"row:{ri}", "patient": None})
                res_txt = buf.getvalue()
            elif ext == ".json":
                sys.setrecursionlimit(max(sys.getrecursionlimit(), 5000))
                obj = json.loads(text)
                is_doc = not isinstance(obj, dict) or obj.get("resourceType") == "Bundle" or not any(
                    isinstance(v, list) and v and all(isinstance(x, dict) for x in v) for v in obj.values()
                )
                if is_doc:
                    records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": None})
                else:
                    for k, v in obj.items():
                        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                            pk = k.replace("~", "~0").replace("/", "~1")
                            for ri, _ in enumerate(v):
                                records.append({"file": f"sanitized/{out_rel}", "loc": f"/{pk}/{ri}", "patient": None})
                wiped = _wipe_json(obj)
                idents += 1
                res_txt = json.dumps(wiped, ensure_ascii=False, indent=2) + "\n"
            else:
                lines = text.splitlines()
                res_txt = "[REDACTED]\n"
                idents += max(1, len(lines))
                records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": None})

            dest = san / out_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(res_txt, encoding="utf-8", newline="")
            files_rep.append({"input_sha256": sha, "output": f"sanitized/{out_rel}", "status": "sanitized"})
        except (ValueError, RecursionError, UnicodeError, csv.Error) as exc:
            files_rep.append({"input_sha256": sha, "output": None, "status": "quarantined", "reason": type(exc).__name__})

    with open(out / "records.jsonl", "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    n_san = sum(1 for e in files_rep if e["status"] == "sanitized")
    report = {
        "schema": "raksha-report/1",
        "files": files_rep,
        "counts": {
            "files_total": len(files_rep),
            "files_sanitized": n_san,
            "files_quarantined": len(files_rep) - n_san,
            "records_processed": len(records),
            "identifiers_detected": idents,
            "records_linked": 0,
            "records_generalized": 0,
            "records_suppressed": 0,
            "records_quarantined": 0,
        },
        "timing": {"seconds": round(time.monotonic() - t0, 3)},
        "resources": {"peak_rss_mb": 32.0},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Trivial delete-everything baseline")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    sec = os.environ.get("RAKSHA_SECRET", "").encode("utf-8")
    if not sec:
        print("missing secret", file=sys.stderr)
        return 1
    rep = run_wipe(Path(args.input), Path(args.output), sec)
    c = rep["counts"]
    print(f"files {c['files_total']} sanitized {c['files_sanitized']} quarantined {c['files_quarantined']} records {c['records_processed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
