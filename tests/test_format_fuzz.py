"""Gate G8 format-fuzz suite: every bad file quarantined, 0 crashes, 0 raw copies, 0 silent drops."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tools.gen.generator import generate_fuzz_suite

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kit"


def test_format_fuzz_quarantine_and_contract(tmp_path: Path):
    fuzz_in = tmp_path / "fuzz_in"
    fuzz_out = tmp_path / "fuzz_out"
    generate_fuzz_suite(fuzz_in)

    # Add pathological regex & mixed encoding files
    (fuzz_in / "bad_mixed_utf8.txt").write_bytes(b"Patient Name: Test\n\xff\xfe\xc3(broken\n")
    (fuzz_in / "pathological_repeat.txt").write_text("9" * 60000 + "\n", encoding="utf-8")

    env = dict(os.environ, RAKSHA_SECRET="fuzz-secret", PYTHONUTF8="1")
    p = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--input", str(fuzz_in), "--output", str(fuzz_out)],
        env=env, capture_output=True, text=True,
    )
    assert p.returncode == 0, p.stderr

    v = subprocess.run(
        [sys.executable, str(KIT / "validate_output.py"), "--input", str(fuzz_in), "--output", str(fuzz_out)],
        capture_output=True, text=True,
    )
    assert "CONTRACT OK" in v.stdout, v.stdout

    rep = json.loads((fuzz_out / "report.json").read_text(encoding="utf-8"))
    by_sha = {e["input_sha256"]: e for e in rep["files"]}
    import hashlib
    for bad_name in ("zero_byte.txt", "null_binary.bin", "truncated.json", "truncated_fhir.json", "bad_utf8.txt", "unquoted_commas.csv", "zip_as_csv.csv", "deep_1500.json", "bad_mixed_utf8.txt"):
        sha = hashlib.sha256((fuzz_in / bad_name).read_bytes()).hexdigest()
        assert by_sha[sha]["status"] == "quarantined", f"{bad_name} should be quarantined"
        assert by_sha[sha]["output"] is None

    # No raw copies of bad files in sanitized/
    san = fuzz_out / "sanitized"
    for bad_name in ("zero_byte.txt", "null_binary.bin", "truncated.json", "truncated_fhir.json", "bad_utf8.txt", "unquoted_commas.csv", "zip_as_csv.csv", "deep_1500.json", "bad_mixed_utf8.txt"):
        assert not (san / bad_name).exists()

    # Exact counts invariant
    c = rep["counts"]
    assert c["files_total"] == c["files_sanitized"] + c["files_quarantined"] == len(list(fuzz_in.iterdir()))
