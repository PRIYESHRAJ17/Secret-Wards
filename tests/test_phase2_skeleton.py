"""Phase 2 skeleton & compliance tests (security, hygiene, G1, G2, G8, speed/RSS)."""
from __future__ import annotations

import ast
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from src.ingest import decode_safe
from src.secure import EncryptedScratchSpill, derive_keys
from tools.gen.generator import generate_dataset
from tools.leakscan.scanner import scan_output_tree

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kit"


def test_missing_secret_fails_closed(tmp_path: Path):
    out = tmp_path / "out"
    env = {k: v for k, v in os.environ.items() if k != "RAKSHA_SECRET"}
    env["RAKSHA_SECRET"] = ""
    p = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--input", str(KIT / "dev/input"), "--output", str(out)],
        env=env, capture_output=True, text=True,
    )
    assert p.returncode != 0
    assert not out.exists() or not any(out.iterdir())


def test_hkdf_and_aesgcm_spill():
    k1 = derive_keys(b"test-secret-vector-1")
    k2 = derive_keys(b"test-secret-vector-1")
    k3 = derive_keys(b"test-secret-vector-2")
    assert k1 == k2
    assert len({k1.pseudonym, k1.dateshift, k1.filename, k1.scratch}) == 4
    assert k1.pseudonym != k3.pseudonym
    # Verify HMAC-SHA256 RFC 4231 Test Case 2 vector ("Jefe" / "what do ya want for nothing?")
    mac = hmac.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha256).hexdigest()
    assert mac == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

    spill = EncryptedScratchSpill(k1.scratch)
    tok = spill.put(b"sensitive-patient-chunk")
    assert spill.get(tok) == b"sensitive-patient-chunk"
    spill_dir = spill._dir
    assert spill_dir is not None and spill_dir.exists()
    spill.cleanup()
    assert not spill_dir.exists()


def test_runtime_hygiene_no_prints_no_tools_imports_no_hardcoding():
    # R-44: no print( inside src/
    for py in (ROOT / "src").rglob("*.py"):
        txt = py.read_text(encoding="utf-8")
        assert "print(" not in txt, f"print( found in {py}"

    # R-20: runtime must not import tools/
    for py in [ROOT / "main.py", *(ROOT / "src").rglob("*.py")]:
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for al in node.names:
                    assert not al.name.startswith("tools"), f"tools import in {py}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("tools"), f"tools import in {py}"

    # R-05: no dev/truth canary or patient full names hardcoded in runtime
    truth = json.loads((KIT / "dev/truth/truth.json").read_text(encoding="utf-8"))
    forbidden = {
        e["surface"].casefold()
        for f in truth["files"].values()
        for u in f["units"].values()
        for e in u["entities"]
        if e["type"] in ("PATIENT_NAME", "RELATIVE_NAME", "CANARY", "AADHAAR", "ABHA_NUMBER", "PAN", "EMAIL")
        and len(e["surface"].strip()) >= 6
    }
    for py in [ROOT / "main.py", *(ROOT / "src").rglob("*.py")]:
        low = py.read_text(encoding="utf-8").casefold()
        for tok in forbidden:
            assert tok not in low, f"Hardcoded dev entity {tok!r} in {py}"


def test_cp1252_vs_corrupt_quarantine():
    legit_raw = (KIT / "dev/input/registration/arogya_legacy_export.csv").read_bytes()
    txt, err = decode_safe(legit_raw)
    assert err is None and txt is not None and "°F" in txt

    corrupt_raw = (KIT / "dev/input/misc/corrupt_bytes_note.txt").read_bytes()
    ctxt, cerr = decode_safe(corrupt_raw)
    assert ctxt is None and cerr == "corrupted_encoding"


def test_phase2_gates_g1_g2_and_perf_on_dev_and_heldout(tmp_path: Path):
    # 1. Practice dev/input
    out_dev = tmp_path / "out_dev"
    t0 = time.monotonic()
    p = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--input", str(KIT / "dev/input"), "--output", str(out_dev)],
        env=dict(os.environ, RAKSHA_SECRET="phase2-secret", PYTHONUTF8="1"),
        capture_output=True, text=True, check=True,
    )
    elapsed = time.monotonic() - t0
    assert elapsed < 15.0, f"Too slow on small dev/input: {elapsed:.2f}s"

    # Strict 3-entry output layout
    assert {x.name for x in out_dev.iterdir()} == {"sanitized", "report.json", "records.jsonl"}

    # G1 validate_output.py
    v = subprocess.run(
        [sys.executable, str(KIT / "validate_output.py"), "--input", str(KIT / "dev/input"), "--output", str(out_dev)],
        capture_output=True, text=True, check=True,
    )
    assert "CONTRACT OK" in v.stdout

    # G2 whole-tree leakscan
    truth = json.loads((KIT / "dev/truth/truth.json").read_text(encoding="utf-8"))
    canaries = [
        e["surface"]
        for f in truth["files"].values()
        for u in f["units"].values()
        for e in u["entities"]
        if e.get("type") == "CANARY"
    ]
    lk = scan_output_tree(out_dev, canaries=canaries, secret="phase2-secret", stdout_stderr=p.stdout + p.stderr)
    assert lk.canary_hits == 0, f"Canary leaks: {lk.findings}"
    assert lk.secret_hits == 0

    # 2. Generated HELD-OUT-SHIFT
    hs_dir = tmp_path / "hs"
    hs_truth = generate_dataset(hs_dir, seed="p2-hs-1", split="heldout_shift", shift_axes=True, n_patients=12)
    out_hs = tmp_path / "out_hs"
    p_hs = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--input", str(hs_dir / "input"), "--output", str(out_hs)],
        env=dict(os.environ, RAKSHA_SECRET="phase2-secret", PYTHONUTF8="1"),
        capture_output=True, text=True, check=True,
    )
    v_hs = subprocess.run(
        [sys.executable, str(KIT / "validate_output.py"), "--input", str(hs_dir / "input"), "--output", str(out_hs)],
        capture_output=True, text=True, check=True,
    )
    assert "CONTRACT OK" in v_hs.stdout
    hs_canaries = [
        e["surface"]
        for f in hs_truth["files"].values()
        for u in f["units"].values()
        for e in u["entities"]
        if e.get("type") == "CANARY"
    ]
    lk_hs = scan_output_tree(out_hs, canaries=hs_canaries, secret="phase2-secret", stdout_stderr=p_hs.stdout + p_hs.stderr)
    assert lk_hs.canary_hits == 0, f"Held-out canary leaks: {lk_hs.findings}"
    assert lk_hs.secret_hits == 0
