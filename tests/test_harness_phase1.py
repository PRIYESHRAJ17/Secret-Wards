"""Phase 1 test suite: verifies kit integrity, generator split disjointness,
7-channel leak scanner, A1-A7 attacker self-checks, local scorer, and wipe/starter baselines.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from tools.attacker.attacker import _a6_invert_pseudonym, extract_age_constraints, run_attack
from tools.eval.score_local import score_output
from tools.eval.wipe_baseline import run_wipe
from tools.gen.generator import generate_dataset, generate_fuzz_suite
from tools.gen.pools import (
    DOCTORS,
    HELDOUT_CANARIES,
    HELDOUT_PEOPLE_POOL,
    PLACES_HELDOUT,
    PLACES_TRAIN,
    TRAIN_CANARIES,
    TRAIN_PEOPLE_POOL,
)
from tools.leakscan.scanner import scan_output_tree

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kit"


def test_zero_single_token_overlap_with_dev_truth():
    import unicodedata
    truth = json.loads((KIT / "dev/truth/truth.json").read_text(encoding="utf-8"))
    dev_tokens = {
        tok
        for f in truth["files"].values()
        for u in f["units"].values()
        for e in u["entities"]
        if e["type"] in ("PATIENT_NAME", "RELATIVE_NAME", "CANARY", "VILLAGE", "LOCALITY")
        for tok in unicodedata.normalize("NFKC", e["surface"]).casefold().split()
        if len(tok) >= 3
    }
    for pool in (TRAIN_PEOPLE_POOL, HELDOUT_PEOPLE_POOL, TRAIN_CANARIES, HELDOUT_CANARIES, PLACES_TRAIN, PLACES_HELDOUT, DOCTORS):
        for row in pool:
            for item in row:
                for tok in unicodedata.normalize("NFKC", str(item)).casefold().split():
                    assert tok not in dev_tokens, f"Token {tok!r} overlaps dev/truth.json"


def test_kit_sha256_immutable():
    assert not (ROOT / "kit_old_crlf").exists(), "kit_old_crlf should be deleted"
    truth = json.loads((KIT / "dev/truth/truth.json").read_text(encoding="utf-8"))
    manifest = json.loads((KIT / "dev/dataset_manifest.json").read_text(encoding="utf-8"))
    assert hashlib.sha256((KIT / "dev/truth/truth.json").read_bytes()).hexdigest() == manifest["hashes"]["truth"]
    matched = sum(
        1 for rel, f in truth["files"].items()
        if hashlib.sha256((KIT / "dev/input" / rel).read_bytes()).hexdigest() == f["sha256"]
    )
    assert matched == len(truth["files"]) == 200


def test_gitattributes_lf_rules():
    ga = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    for ext in ("*.py", "*.csv", "*.tsv", "*.json", "*.jsonl", "*.txt"):
        assert f"{ext} text eol=lf" in ga
    for ext in ("*.pdf", "*.jpg", "*.zip"):
        assert f"{ext} binary" in ga


def test_generator_splits_disjoint_and_complete(tmp_path: Path):
    train_names = {p[0].casefold() for p in TRAIN_PEOPLE_POOL} | {p[2].casefold() for p in TRAIN_PEOPLE_POOL}
    held_names = {p[0].casefold() for p in HELDOUT_PEOPLE_POOL} | {p[2].casefold() for p in HELDOUT_PEOPLE_POOL}
    assert not (train_names & held_names), f"Overlap between TRAIN and HELD-OUT: {train_names & held_names}"

    # Verify disjointness from kit dev/truth names
    truth = json.loads((KIT / "dev/truth/truth.json").read_text(encoding="utf-8"))
    dev_full_names = {
        e["surface"].casefold()
        for f in truth["files"].values()
        for u in f["units"].values()
        for e in u["entities"]
        if e["type"] in ("PATIENT_NAME", "RELATIVE_NAME", "CANARY")
    }
    train_full = {f"{p[0]} {p[2]}".casefold() for p in TRAIN_PEOPLE_POOL} | {f"{c[0]} {c[2]}".casefold() for c in TRAIN_CANARIES}
    held_full = {f"{p[0]} {p[2]}".casefold() for p in HELDOUT_PEOPLE_POOL} | {f"{c[0]} {c[2]}".casefold() for c in HELDOUT_CANARIES}
    assert not (train_full & dev_full_names)
    assert not (held_full & dev_full_names)

    t_dir = tmp_path / "train"
    h_dir = tmp_path / "heldout"
    t_truth = generate_dataset(t_dir, seed="train-1", split="train", shift_axes=False, n_patients=12)
    h_truth = generate_dataset(h_dir, seed="heldout-1", split="heldout_shift", shift_axes=True, n_patients=12)
    assert t_truth["chaos"] is False and h_truth["chaos"] is True
    assert len(t_truth["canaries"]) == 4 and len(h_truth["canaries"]) == 4

    channels = {
        e["channel"]
        for f in h_truth["files"].values()
        for u in f["units"].values()
        for e in u["entities"]
    }
    assert {"content", "filename", "header", "key", "metadata", "base64"} <= channels

    fuzz_files = generate_fuzz_suite(tmp_path / "fuzz")
    assert len(fuzz_files) >= 10


def test_leakscan_catches_all_7_channels(tmp_path: Path):
    canary = "Zephaniah Kandathil"
    deva_canary = "ज़ेफ़नियाह कंदथिल"
    secret = "super-secret-xyz"

    out = tmp_path / "out"
    san = out / "sanitized"
    (san / "Zephaniah_Kandathil_dir").mkdir(parents=True)
    # 1. content (base64 + \uXXXX + Devanagari)
    b64 = base64.b64encode(canary.encode("utf-8")).decode("ascii")
    (san / "note.txt").write_text(f"payload {b64}", encoding="utf-8")
    # 2. filename/dir
    (san / "Zephaniah_Kandathil_dir" / "ok.txt").write_text("clean", encoding="utf-8")
    # 3. report.json
    (out / "report.json").write_text(json.dumps({"note": deva_canary}, ensure_ascii=True), encoding="utf-8")
    # 4. records.jsonl
    (out / "records.jsonl").write_text(json.dumps({"file": "sanitized/note.txt", "loc": "doc", "patient": None}) + "\n", encoding="utf-8")
    # 5. logs/
    (out / "logs").mkdir()
    (out / "logs" / "run.log").write_text(f"err {secret}", encoding="utf-8")
    # 7. leftover temp file
    tmp_leftover = tmp_path / "leftover_tmp"
    tmp_leftover.mkdir()
    (tmp_leftover / "spill.txt").write_text(canary, encoding="utf-8")

    rep = scan_output_tree(
        out,
        canaries=[canary, deva_canary],
        secret=secret,
        stdout_stderr=f"stdout leaked {canary}",
        temp_paths=[tmp_leftover],
    )
    assert rep.canary_hits == 2
    assert rep.secret_hits >= 1
    assert rep.channels_clean["sanitized_content"] is False
    assert rep.channels_clean["sanitized_filenames"] is False
    assert rep.channels_clean["report_json"] is False
    assert rep.channels_clean["logs_and_other"] is False
    assert rep.channels_clean["stdout_stderr"] is False
    assert rep.channels_clean["temp_dirs"] is False


def test_attacker_self_checks_and_attacks(tmp_path: Path):
    # ATTACKS.md:104-111 age-parser self-checks
    assert extract_age_constraints("50-54 Yrs/F") == [(50, 54)]
    assert extract_age_constraints("K/C/O DM x 12 yrs, TB 7 yrs back") == []
    assert extract_age_constraints("Random Blood Sugar 70-140 mg/dL") == []
    assert extract_age_constraints("85+ Yrs") == [(85, 120)]

    # A6 pseudonym inversion: unkeyed SHA-256 inverted, HMAC-SHA256 not inverted
    uhid = "NRM-26-100001"
    weak_psn = "PSN-" + hashlib.sha256(uhid.encode()).hexdigest()[:10]
    strong_psn = "PSN-9Q2K7R4M8W"
    assert _a6_invert_pseudonym(weak_psn, [uhid]) is True
    assert _a6_invert_pseudonym(strong_psn, [uhid]) is False

    # A5 global shift recovery vs per-patient shifts
    ds_dir = tmp_path / "ds"
    truth = generate_dataset(ds_dir, seed="atk-1", split="train", shift_axes=False, n_patients=8)
    # Build two fake sanitized outputs: one with constant +30d shift (recoverable), one with per-patient shifts
    for mode, out_name in [("global", "out_global"), ("per_patient", "out_pp")]:
        out = tmp_path / out_name
        san = out / "sanitized"
        san.mkdir(parents=True)
        for rel, finfo in truth["files"].items():
            if finfo["expect"] != "sanitize":
                continue
            src = ds_dir / "input" / rel
            dst = san / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            txt = src.read_bytes().decode(finfo["encoding"], errors="replace")
            if rel.startswith("fhir/"):
                from datetime import date, timedelta
                obj = json.loads(txt)
                pt_id = finfo["units"]["doc"]["patient"]
                shift_d = 30 if mode == "global" else (30 + int(pt_id[-2:]) * 17)
                pidx = int(pt_id[-2:])
                psn = f"PSN-TEST{pidx:04d}AA"
                obj["meta"]["lastUpdated"] = (date.fromisoformat(obj["meta"]["lastUpdated"][:10]) + timedelta(days=shift_d)).isoformat() + obj["meta"]["lastUpdated"][10:]
                obj["timestamp"] = (date.fromisoformat(obj["timestamp"][:10]) + timedelta(days=shift_d)).isoformat() + obj["timestamp"][10:]
                for ent in obj["entry"]:
                    res = ent["resource"]
                    rt = res["resourceType"]
                    if rt == "Patient":
                        # Keep direct IDs stripped, but keep birthDate/gender/village/pin so profile >= 0.9 for A5 shift recovery test
                        res["name"] = [{"text": psn}]
                        res["identifier"] = [{"value": psn}]
                        res["telecom"] = []
                        res["text"]["div"] = f"<div xmlns=\"http://www.w3.org/1999/xhtml\">{psn}</div>"
                    elif rt == "Composition":
                        res["subject"]["display"] = psn
                        res["date"] = (date.fromisoformat(res["date"][:10]) + timedelta(days=shift_d)).isoformat() + res["date"][10:]
                    elif rt == "Encounter":
                        for k in ("start", "end"):
                            d = res["period"][k][:10]
                            nd = (date.fromisoformat(d) + timedelta(days=shift_d)).isoformat()
                            res["period"][k] = nd + res["period"][k][10:]
                dst.write_text(json.dumps(obj, indent=2), encoding="utf-8")
            else:
                dst.write_text("[REDACTED]", encoding="utf-8")
        atk_g = run_attack(out, truth, ds_dir / "attacker/registry.csv", ds_dir / "attacker/known_facts.jsonl")
        if mode == "global":
            assert atk_g.recovered_global_shift_days == 30
        else:
            assert atk_g.recovered_global_shift_days == 0


def test_starter_and_wipe_baselines_in_scorer(tmp_path: Path):
    truth = json.loads((KIT / "dev/truth/truth.json").read_text(encoding="utf-8"))
    env = dict(os.environ, RAKSHA_SECRET="practice", PYTHONUTF8="1")

    # 1. Starter baseline
    out_st = tmp_path / "out_starter"
    p_st = subprocess.run(
        [sys.executable, str(KIT / "starter/main.py"), "--input", str(KIT / "dev/input"), "--output", str(out_st)],
        env=env, capture_output=True, text=True, check=True,
    )
    v_st = subprocess.run(
        [sys.executable, str(KIT / "validate_output.py"), "--input", str(KIT / "dev/input"), "--output", str(out_st)],
        capture_output=True, text=True, check=True,
    )
    assert "CONTRACT OK" in v_st.stdout
    sc_st = score_output(
        KIT / "dev/input", out_st, truth, KIT / "scoring.toml",
        attacker_dir=KIT / "dev/attacker", raw_attack_path=KIT / "dev/truth/raw_attack.json",
        stdout_stderr=p_st.stdout + p_st.stderr,
    )
    assert sc_st["details"]["canary_hits"] == 4
    assert sc_st["penalties"]["canary_leaks"] == 12.0
    assert sc_st["components"]["identity_resolution"] == 0.0
    assert sc_st["total"] < 20.0

    # 2. Wipe-all baseline
    out_wp = tmp_path / "out_wipe"
    run_wipe(KIT / "dev/input", out_wp, b"practice")
    v_wp = subprocess.run(
        [sys.executable, str(KIT / "validate_output.py"), "--input", str(KIT / "dev/input"), "--output", str(out_wp)],
        capture_output=True, text=True, check=True,
    )
    assert "CONTRACT OK" in v_wp.stdout
    sc_wp = score_output(
        KIT / "dev/input", out_wp, truth, KIT / "scoring.toml",
        attacker_dir=KIT / "dev/attacker", raw_attack_path=KIT / "dev/truth/raw_attack.json",
    )
    assert sc_wp["details"]["canary_hits"] == 0
    assert sc_wp["details"]["raw_copies"] == 0
    assert sc_wp["penalties"]["total"] == 0.0
    # Calibrated redact_all matches SCORING.md:170 (22.75 +/- 1.0)
    assert 21.75 <= sc_wp["total"] <= 23.75


def test_starter_on_generated_train_matches_dev_profile(tmp_path: Path):
    tr_dir = tmp_path / "train_prof"
    generate_dataset(tr_dir, seed="train-prof-1", split="train", shift_axes=False, n_patients=24)
    out_tr = tmp_path / "out_tr"
    env = dict(os.environ, RAKSHA_SECRET="practice", PYTHONUTF8="1")
    subprocess.run(
        [sys.executable, str(KIT / "starter/main.py"), "--input", str(tr_dir / "input"), "--output", str(out_tr)],
        env=env, capture_output=True, text=True, check=True,
    )
    cd = subprocess.run(
        [sys.executable, str(KIT / "check_dev.py"), "--output", str(out_tr), "--truth", str(tr_dir / "truth/truth.json")],
        capture_output=True, text=True, check=True,
    )
    assert "still visible" in cd.stdout
    for ch in ("content", "filename", "base64", "metadata", "key", "header"):
        assert ch in cd.stdout, f"Missing channel {ch} in generated TRAIN check_dev output"


def test_wipe_baseline_on_generated_heldout_shift(tmp_path: Path):
    h_dir = tmp_path / "heldout"
    h_truth = generate_dataset(h_dir, seed="hs-1", split="heldout_shift", shift_axes=True, n_patients=10)
    out_wp = tmp_path / "out_hs"
    run_wipe(h_dir / "input", out_wp, b"secret-heldout")
    v = subprocess.run(
        [sys.executable, str(KIT / "validate_output.py"), "--input", str(h_dir / "input"), "--output", str(out_wp)],
        capture_output=True, text=True, check=True,
    )
    assert "CONTRACT OK" in v.stdout
    canaries = [
        e["surface"]
        for f in h_truth["files"].values()
        for u in f["units"].values()
        for e in u["entities"]
        if e.get("type") == "CANARY"
    ]
    lk = scan_output_tree(out_wp, canaries=canaries, secret="secret-heldout")
    assert lk.canary_hits == 0 and lk.secret_hits == 0
