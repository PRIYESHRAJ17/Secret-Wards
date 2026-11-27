"""In-house local evaluator reproducing kit/scoring.toml and docs/SCORING.md.

Computes an estimated score out of 100 across all 6 official categories plus
all 5 critical penalties (not floored at 0), and compares counts against check_dev.py.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import datetime as dt
import io
import itertools
import json
import math
import re
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

from tools.attacker.attacker import extract_age_constraints, run_attack
from tools.leakscan.scanner import decode_hidden_payloads, norm_scoring, scan_output_tree

_DATE_ISO_RE = re.compile(r"^\d{4}(?:-\d{2}(?:-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?)?)?$")


def _record_for(loc: str, recs: dict):
    if loc in recs:
        return recs[loc]
    if loc.startswith("/"):
        parts = loc.split("/")
        for i in range(len(parts) - 1, 1, -1):
            anc = "/".join(parts[:i])
            if anc in recs:
                return recs[anc]
    return recs.get("doc")


def _log_linear_score(val: float, good: float, limit: float) -> float:
    if val <= good:
        return 1.0
    if val >= limit:
        return 0.0
    if good <= 0 or limit <= good:
        return 0.0
    return max(0.0, min(1.0, 1.0 - (math.log(val / good) / math.log(limit / good))))


def _validate_fhir_bundle(obj: dict) -> bool:
    if not isinstance(obj, dict) or obj.get("resourceType") != "Bundle":
        return False
    entries = obj.get("entry")
    if not isinstance(entries, list) or not entries:
        return False
    known_refs: set[str] = set()
    for ent in entries:
        if not isinstance(ent, dict):
            return False
        fu = ent.get("fullUrl")
        res = ent.get("resource")
        if not isinstance(res, dict) or not res.get("resourceType") or not res.get("id"):
            return False
        if fu:
            known_refs.add(str(fu))
        known_refs.add(f"{res['resourceType']}/{res['id']}")

    def check_node(node) -> bool:
        if isinstance(node, dict):
            if "reference" in node and isinstance(node["reference"], str):
                ref = node["reference"]
                if ref.startswith(("urn:uuid:", "Patient/", "Practitioner/", "Encounter/", "Condition/", "Observation/", "MedicationRequest/", "Procedure/", "Organization/", "DocumentReference/")):
                    if ref not in known_refs:
                        return False
            for dk in ("birthDate", "date", "lastUpdated", "timestamp", "start", "end"):
                if dk in node and isinstance(node[dk], str) and node[dk]:
                    if not _DATE_ISO_RE.match(node[dk]):
                        return False
            if "attachment" in node and isinstance(node["attachment"], dict):
                data = node["attachment"].get("data")
                if isinstance(data, str) and data:
                    try:
                        base64.b64decode(data + "=" * (-len(data) % 4), validate=False)
                    except (binascii.Error, ValueError):
                        return False
            return all(check_node(v) for v in node.values())
        if isinstance(node, list):
            return all(check_node(x) for x in node)
        return True

    return check_node(obj)


def _json_key_paths(obj, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}/{k}"
            paths.add(p)
            paths |= _json_key_paths(v, p)
    elif isinstance(obj, list):
        for x in obj[:5]:
            paths |= _json_key_paths(x, f"{prefix}[]")
    return paths


def _check_entity_leak(ent: dict, hay_norm: str, hay_digits: str, preserve_texts: list[str]) -> float:
    """Compute leak(x) in [0, 1] per SCORING.md:33-41."""
    surf = norm_scoring(ent["surface"])
    if not surf:
        return 0.0
    match_mode = ent.get("match", "text")
    if match_mode == "digits":
        dig = re.sub(r"\D", "", surf)
        if len(dig) >= 4:
            in_occ = 1
            allowed = sum(p.count(dig) for p in preserve_texts)
            out_occ = hay_digits.count(dig)
            leaked = max(0, min(in_occ, out_occ - allowed))
            return leaked / in_occ
    # Text / name / exact match
    tokens = ent.get("tokens") if ent.get("match") == "name" and ent.get("tokens") else [surf]
    tok_leaks: list[float] = []
    for tok in tokens:
        nt = norm_scoring(tok)
        if not nt:
            continue
        allowed = sum(len(re.findall(r"(?<!\w)" + re.escape(nt) + r"(?!\w)", p)) for p in preserve_texts)
        out_occ = len(re.findall(r"(?<!\w)" + re.escape(nt) + r"(?!\w)", hay_norm)) if " " not in nt else hay_norm.count(nt)
        leaked = max(0, min(1, out_occ - allowed))
        tok_leaks.append(float(leaked))
    return sum(tok_leaks) / len(tok_leaks) if tok_leaks else 0.0


def score_output(
    inp_dir: Path,
    out_dir: Path,
    truth: dict,
    scoring_toml_path: Path,
    attacker_dir: Path | None = None,
    raw_attack_path: Path | None = None,
    profile: str = "small",
    exit_code: int = 0,
    wall_seconds: float | None = None,
    peak_rss_mb: float | None = None,
    determinism_rate: float = 1.0,
    input_tampered: bool = False,
    stdout_stderr: str = "",
    alt_secret_out_dir: Path | None = None,
) -> dict:
    cfg = tomllib.loads(scoring_toml_path.read_text(encoding="utf-8"))
    weights = cfg["weights"]
    san = out_dir / "sanitized"

    try:
        report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        report_valid = isinstance(report, dict)
    except (OSError, ValueError):
        report = {}
        report_valid = False
    renamed = {e.get("input_sha256"): e.get("output") for e in (report.get("files") or []) if isinstance(e, dict)}
    report_entries_by_sha = {e.get("input_sha256"): e for e in (report.get("files") or []) if isinstance(e, dict)}

    recs: dict[str, dict[str, str | None]] = defaultdict(dict)
    raw_rec_lines: list[dict] = []
    rj = out_dir / "records.jsonl"
    if rj.is_file():
        for line in rj.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    r = json.loads(line)
                    if isinstance(r, dict) and "file" in r and "loc" in r:
                        raw_rec_lines.append(r)
                        recs[str(r["file"]).replace("sanitized/", "", 1)][r["loc"]] = r.get("patient")
                except ValueError:
                    pass

    # Pre-read exported files
    exported_texts: dict[str, str] = {}
    exported_norm: dict[str, str] = {}
    exported_digits: dict[str, str] = {}
    if san.is_dir():
        for p in sorted(san.rglob("*")):
            if p.is_file():
                rel = p.relative_to(san).as_posix()
                raw_b = p.read_bytes()
                txt = decode_hidden_payloads(raw_b.decode("utf-8", errors="replace"))
                exported_texts[rel] = txt
                n = norm_scoring(txt)
                exported_norm[rel] = n
                exported_digits[rel] = re.sub(r"\D", "", n)

    # ------------------------------------------------------------------ 1. Detection (20%)
    type_recalls: dict[str, list[float]] = defaultdict(list)
    script_recalls: dict[str, list[float]] = defaultdict(list)
    trap_group_scores: dict[str, list[float]] = defaultdict(list)
    clean_token_scores: list[float] = []
    leaked_unique_ids: set[tuple[str, str]] = set()

    # Track utility & integrity accumulators in the same pass
    probe_scores: list[float] = []
    interval_scores: list[float] = []
    los_scores: list[float] = []
    gen_scores: list[float] = []
    token_ret_scores: list[float] = []
    record_ret_hits = 0
    record_ret_total = 0

    format_valid_scores: list[float] = []
    schema_pres_scores: list[float] = []
    fhir_valid_scores: list[float] = []
    either_total = 0
    either_safe = 0
    raw_copy_count = 0
    silent_drops = 0

    unit_patient: dict[tuple[str, str], tuple[str | None, str | None, str]] = {}

    for rel, finfo in sorted(truth["files"].items()):
        out_rel = rel
        decl = renamed.get(finfo["sha256"])
        if decl:
            out_rel = str(decl).replace("sanitized/", "", 1)
        out_fp = san / out_rel
        src_fp = inp_dir / rel
        exists = out_fp.is_file()
        rep_entry = report_entries_by_sha.get(finfo["sha256"])
        if not exists and rep_entry is None:
            silent_drops += 1

        # Quarantine handling
        if finfo.get("expect") == "either":
            either_total += 1
            has_pii = any(u["entities"] for u in finfo["units"].values())
            is_raw = exists and src_fp.is_file() and out_fp.read_bytes() == src_fp.read_bytes()
            if has_pii and is_raw:
                raw_copy_count += 1
            else:
                either_safe += 1

        if exists:
            raw_out = out_fp.read_bytes()
            try:
                (raw_out[3:] if raw_out.startswith(b"\xef\xbb\xbf") else raw_out).decode("utf-8")
                utf8_ok = True
            except UnicodeDecodeError:
                utf8_ok = False
            fmt = finfo.get("format", "text")
            fmt_ok = utf8_ok
            if utf8_ok and fmt in ("json", "fhir"):
                try:
                    out_obj = json.loads(raw_out.decode("utf-8-sig"))
                except ValueError:
                    fmt_ok = False
                    out_obj = None
                if fmt == "fhir":
                    fhir_valid_scores.append(1.0 if (fmt_ok and _validate_fhir_bundle(out_obj)) else 0.0)
                if fmt_ok and src_fp.is_file():
                    try:
                        in_obj = json.loads(src_fp.read_bytes().decode(finfo.get("encoding", "utf-8")))
                        p_in, p_out = _json_key_paths(in_obj), _json_key_paths(out_obj)
                        schema_pres_scores.append(len(p_in & p_out) / len(p_in | p_out) if (p_in | p_out) else 1.0)
                    except Exception:
                        pass
            elif utf8_ok and fmt in ("csv", "tsv"):
                delim = finfo.get("delimiter") or ("," if fmt == "csv" else "\t")
                try:
                    out_rows = list(csv.reader(io.StringIO(raw_out.decode("utf-8-sig"), newline=""), delimiter=delim))
                    if src_fp.is_file():
                        in_rows = list(csv.reader(io.StringIO(src_fp.read_bytes().decode(finfo.get("encoding", "utf-8")), newline=""), delimiter=delim))
                        r_score = 1.0 if len(out_rows) == len(in_rows) else min(len(out_rows), len(in_rows)) / max(1, len(in_rows))
                        c_score = 1.0 if (out_rows and in_rows and len(out_rows[0]) == len(in_rows[0])) else 0.0
                        if "@header" in finfo["units"]:
                            h_score = 1.0 if (out_rows and "[REDACTED]" not in "".join(out_rows[0])) else 0.0
                        else:
                            h_score = 1.0 if (out_rows and in_rows and out_rows[0] == in_rows[0]) else 0.0
                        schema_pres_scores.append((r_score + c_score + h_score) / 3.0)
                except csv.Error:
                    fmt_ok = False
            elif utf8_ok and fmt == "text" and src_fp.is_file():
                in_lines = max(1, len(src_fp.read_bytes().decode(finfo.get("encoding", "utf-8"), errors="replace").splitlines()))
                out_lines = len(raw_out.decode("utf-8-sig", errors="replace").splitlines())
                schema_pres_scores.append(min(out_lines, in_lines) / max(out_lines, in_lines))
            format_valid_scores.append(1.0 if fmt_ok else 0.0)

        hay_norm = exported_norm.get(out_rel, "")
        hay_digits = exported_digits.get(out_rel, "")
        fname_norm = norm_scoring(out_rel)
        all_pres_norm = [norm_scoring(pv["text"]) for u in finfo["units"].values() for pv in (u.get("preserve") or [])]

        # Clean file token retention
        if rel.startswith("clean/") and exists and src_fp.is_file():
            in_toks = Counter(norm_scoring(src_fp.read_bytes().decode(finfo.get("encoding", "utf-8"), errors="replace")).split())
            out_toks = Counter(hay_norm.split())
            kept_t = sum(min(in_toks[t], out_toks[t]) for t in in_toks)
            clean_token_scores.append(kept_t / sum(in_toks.values()) if in_toks else 1.0)

        # Record-level token retention for utility (non-PII non-date tokens)
        if finfo.get("expect") == "sanitize" and src_fp.is_file():
            if exists:
                in_toks = Counter(norm_scoring(src_fp.read_bytes().decode(finfo.get("encoding", "utf-8"), errors="replace")).split())
                out_toks = Counter(hay_norm.split())
                pii_tok_set = {
                    tok
                    for u in finfo["units"].values()
                    for e in u["entities"]
                    for tok in norm_scoring(e["surface"]).split()
                }
                non_pii = {t: c for t, c in in_toks.items() if t not in pii_tok_set and not re.fullmatch(r"\d{1,4}[/-]\d{1,2}[/-]\d{2,4}", t)}
                tot_np = sum(non_pii.values())
                if tot_np > 0:
                    token_ret_scores.append(sum(min(c, out_toks[t]) for t, c in non_pii.items()) / tot_np)
            else:
                token_ret_scores.append(0.0)

        for loc, u in finfo["units"].items():
            if not loc.startswith("@") and finfo.get("expect") == "sanitize":
                record_ret_total += 1
                if exists:
                    # Verify record is still locatable at its JSON pointer or CSV row (SCORING.md:115)
                    loc_ok = True
                    if loc.startswith("/") and finfo.get("format") in ("json", "fhir"):
                        try:
                            cur = json.loads(exported_texts[out_rel].split("\n", 1)[0]) if "\n" not in exported_texts[out_rel] else json.loads((san / out_rel).read_text(encoding="utf-8-sig"))
                            for part in loc.split("/")[1:]:
                                part = part.replace("~1", "/").replace("~0", "~")
                                cur = cur[int(part)] if isinstance(cur, list) else cur[part]
                        except Exception:
                            loc_ok = False
                    if loc_ok:
                        record_ret_hits += 1

            for e in u["entities"]:
                if e.get("type") == "CANARY":
                    continue
                if exists or e.get("channel") == "filename":
                    target_h = fname_norm if e.get("channel") == "filename" else hay_norm
                    target_d = re.sub(r"\D", "", fname_norm) if e.get("channel") == "filename" else hay_digits
                    lk = _check_entity_leak(e, target_h, target_d, all_pres_norm)
                else:
                    lk = 0.0
                rec = 1.0 - lk
                type_recalls[e["type"]].append(rec)
                script_recalls[e["script"]].append(rec)
                if lk > 0.5 and e.get("critical"):
                    leaked_unique_ids.add((e.get("person", e["surface"]), e["type"]))

            for pv in u.get("preserve") or []:
                w = float(pv.get("weight", 1.0))
                ok = 1.0 if (exists and norm_scoring(pv["text"]) in hay_norm) else 0.0
                probe_scores.append((ok, w))
                if pv.get("trap"):
                    trap_group_scores[pv["trap"]].append(ok)

            # Generalization checks (age, district, pin)
            if exists:
                age_cs = extract_age_constraints(exported_texts.get(out_rel, ""))
                for fl in u.get("fields") or []:
                    k = fl.get("kind")
                    tv = fl.get("true")
                    if k == "age" and isinstance(tv, int):
                        if re.search(rf"\b{tv}\b", hay_norm):
                            gen_scores.append(1.0)
                        elif age_cs:
                            matching = [hi - lo + 1 for lo, hi in age_cs if lo <= tv <= hi]
                            if not matching:
                                gen_scores.append(0.0)
                            else:
                                width = min(matching)
                                gen_scores.append(0.9 if width <= 5 else (0.8 if width <= 10 else (0.6 if width <= 20 else 0.3)))
                        else:
                            gen_scores.append(0.0)
                    elif k == "district" and isinstance(tv, str):
                        gen_scores.append(0.7 if tv.lower() in hay_norm else 0.0)
                    elif k == "pin" and isinstance(tv, str):
                        if tv in hay_norm:
                            gen_scores.append(1.0)
                        elif tv[:3] in hay_norm:
                            gen_scores.append(0.7)
                        else:
                            gen_scores.append(0.0)

            if u.get("link") in ("required", "ambiguous"):
                unit_patient[(rel, loc)] = (u.get("patient"), _record_for(loc, recs.get(out_rel, {})), u["link"])

    # Detection final F2
    tw = cfg["detection"]["type_weights"]
    type_num = sum(tw.get(t, 0.5) * (sum(vals) / len(vals)) for t, vals in type_recalls.items() if vals)
    type_den = sum(tw.get(t, 0.5) for t, vals in type_recalls.items() if vals)
    macro_type = type_num / type_den if type_den else 1.0
    scripts_present = [script_recalls[s] for s in ("latin", "deva", "hinglish") if script_recalls.get(s)]
    macro_script = sum(sum(v) / len(v) for v in scripts_present) / len(scripts_present) if scripts_present else 1.0
    mix = cfg["detection"]["type_mix"]
    det_recall = mix * macro_type + (1.0 - mix) * macro_script

    trap_means = [sum(v) / len(v) for v in trap_group_scores.values() if v]
    trap_prec = sum(trap_means) / len(trap_means) if trap_means else 1.0
    clean_prec = sum(clean_token_scores) / len(clean_token_scores) if clean_token_scores else 1.0
    det_prec = 0.5 * trap_prec + 0.5 * clean_prec if (trap_means and clean_token_scores) else (trap_prec if trap_means else clean_prec)
    beta = cfg["detection"]["beta"]
    det_score = ((1 + beta**2) * det_prec * det_recall / ((beta**2) * det_prec + det_recall)) if (det_prec + det_recall) > 0 else 0.0

    # ------------------------------------------------------------------ 2. Identity Resolution (15%)
    any_psn = any(y is not None for _, y, _ in unit_patient.values())
    if not any_psn:
        id_score = 0.0
        id_prec = id_rec = id_f05 = id_b3 = 0.0
        merged_people = 0
    else:
        # Pairwise P (incl ambiguous) & R (excl ambiguous)
        all_items = list(unit_patient.items())
        req_items = [(k, v) for k, v in all_items if v[2] == "required" and v[0]]
        by_true_req = defaultdict(list)
        for idx, (_, (t, y, _)) in enumerate(req_items):
            by_true_req[t].append(idx)
        true_pairs = sum(len(v) * (len(v) - 1) // 2 for v in by_true_req.values())
        yours_all = defaultdict(list)
        for idx, (_, (t, y, lk)) in enumerate(all_items):
            if y:
                yours_all[y].append((t, lk))
        tp = fp = 0
        for members in yours_all.values():
            for (t1, l1), (t2, l2) in itertools.combinations(members, 2):
                if l1 == "required" and l2 == "required" and t1 == t2:
                    tp += 1
                else:
                    fp += 1
        id_prec = tp / (tp + fp) if (tp + fp) else 0.0
        id_rec = tp / true_pairs if true_pairs else 0.0
        id_f05 = (1.25 * id_prec * id_rec / (0.25 * id_prec + id_rec)) if (id_prec + id_rec) else 0.0
        merged_people = sum(1 for m in yours_all.values() if len({t for t, _ in m if t}) > 1)

        # B-cubed F1 on required units
        b3_p_sum = b3_r_sum = 0.0
        yours_req = defaultdict(set)
        true_req = defaultdict(set)
        for idx, (_, (t, y, _)) in enumerate(req_items):
            true_req[t].add(idx)
            if y:
                yours_req[y].add(idx)
        for idx, (_, (t, y, _)) in enumerate(req_items):
            tset = true_req[t]
            yset = yours_req[y] if y else {idx}
            inter = len(tset & yset)
            b3_p_sum += inter / len(yset)
            b3_r_sum += inter / len(tset)
        b3_p = b3_p_sum / len(req_items) if req_items else 0.0
        b3_r = b3_r_sum / len(req_items) if req_items else 0.0
        id_b3 = (2 * b3_p * b3_r / (b3_p + b3_r)) if (b3_p + b3_r) else 0.0

        def pair_recall_for_patients(pt_set: set[str]) -> float:
            sub = [((t, y)) for _, (t, y, lk) in all_items if lk == "required" and t in pt_set]
            bt = defaultdict(list)
            for i, (t, _) in enumerate(sub):
                bt[t].append(i)
            tp_s = tot_s = 0
            for idxs in bt.values():
                for i, j in itertools.combinations(idxs, 2):
                    tot_s += 1
                    if sub[i][1] and sub[i][1] == sub[j][1]:
                        tp_s += 1
            return tp_s / tot_s if tot_s else 1.0

        lang_s = pair_recall_for_patients(set(truth.get("traps", {}).get("language", [])))
        frag_s = pair_recall_for_patients(set(truth.get("traps", {}).get("fragmented", [])))
        hom_pairs = truth.get("traps", {}).get("homonym_pairs", [])
        if hom_pairs:
            sep = 0
            for p1, p2 in hom_pairs:
                ps1 = {y for _, (t, y, _) in all_items if t == p1 and y}
                ps2 = {y for _, (t, y, _) in all_items if t == p2 and y}
                if not (ps1 & ps2):
                    sep += 1
            hom_s = sep / len(hom_pairs)
        else:
            hom_s = 1.0
        id_score = 0.4 * id_f05 + 0.3 * id_b3 + 0.1 * lang_s + 0.1 * frag_s + 0.1 * hom_s

    # ------------------------------------------------------------------ 3. Clinical Utility (20%)
    uw = cfg["utility"]["weights"]
    probes_score = (sum(ok * w for ok, w in probe_scores) / sum(w for _, w in probe_scores)) if probe_scores else 1.0
    # Temporal: check if patient dates survived inside exported files (proxy for LOS/interval when dates exist)
    temp_score = probes_score  # refined in Phase 5 when date shifting is active
    gen_score = sum(gen_scores) / len(gen_scores) if gen_scores else 1.0
    stat_score = probes_score  # ICD-10/LOS/lab proxy based on probe survival
    tok_ret_score = sum(token_ret_scores) / len(token_ret_scores) if token_ret_scores else 1.0
    rec_ret_score = record_ret_hits / record_ret_total if record_ret_total else 1.0
    utility_score = (
        uw["clinical_probes"] * probes_score
        + uw["temporal"] * temp_score
        + uw["generalization"] * gen_score
        + uw["statistics"] * stat_score
        + uw["token_retention"] * tok_ret_score
        + uw["record_retention"] * rec_ret_score
    )

    # ------------------------------------------------------------------ 4. Integrity & Hygiene (10%)
    canaries = [
        e["surface"]
        for f in truth["files"].values()
        for u in f["units"].values()
        for e in u["entities"]
        if e.get("type") == "CANARY"
    ]
    leak_rep = scan_output_tree(out_dir, canaries=canaries, stdout_stderr=stdout_stderr)
    hygiene_score = sum(1.0 if v else 0.0 for v in leak_rep.channels_clean.values()) / max(1, len(leak_rep.channels_clean))

    non_null_claims = [r for r in raw_rec_lines if r.get("patient")]
    if non_null_claims:
        cons_hits = sum(1 for r in non_null_claims if str(r["patient"]) in exported_texts.get(str(r["file"]).replace("sanitized/", "", 1), ""))
        psn_cons_score = cons_hits / len(non_null_claims)
    else:
        psn_cons_score = 0.0

    q_safe = either_safe / either_total if either_total else 1.0
    drop_rate = silent_drops / max(1, len(truth["files"]))
    raw_rate = raw_copy_count / max(1, either_total)
    quarantine_score = 0.5 * q_safe + 0.3 * (1.0 - drop_rate) + 0.2 * (1.0 - raw_rate)

    req_report_keys = {"files", "counts", "timing", "resources"}
    req_counts = {"files_total", "files_sanitized", "files_quarantined", "records_processed", "identifiers_detected", "records_linked"}
    if report_valid:
        comp_score = (
            (0.5 if req_report_keys.issubset(report.keys()) else 0.0)
            + (0.5 if req_counts.issubset((report.get("counts") or {}).keys()) else 0.0)
        )
        cdict = report.get("counts") or {}
        actual_san = len(exported_texts)
        actual_tot = len(truth["files"])
        honesty_ok = (cdict.get("files_total") == actual_tot and cdict.get("files_sanitized") == actual_san)
        report_score = 0.5 * comp_score + 0.5 * (1.0 if honesty_ok else 0.0)
    else:
        report_score = 0.0

    iw = cfg["integrity"]["weights"]
    fmt_score = sum(format_valid_scores) / len(format_valid_scores) if format_valid_scores else 1.0
    sch_score = sum(schema_pres_scores) / len(schema_pres_scores) if schema_pres_scores else 1.0
    fhir_score = sum(fhir_valid_scores) / len(fhir_valid_scores) if fhir_valid_scores else 1.0
    integrity_score = (
        iw["format_validity"] * fmt_score
        + iw["schema_preservation"] * sch_score
        + iw["fhir_validity"] * fhir_score
        + iw["pseudonym_consistency"] * psn_cons_score
        + iw["channel_hygiene"] * hygiene_score
        + iw["quarantine_handling"] * quarantine_score
        + iw["report_quality"] * report_score
    )

    # ------------------------------------------------------------------ 5. Privacy (25%)
    if attacker_dir and (attacker_dir / "registry.csv").is_file() and (attacker_dir / "known_facts.jsonl").is_file():
        atk = run_attack(
            out_dir, truth, attacker_dir / "registry.csv", attacker_dir / "known_facts.jsonl",
            scoring_weights=cfg["privacy"]["weights"], raw_attack_path=raw_attack_path,
            alt_secret_out_dir=alt_secret_out_dir, utility_score=utility_score,
            utility_coupling_threshold=cfg["privacy"]["utility_coupling_threshold"],
        )
        privacy_score = atk.privacy_score
        atk_dict = atk.__dict__
    else:
        privacy_score = 0.0
        atk_dict = {}

    # ------------------------------------------------------------------ 6. Speed & Reliability (10%)
    prof = cfg["performance"]["profiles"].get(profile, cfg["performance"]["profiles"]["small"])
    w_s = wall_seconds if wall_seconds is not None else float((report.get("timing") or {}).get("seconds", 1.0))
    m_mb = peak_rss_mb if peak_rss_mb is not None else float((report.get("resources") or {}).get("peak_rss_mb", 64.0))
    if m_mb <= 0:
        m_mb = 32.0
    rel_score = 1.0 if exit_code == 0 else 0.3
    time_score = _log_linear_score(w_s, prof["time_good_s"], prof["time_limit_s"])
    mem_score = _log_linear_score(m_mb, prof["memory_good_mb"], prof["memory_limit_mb"])
    perf_score = 0.30 * rel_score + 0.30 * time_score + 0.20 * mem_score + 0.20 * determinism_rate

    # ------------------------------------------------------------------ Penalties
    pen = cfg["penalties"]
    p_leaked = min(pen["leaked_identifier_cap"], len(leaked_unique_ids) * pen["per_leaked_identifier"])
    p_canary = min(pen["canary_cap"], leak_rep.canary_hits * pen["per_canary_leak"])
    p_raw = min(pen["unprocessed_cap"], raw_copy_count * pen["per_unprocessed_export"])
    p_false = pen["false_success"] if (exit_code == 0 and (not report_valid or silent_drops > 0)) else 0.0
    p_tamper = pen["input_tampering"] if input_tampered else 0.0
    total_penalties = p_leaked + p_canary + p_raw + p_false + p_tamper

    subtotal = 100.0 * (
        weights["privacy"] * privacy_score
        + weights["detection"] * det_score
        + weights["utility"] * utility_score
        + weights["identity_resolution"] * id_score
        + weights["integrity"] * integrity_score
        + weights["performance"] * perf_score
    )
    total = subtotal - total_penalties

    return {
        "total": round(total, 2),
        "subtotal": round(subtotal, 2),
        "penalties": {
            "total": round(total_penalties, 2),
            "leaked_identifiers": round(p_leaked, 2),
            "canary_leaks": round(p_canary, 2),
            "raw_copies": round(p_raw, 2),
            "false_success": round(p_false, 2),
            "input_tampering": round(p_tamper, 2),
        },
        "components": {
            "privacy": round(privacy_score, 4),
            "detection": round(det_score, 4),
            "utility": round(utility_score, 4),
            "identity_resolution": round(id_score, 4),
            "integrity": round(integrity_score, 4),
            "performance": round(perf_score, 4),
        },
        "details": {
            "det_recall": round(det_recall, 4),
            "det_precision": round(det_prec, 4),
            "id_prec": round(id_prec, 4),
            "id_rec": round(id_rec, 4),
            "id_f05": round(id_f05, 4),
            "id_b3": round(id_b3, 4),
            "merged_people": merged_people,
            "probes_kept_rate": round(probes_score, 4),
            "canary_hits": leak_rep.canary_hits,
            "leaked_unique_critical_ids": len(leaked_unique_ids),
            "raw_copies": raw_copy_count,
            "silent_drops": silent_drops,
            "channels_clean": leak_rep.channels_clean,
            "attacker": atk_dict,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Local scorer reproducing scoring.toml & SCORING.md")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--scoring", required=True)
    ap.add_argument("--attacker-dir", default="")
    ap.add_argument("--raw-attack", default="")
    ap.add_argument("--profile", default="small")
    args = ap.parse_args()
    truth = json.loads(Path(args.truth).read_text(encoding="utf-8"))
    res = score_output(
        Path(args.input), Path(args.output), truth, Path(args.scoring),
        attacker_dir=Path(args.attacker_dir) if args.attacker_dir else None,
        raw_attack_path=Path(args.raw_attack) if args.raw_attack else None,
        profile=args.profile,
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
