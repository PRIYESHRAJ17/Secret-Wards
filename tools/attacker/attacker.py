"""In-house Privacy Attack Arena simulator implementing A1-A7 from docs/ATTACKS.md.

Mirrors the official attacker:
  - Evidence extraction (ages/bands with ATTACKS.md:104-111 self-checks, birth years,
    gender, district/tehsil/village, PIN & 3-digit prefix, names/relatives, phones, masked IDs,
    rare conditions, hospitals, dates)
  - A1: Direct exposure
  - A2/A3: Ordered skip-on-empty filter cascade + multiplicative candidate weighting
  - A4: Profile aggregation via in-record pseudonyms / patient_ref / uhid
  - A5: Targeted attack with >= 2 @ >= 0.9 global date-shift recovery + decoy false claims
  - A6: Pseudonym inversion (case, digits, MD5/SHA1/SHA256/SHA512 >=8 hex, base64, reversal, embedded ID)
  - A7: Cross-release linkability across two secrets
  - Plus fuzzy/phonetic residue attack (R-133)
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import io
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from tools.leakscan.scanner import consonant_skeleton, decode_hidden_payloads, norm_scoring

# Age extraction regexes honoring ATTACKS.md:104-111 (ignore durations `x 12 yrs`, `70-140` lab ranges)
_AGE_BAND_RE = re.compile(r"\b(\d{1,3})\s*[-–]\s*(\d{1,3})\s*(?:yrs?|years?|y|वर्ष)?(?:\s*/\s*([mf]))?\b", re.I)
_AGE_PLUS_RE = re.compile(r"\b(\d{2,3})\s*\+(?:\s*(?:yrs?|years?|y))?\b", re.I)
_AGE_EXACT_RE = re.compile(r"(?:age\s*[:=]\s*|(?<![-\d])\b)(\d{1,3})\s*(?:yrs?|years?|saal|वर्ष|y\s*/\s*([mf]))\b", re.I)
_AGE_SLASH_GENDER_RE = re.compile(r"\b(\d{1,3})\s*/\s*([mf])\b", re.I)
_DURATION_CTX_RE = re.compile(r"(?:x\s*\d+\s*(?:yrs?|years?|days?)|\d+\s*(?:yrs?|years?)\s*back|range|ref)", re.I)
_BIRTH_YEAR_RE = re.compile(r"\b(19\d{2}|20[0-2]\d)\b")
_ISO_DATE_RE = re.compile(r"(?<!\d)(20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])(?!\d)")
_DMY_DATE_RE = re.compile(r"\b(\d{1,2})[/-](\d{1,2})[/-]((?:19|20)?\d{2})\b")
_PIN_FULL_RE = re.compile(r"\b([1-8]\d{5})\b")
_PIN_PFX_RE = re.compile(r"\b([1-8]\d{2})\*{2,3}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?([6-9]\d{4}[\s-]?\d{5})(?!\d)")
_MASKED_PHONE_RE = re.compile(r"\b([6-9]\d)x{4,}(\d{2,4})\b", re.I)
_MASKED_AADHAAR_RE = re.compile(r"\b[xX*]{4}[\s-]?[xX*]{4}[\s-]?(\d{4})\b")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
_PSN_RE = re.compile(r"\bPSN-[0-9A-Z]{6,16}\b")


def extract_age_constraints(text: str) -> list[tuple[int, int]]:
    """Parse exact ages and age bands while ignoring durations and lab reference ranges (ATTACKS.md:104-111)."""
    constraints: list[tuple[int, int]] = []
    for line in text.splitlines():
        l_low = line.casefold()
        for m in _AGE_BAND_RE.finditer(line):
            lo, hi = int(m.group(1)), int(m.group(2))
            if not (0 <= lo <= hi <= 120):
                continue
            prefix = l_low[max(0, m.start() - 20):m.start()]
            suffix = l_low[m.end():m.end() + 20]
            # Ignore lab ranges like "Hb 12.0-16.0" or "70-140 mg/dL" unless age cue or /M,/F present
            has_age_cue = bool(m.group(3) or re.search(r"age|umar|आयु|yrs?|years?|band", prefix + suffix))
            if not has_age_cue and (hi - lo > 30 or "mg/dl" in suffix or "/ul" in suffix or "range" in prefix):
                continue
            constraints.append((lo, hi))
        for m in _AGE_PLUS_RE.finditer(line):
            lo = int(m.group(1))
            if 50 <= lo <= 110:
                constraints.append((lo, 120))
        for m in _AGE_SLASH_GENDER_RE.finditer(line):
            a = int(m.group(1))
            if 0 <= a <= 115:
                constraints.append((max(0, a - 1), a + 1))
        for m in _AGE_EXACT_RE.finditer(line):
            # Skip duration context ("x 12 yrs", "7 yrs back")
            ctx = l_low[max(0, m.start() - 8):min(len(l_low), m.end() + 12)]
            if _DURATION_CTX_RE.search(ctx):
                continue
            a = int(m.group(1))
            if 0 <= a <= 115:
                constraints.append((max(0, a - 1), a + 1))
    return constraints


def _parse_dates(text: str) -> list[dt.date]:
    out: list[dt.date] = []
    for m in _ISO_DATE_RE.finditer(text):
        try:
            out.append(dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
        except ValueError:
            pass
    for m in _DMY_DATE_RE.finditer(text):
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if y < 100:
            y += 2000 if y <= 30 else 1900
        if 1 <= mo <= 12 and 1 <= d <= 31:
            try:
                out.append(dt.date(y, mo, d))
            except ValueError:
                pass
    return out


@dataclass
class RegistryPerson:
    rid: str
    name: str
    given: str
    surname: str
    rel_name: str
    gender: str
    age: int
    house: str
    village: str
    tehsil: str
    district: str
    pin: str
    pin_prefix: str
    phone: str
    email: str
    aadhaar_last4: str


def load_registry(path: Path) -> list[RegistryPerson]:
    people: list[RegistryPerson] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            nm = norm_scoring(row.get("name", ""))
            toks = nm.split()
            people.append(RegistryPerson(
                rid=row["rid"],
                name=nm,
                given=toks[0] if toks else "",
                surname=toks[-1] if len(toks) > 1 else "",
                rel_name=norm_scoring(row.get("relative_name", "")),
                gender=row.get("gender", "").strip().upper()[:1],
                age=int(row["age"]) if row.get("age", "").isdigit() else -1,
                house=norm_scoring(row.get("house_no", "")),
                village=norm_scoring(row.get("village", "")),
                tehsil=norm_scoring(row.get("tehsil", "")),
                district=norm_scoring(row.get("district", "")),
                pin=row.get("pin", "").strip(),
                pin_prefix=row.get("pin", "").strip()[:3],
                phone=re.sub(r"\D", "", row.get("phone", ""))[-10:],
                email=norm_scoring(row.get("email", "")),
                aadhaar_last4=row.get("aadhaar_last4", "").strip(),
            ))
    return people


def _extract_record_blobs(file_path: Path, fmt: str) -> list[tuple[str, str]]:
    """Return [(loc, text_blob)] for a sanitized file."""
    try:
        raw = file_path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return []
    raw_dec = decode_hidden_payloads(raw)
    if fmt in ("csv", "tsv"):
        delim = "\t" if fmt == "tsv" or ("\t" in raw.splitlines()[0] if raw.splitlines() else False) else ","
        try:
            rows = list(csv.reader(io.StringIO(raw, newline=""), delimiter=delim))
        except csv.Error:
            return [("doc", raw_dec)]
        if len(rows) <= 1:
            return []
        hdr = rows[0]
        out = []
        for idx, r in enumerate(rows[1:]):
            pairs = " ".join(f"{hdr[i] if i < len(hdr) else ''}: {c}" for i, c in enumerate(r))
            out.append((f"row:{idx}", decode_hidden_payloads(pairs)))
        return out
    if fmt == "json":
        try:
            obj = json.loads(raw)
        except ValueError:
            return [("doc", raw_dec)]
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                    pk = k.replace("~", "~0").replace("/", "~1")
                    return [(f"/{pk}/{i}", decode_hidden_payloads(json.dumps(item, ensure_ascii=False))) for i, item in enumerate(v)]
        return [("doc", raw_dec)]
    return [("doc", raw_dec)]


def _extract_evidence(text: str, districts: set[str], tehsils: set[str], villages: set[str], hospitals: set[str], rare_dx: set[str]) -> dict:
    ntext = norm_scoring(text)
    ages = extract_age_constraints(text)
    years = [int(y) for y in _BIRTH_YEAR_RE.findall(ntext) if 1900 <= int(y) <= 2026]
    gender = ""
    if re.search(r"\b(female|mahila|behenji|w/o|d/o)\b|/\s*f\b", ntext):
        gender = "F"
    elif re.search(r"\b(male|purush|sahab|s/o)\b|/\s*m\b", ntext):
        gender = "M"
    phones = [re.sub(r"\D", "", m.group(1))[-10:] for m in _PHONE_RE.finditer(ntext)]
    mphones = [(m.group(1), m.group(2)) for m in _MASKED_PHONE_RE.finditer(ntext)]
    last4s = _MASKED_AADHAAR_RE.findall(ntext)
    emails = _EMAIL_RE.findall(ntext)
    pins = _PIN_FULL_RE.findall(ntext)
    pin_pfxs = _PIN_PFX_RE.findall(ntext) + [p[:3] for p in pins]
    psns = _PSN_RE.findall(text)
    dates = _parse_dates(text)
    found_dist = {d for d in districts if d and re.search(r"(?<!\w)" + re.escape(d) + r"(?!\w)", ntext)}
    found_teh = {t for t in tehsils if t and re.search(r"(?<!\w)" + re.escape(t) + r"(?!\w)", ntext)}
    found_vil = {v for v in villages if v and re.search(r"(?<!\w)" + re.escape(v) + r"(?!\w)", ntext)}
    found_hosp = {h for h in hospitals if h and h in ntext}
    found_dx = {dx for dx in rare_dx if dx and dx in ntext}
    return {
        "ntext": ntext,
        "ages": ages,
        "birth_years": years,
        "gender": gender,
        "phones": set(phones),
        "masked_phones": mphones,
        "last4s": set(last4s),
        "emails": set(emails),
        "pins": set(pins),
        "pin_pfxs": set(pin_pfxs),
        "districts": found_dist,
        "tehsils": found_teh,
        "villages": found_vil,
        "hospitals": found_hosp,
        "rare_dx": found_dx,
        "psns": psns,
        "dates": dates,
    }


def _score_registry_candidates(ev: dict, registry: list[RegistryPerson], ref_year: int = 2026) -> dict[str, float]:
    """A2/A3 ordered skip-on-empty filter cascade + multiplicative weights (ATTACKS.md:43-50)."""
    cands = list(registry)

    def apply_filter(pred):
        nonlocal cands
        sub = [c for c in cands if pred(c)]
        if sub:
            cands = sub

    if ev["phones"]:
        apply_filter(lambda c: c.phone and c.phone in ev["phones"])
    if ev["emails"]:
        apply_filter(lambda c: c.email and c.email in ev["emails"])
    if ev["last4s"]:
        apply_filter(lambda c: c.aadhaar_last4 and c.aadhaar_last4 in ev["last4s"])
    if ev["masked_phones"]:
        apply_filter(lambda c: any(c.phone.startswith(p0) and c.phone.endswith(p1) for p0, p1 in ev["masked_phones"]))
    if ev["districts"]:
        apply_filter(lambda c: c.district in ev["districts"])
    if ev["gender"]:
        apply_filter(lambda c: c.gender == ev["gender"])
    if ev["ages"]:
        apply_filter(lambda c: c.age >= 0 and any((lo - 1) <= c.age <= (hi + 2) for lo, hi in ev["ages"]))
    elif ev["birth_years"]:
        apply_filter(lambda c: c.age >= 0 and any(abs((ref_year - c.age) - y) <= 2 for y in ev["birth_years"]))
    if ev["tehsils"]:
        apply_filter(lambda c: c.tehsil in ev["tehsils"])
    if ev["villages"]:
        apply_filter(lambda c: c.village in ev["villages"])
    if ev["pins"]:
        apply_filter(lambda c: c.pin in ev["pins"])
    elif ev["pin_pfxs"]:
        apply_filter(lambda c: c.pin_prefix in ev["pin_pfxs"])

    ntext = ev["ntext"]
    weights: dict[str, float] = {}
    for c in cands:
        w = 1.0
        if c.name and c.name in ntext:
            w *= 60.0
        else:
            if c.given and len(c.given) >= 3 and re.search(r"(?<!\w)" + re.escape(c.given) + r"(?!\w)", ntext):
                # Skip Dr. <given>
                if f"dr. {c.given}" not in ntext and f"dr {c.given}" not in ntext:
                    w *= 8.0
            if c.surname and len(c.surname) >= 3 and re.search(r"(?<!\w)" + re.escape(c.surname) + r"(?!\w)", ntext):
                w *= 3.0
        if c.rel_name and c.rel_name in ntext:
            w *= 8.0
        if c.house and len(c.house) >= 2 and re.search(r"(?:h\.?no\.?|house)\s*" + re.escape(c.house) + r"\b", ntext):
            w *= 2.0
        weights[c.rid] = w
    tot = sum(weights.values()) or 1.0
    return {rid: w / tot for rid, w in weights.items()}


def _a6_invert_pseudonym(psn: str, patient_originals: list[str]) -> bool:
    """Check whether pseudonym matches unkeyed hash/encoding/embedded-ID transforms (ATTACKS.md:70-75)."""
    core = psn.split("-", 1)[-1].casefold() if "-" in psn else psn.casefold()
    if len(core) < 4:
        return False
    for orig in patient_originals:
        if not orig:
            continue
        variants = {orig, orig.lower(), orig.upper(), re.sub(r"\D", "", orig)}
        for v in list(variants):
            if not v:
                continue
            if len(v) >= 6 and (v.lower() in psn.lower() or psn.lower() in v.lower()):
                return True
            if v[::-1].lower() == core:
                return True
            b64 = base64.b64encode(v.encode("utf-8")).decode("ascii").rstrip("=").lower()
            if len(b64) >= 6 and (core.startswith(b64[:6]) or b64.startswith(core)):
                return True
            for hfn in (hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512):
                hx = hfn(v.encode("utf-8")).hexdigest().lower()
                if len(core) >= 6 and (hx.startswith(core) or core.startswith(hx[:8])):
                    return True
    return False


@dataclass
class AttackReport:
    records_attacked: int = 0
    patients_present: int = 0
    a1_direct_exposure: float = 0.0
    a2_a3_record_linkage: float = 0.0
    a4_profile_reid: float = 0.0
    a5_targeted_success: float = 0.0
    a6_pseudonym_inversion: float | None = None
    a7_cross_release: float | None = None
    residue_hits: int = 0
    decoy_false_claims: float = 0.0
    recovered_global_shift_days: int | None = None
    candidate_set_sizes: list[int] = field(default_factory=list)
    normalized_risk: float = 0.0
    privacy_score: float = 0.0


def run_attack(
    out_dir: Path,
    truth: dict,
    registry_path: Path,
    known_facts_path: Path,
    scoring_weights: dict[str, float] | None = None,
    raw_attack_path: Path | None = None,
    alt_secret_out_dir: Path | None = None,
    utility_score: float = 1.0,
    utility_coupling_threshold: float = 0.40,
) -> AttackReport:
    """Execute A1-A7 + residue attack against sanitized output."""
    registry = load_registry(registry_path)
    reg_by_rid = {r.rid: r for r in registry}
    facts = [json.loads(line) for line in known_facts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    raw_ref = json.loads(raw_attack_path.read_text(encoding="utf-8"))["result"] if raw_attack_path and raw_attack_path.is_file() else {}

    districts = {r.district for r in registry if r.district}
    tehsils = {r.tehsil for r in registry if r.tehsil}
    villages = {r.village for r in registry if r.village}
    hospitals = {norm_scoring(f["hospital"]) for f in facts if f.get("hospital")}
    rare_dx = {norm_scoring(f["condition_hint"]) for f in facts if f.get("condition_hint")}

    # Map report.json renamed paths
    san = out_dir / "sanitized"
    renamed = {}
    try:
        rep = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        renamed = {e.get("input_sha256"): e.get("output") for e in rep.get("files") or []}
    except (OSError, ValueError):
        pass

    # Map patient -> rid (single pass for A1, A2/A3, and A4 profile collection)
    pt_to_rid = {pt_id: pinfo.get("rid") for pt_id, pinfo in truth.get("patients", {}).items()}
    patients_exposed_direct: set[str] = set()
    rec_probs: list[float] = []
    rec_true_rids: list[str] = []
    profiles_by_key: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    unpooled_records: list[tuple[str, dict, dict[str, float]]] = []
    patient_psns: dict[str, set[str]] = defaultdict(set)
    patient_dates: dict[str, list[dt.date]] = defaultdict(list)
    _mrn_ref_re = re.compile(r"\b(?:SNJ/\d+/\d+|JJH-\d+|UHID-\d+|DHH\d+-\d+|[A-Z]{2,5}-26-\d+)\b")

    for rel, finfo in sorted(truth["files"].items()):
        out_rel = rel
        decl = renamed.get(finfo["sha256"])
        if decl:
            out_rel = str(decl).replace("sanitized/", "", 1)
        fp = san / out_rel
        if not fp.is_file():
            continue
        blobs = _extract_record_blobs(fp, finfo.get("format", "text"))
        blob_map = {loc: txt for loc, txt in blobs}
        whole_txt = "\n".join(txt for _, txt in blobs)

        for loc, u in finfo.get("units", {}).items():
            pt_id = u.get("patient")
            if not pt_id or pt_id not in pt_to_rid:
                continue
            true_rid = pt_to_rid[pt_id]
            txt = blob_map.get(loc, whole_txt)
            ntxt = norm_scoring(txt)
            # A1 direct exposure check (critical direct IDs or full patient name)
            for e in u.get("entities", []):
                if e.get("critical") and e.get("type") != "CANARY":
                    surf = norm_scoring(e["surface"])
                    dig = re.sub(r"\D", "", surf)
                    if (len(dig) >= 6 and dig in re.sub(r"\D", "", ntxt)) or (surf and surf in ntxt):
                        patients_exposed_direct.add(pt_id)
            ev = _extract_evidence(txt, districts, tehsils, villages, hospitals, rare_dx)
            probs = _score_registry_candidates(ev, registry)
            p_true = probs.get(true_rid, 0.0)
            rec_probs.append(p_true)
            rec_true_rids.append(true_rid)
            for psn in ev["psns"]:
                patient_psns[pt_id].add(psn)
            keys = list(dict.fromkeys(ev["psns"])) or list(dict.fromkeys(_mrn_ref_re.findall(txt)))
            if keys:
                for k in keys:
                    profiles_by_key[k].append((true_rid, ev))
            else:
                unpooled_records.append((true_rid, ev, probs))
            patient_dates[pt_id].extend(ev["dates"])

    # A4: profile aggregation over in-record pseudonyms or MRN/patient_ref, plus unpooled records
    max_prob_by_rid: dict[str, float] = defaultdict(float)
    for rid, pr in zip(rec_true_rids, rec_probs):
        max_prob_by_rid[rid] = max(max_prob_by_rid[rid], pr)
    pooled_profiles: list[tuple[set[str], dict, dict[str, float]]] = []

    for psn, items in profiles_by_key.items():
        merged_ev = {
            "ntext": " ".join(x[1]["ntext"] for x in items),
            "ages": [a for x in items for a in x[1]["ages"]],
            "birth_years": [y for x in items for y in x[1]["birth_years"]],
            "gender": next((x[1]["gender"] for x in items if x[1]["gender"]), ""),
            "phones": set().union(*(x[1]["phones"] for x in items)),
            "masked_phones": [mp for x in items for mp in x[1]["masked_phones"]],
            "last4s": set().union(*(x[1]["last4s"] for x in items)),
            "emails": set().union(*(x[1]["emails"] for x in items)),
            "pins": set().union(*(x[1]["pins"] for x in items)),
            "pin_pfxs": set().union(*(x[1]["pin_pfxs"] for x in items)),
            "districts": set().union(*(x[1]["districts"] for x in items)),
            "tehsils": set().union(*(x[1]["tehsils"] for x in items)),
            "villages": set().union(*(x[1]["villages"] for x in items)),
            "hospitals": set().union(*(x[1]["hospitals"] for x in items)),
            "rare_dx": set().union(*(x[1]["rare_dx"] for x in items)),
            "psns": [psn],
            "dates": [d for x in items for d in x[1]["dates"]],
        }
        pprobs = _score_registry_candidates(merged_ev, registry)
        rids_in = {x[0] for x in items}
        for rid in rids_in:
            max_prob_by_rid[rid] = max(max_prob_by_rid[rid], pprobs.get(rid, 0.0))
        pooled_profiles.append((rids_in, merged_ev, pprobs))

    for rid_u, ev_u, probs_u in unpooled_records:
        pooled_profiles.append(({rid_u}, ev_u, probs_u))

    # A5: Global shift recovery + targeted known-facts attack (ATTACKS.md:64-66: >= 2 people agree)
    shift_votes: Counter[int] = Counter()
    for rids_in, mev, pprobs in pooled_profiles:
        top_rid, top_p = max(pprobs.items(), key=lambda kv: kv[1], default=("", 0.0))
        if top_p >= 0.9 and mev["dates"]:
            profile_offsets: set[int] = set()
            for kf in facts:
                if kf["rid"] == top_rid:
                    for kd in kf.get("visit_dates", []):
                        kd_dt = dt.date.fromisoformat(kd)
                        for pd_dt in set(mev["dates"]):
                            profile_offsets.add((pd_dt - kd_dt).days)
            for off in profile_offsets:
                shift_votes[off] += 1
    recovered_shift = 0
    if shift_votes:
        best_shift, cnt = shift_votes.most_common(1)[0]
        if cnt >= 2:
            recovered_shift = best_shift

    dx_freq = Counter(dx for _, mev, _ in pooled_profiles for dx in mev["rare_dx"])
    target_hits: list[float] = []
    decoy_claims = 0
    decoy_total = 0
    for kf in facts:
        krid = kf["rid"]
        is_patient = krid in set(pt_to_rid.values())
        if not is_patient:
            decoy_total += 1
        kf_dates = [dt.date.fromisoformat(d) for d in kf.get("visit_dates", [])]
        kf_hosp = norm_scoring(kf.get("hospital", ""))
        kf_dx = norm_scoring(kf.get("condition_hint", ""))
        kf_stay = kf.get("stay_days")

        prof_scores: dict[int, float] = {}
        for pi, (rids_in, mev, pprobs) in enumerate(pooled_profiles):
            base_p = pprobs.get(krid, 0.0)
            if base_p <= 0.0:
                continue
            mult = 1.0
            unshifted = [d - dt.timedelta(days=recovered_shift) for d in mev["dates"]]
            if any(abs((ud - kd).days) <= 1 for ud in unshifted for kd in kf_dates):
                mult *= 4.0
            if kf_hosp and kf_hosp in mev["hospitals"]:
                mult *= 2.0
            if kf_dx and kf_dx in mev["rare_dx"]:
                mult *= 8.0 if dx_freq[kf_dx] <= 3 else 2.0
            if kf_stay is not None and len(mev["dates"]) >= 2:
                intervals = {abs((d2 - d1).days) for i, d1 in enumerate(mev["dates"]) for d2 in mev["dates"][i + 1:]}
                if kf_stay in intervals:
                    mult *= 3.0
            if mult > 1.0:
                prof_scores[pi] = base_p * mult
        if not is_patient:
            if prof_scores:
                decoy_claims += 1
            continue
        tot_s = sum(prof_scores.values())
        if tot_s > 0:
            true_s = sum(sc for pi, sc in prof_scores.items() if krid in pooled_profiles[pi][0])
            target_hits.append(true_s / tot_s)
        else:
            target_hits.append(0.0)

    # A6: Pseudonym inversion
    a6_val: float | None = None
    if any(patient_psns.values()):
        inverted = 0
        psn_pts = 0
        for pt_id, psns in patient_psns.items():
            if not psns:
                continue
            psn_pts += 1
            rid = pt_to_rid.get(pt_id)
            originals = []
            if rid and rid in reg_by_rid:
                rp = reg_by_rid[rid]
                originals.extend([rp.name, rp.phone, rp.email])
            for e_mrn in truth.get("patients", {}).get(pt_id, {}).get("uhids", {}).values():
                originals.extend(e_mrn)
            if any(_a6_invert_pseudonym(psn, originals) for psn in psns):
                inverted += 1
        a6_val = inverted / psn_pts if psn_pts else 0.0

    # A7: Cross-release linkability
    a7_val: float | None = None
    if alt_secret_out_dir and alt_secret_out_dir.is_dir():
        alt_psns: dict[str, set[str]] = defaultdict(set)
        alt_dates: dict[str, list[dt.date]] = defaultdict(list)
        for rel, finfo in truth["files"].items():
            fp = alt_secret_out_dir / "sanitized" / rel
            if not fp.is_file():
                continue
            for _, txt in _extract_record_blobs(fp, finfo.get("format", "text")):
                for loc, u in finfo.get("units", {}).items():
                    pt_id = u.get("patient")
                    if pt_id:
                        alt_psns[pt_id].update(_PSN_RE.findall(txt))
                        alt_dates[pt_id].extend(_parse_dates(txt))
        comparable_pts = [pt for pt in patient_psns if patient_psns[pt] and alt_psns.get(pt)]
        same_psn = sum(1 for pt in comparable_pts if patient_psns[pt] & alt_psns[pt]) / len(comparable_pts) if comparable_pts else 0.0
        comp_d = [pt for pt in patient_dates if patient_dates[pt] and alt_dates.get(pt)]
        same_dt = sum(1 for pt in comp_d if set(patient_dates[pt]) & set(alt_dates[pt])) / len(comp_d) if comp_d else 0.0
        a7_val = max(same_psn, same_dt)

    # Residue attack (fuzzy/phonetic check on voter registry names against sanitized/)
    residue_hits = 0
    if san.is_dir():
        all_raw = "\n".join(
            p.read_bytes().decode("utf-8", errors="replace")
            for p in sorted(san.rglob("*"))
            if p.is_file()
        )
        nt_all = norm_scoring(decode_hidden_payloads(all_raw))
        sk_all = consonant_skeleton(all_raw)
        for rp in registry:
            if len(rp.name.split()) < 2:
                continue
            sk = consonant_skeleton(rp.name)
            if rp.name in nt_all or (len(sk.replace(" ", "")) >= 7 and sk in sk_all):
                residue_hits += 1

    n_pts = max(1, len(truth.get("patients", {})))
    a1 = len(patients_exposed_direct) / n_pts
    raw_a23 = sum(rec_probs) / len(rec_probs) if rec_probs else 0.0
    raw_a4 = sum(1 for v in max_prob_by_rid.values() if v >= 0.5) / n_pts
    raw_a5 = sum(target_hits) / len(target_hits) if target_hits else 0.0

    # Normalize against raw_attack.json when provided
    a23_norm = min(1.0, raw_a23 / raw_ref["record_linkage_risk"]) if raw_ref.get("record_linkage_risk") else raw_a23
    a4_norm = min(1.0, raw_a4 / raw_ref["patients_reidentified"]) if raw_ref.get("patients_reidentified") else raw_a4
    a5_norm = min(1.0, raw_a5 / raw_ref["targeted_success"]) if raw_ref.get("targeted_success") else raw_a5

    w = scoring_weights or {
        "direct_exposure": 0.20,
        "record_linkage": 0.20,
        "profile_reidentification": 0.20,
        "targeted_attack": 0.20,
        "pseudonym_inversion": 0.10,
        "cross_release": 0.10,
    }
    comp = [
        (w["direct_exposure"], a1),
        (w["record_linkage"], a23_norm),
        (w["profile_reidentification"], a4_norm),
        (w["targeted_attack"], a5_norm),
    ]
    if a6_val is not None:
        comp.append((w["pseudonym_inversion"], a6_val))
    if a7_val is not None:
        comp.append((w["cross_release"], a7_val))
    risk = sum(wi * vi for wi, vi in comp) / sum(wi for wi, _ in comp)
    resistance = max(0.0, 1.0 - risk)
    priv = resistance * min(1.0, utility_score / utility_coupling_threshold)

    return AttackReport(
        records_attacked=len(rec_probs),
        patients_present=n_pts,
        a1_direct_exposure=a1,
        a2_a3_record_linkage=a23_norm,
        a4_profile_reid=a4_norm,
        a5_targeted_success=a5_norm,
        a6_pseudonym_inversion=a6_val,
        a7_cross_release=a7_val,
        residue_hits=residue_hits,
        decoy_false_claims=(decoy_claims / decoy_total) if decoy_total else 0.0,
        recovered_global_shift_days=recovered_shift,
        normalized_risk=risk,
        privacy_score=priv,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Run A1-A7 privacy attack arena simulator")
    ap.add_argument("--output", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--attacker-dir", required=True)
    ap.add_argument("--raw-attack", default="")
    ap.add_argument("--utility", type=float, default=1.0)
    args = ap.parse_args()
    truth = json.loads(Path(args.truth).read_text(encoding="utf-8"))
    rep = run_attack(
        Path(args.output),
        truth,
        Path(args.attacker_dir) / "registry.csv",
        Path(args.attacker_dir) / "known_facts.jsonl",
        raw_attack_path=Path(args.raw_attack) if args.raw_attack else None,
        utility_score=args.utility,
    )
    print(json.dumps(rep.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
