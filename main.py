"""Secret Wards CLI entrypoint: two-pass offline multilingual clinical privacy firewall."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import regex as re
import yaml

from src.detect.arbitrate import _SAFE_CLINICAL_STOPWORDS, clean_text_with_arbitration
from src.export import write_outputs
from src.ingest import IngestedFile, QuarantinedFile, discover_files, ingest_file
from src.linkage import RecordProfile, build_clusters
from src.privacy import shift_days_for_key
from src.pseudonym import issue_psn
from src.sanitize.csv_tsv import _classify_column, sanitize_csv_tsv
from src.sanitize.fhir import sanitize_fhir_bundle
from src.sanitize.json_tree import sanitize_json_doc
from src.sanitize.text import sanitize_text_doc
from src.secure import derive_keys, install_safe_error_handlers, peak_rss_mb
from src.surfaces import sanitize_rel_path
from src.textnorm import canonical_name_parts, fold_digits, normalize_match, norm_mrn, norm_phone
from src.verify import verify_sanitized_file

_TEXT_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
_TEXT_AADHAAR_RE = re.compile(r"(?<!\d)(?:[2-9]\d{3}[\s-]\d{4}[\s-]\d{4}|[2-9]\d{11})(?!\d)")
_TEXT_ABHA_RE = re.compile(r"(?<!\d)91[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)")
_TEXT_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_TEXT_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_TEXT_MRN_EXPLICIT_RE = re.compile(
    r"\b(?:[A-Z]{2,5}[-/]\d{2,4}[-/]\d{4,}|[A-Z]{2,5}/(?:LOCAL|IPD|OPD)/\d{3,}|(?:UHID|JJH|DHH\d{2,4})-\d{5,}|ADM\d{5,})\b",
    re.I,
)
_TEXT_MRN_LBL_RE = re.compile(
    r"(?:UHID|IPD(?:\s*No\.?)?|MRN|Adm(?:ission)?\.?\s*No\.?|Reg(?:istration)?\.?\s*No\.?|पंजीकरण\s*सं\.?|आईपीडी\s*सं\.?)\s*[:=-]\s*([A-Za-z0-9][A-Za-z0-9/-]{3,24})",
    re.I,
)
_TEXT_PATIENT_RE = re.compile(
    r"(?m)(?:(?:^|\s)(?:Patient\s*(?:Name)?|Pt\.?\s*Name)\s*[:=-]\s*([^\n\t]+?)(?=\s{2,}|\s+(?:Age(?:/Sex)?|Sex|DOB|Mob(?:ile)?|Phone|UHID|IPD|MRN)|$)|(?:मरीज़\s*का\s*नाम|रोगी\s*का\s*नाम|नाम)\s*[:=-]\s*([\u0900-\u097F][\u0900-\u097F\s.]{1,40}?)(?=\s{2,}|\s+(?:आयु|उम्र|लिंग|पता|ग्राम|पंजीकरण)|$))",
    re.I,
)
_TEXT_PATIENT_FALLBACK_RE = re.compile(
    r"(?:\bReport\s+of\s+([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)\s*(?:ji|behenji|bhaiya|bhai|babu|sahab|didi|\d|\n|$)|"
    r"(?m)(?:^|[.!?\n]\s*)([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?),\s*(?:S/[Oo]|D/[Oo]|W/[Oo])|"
    r"(?m)(?:^|\n|[।?!]\s*)([\u0900-\u097F]{2,}(?:\s+[\u0900-\u097F]{2,}){1,2})\s+(?:को|ने)\s+(?:\d+\s*दिन|बुखार|दर्द)|"
    r"\b([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)\s+(?:ji|behenji|bhaiya|bhai|babu|sahab|saheb|didi)\b|"
    r"(?:\d{1,2}:\d{2}\s*[-–]\s*|[.!?\n]\s*)([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)\s*-\s*(?:K/C/O|H/O)\b)"
)
_TEXT_REL_RE = re.compile(
    r"(?:\b(?:S/[Oo]|D/[Oo]|W/[Oo])\s+([A-Z][a-z]{1,25}(?:\s+[A-Z][a-z]{1,25}){0,2})(?:\s*\([^)]*\))?|"
    r"\bC/[Oo]\s+([A-Z][a-z]{1,25}(?:\s+[A-Z][a-z]{1,25}){1,2})|"
    r"\bAttendant(?:\s*\([^)]*\))?\s*[:=-]\s*([^\n,;]+?)(?=\s*(?:,|;|\n|\bMob|$))|"
    r"(?:पिता\s*का\s*नाम|पति\s*का\s*नाम|माता\s*का\s*नाम|अभिभावक)\s*[:=-]\s*([\u0900-\u097F\s.]{2,40}?)(?=\s{2,}|\n|$)|"
    r"(?m)^\[[^\]]{6,30}\]\s*([^:\n<]{2,45}?):)"
)
_TEXT_VILLAGE_RE = re.compile(
    r"(?:\b(?:Gram|Village|Vill\.?)\s*[:=-]?\s*([A-Z\u0900-\u097F][^\n,;]{1,34}?)(?=\s*(?:,|;|\n|Tehsil|तहसील|Distt|जिला|-|\d|$))|"
    r"ग्राम\s*[:=-]?\s*([^\n,;]{2,34}?)(?=\s*(?:,|;|\n|तहसील|जिला|-|\d|$)))"
)
_TEXT_ADDR_VIL_RE = re.compile(r"(?m)(?:Address|पता)\s*:\s*[^\n]*?,\s*([^,\n]+?)\s*,\s*(?:Tehsil|तहसील)\b", re.I)
_TEXT_DIST_RE = re.compile(r"(?:\bDistt?\.?\s*[:=-]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)|जिला\s+([\u0900-\u097F]+))")
_TEXT_TEHSIL_RE = re.compile(r"(?:\bTehsil\s*[:=-]?\s*([A-Z][a-z]+)|तहसील\s+([\u0900-\u097F]+))", re.I)
_TEXT_PIN_RE = re.compile(r"(?<!\d)([1-8]\d{5})(?!\d)")
_TEXT_DOB_RE = re.compile(r"(?:DOB|Date\s*of\s*Birth)\s*[:=-]\s*[^\n]*?\b(19\d{2}|20[0-2]\d)\b", re.I)
_TEXT_AGE_SEX_RE = re.compile(
    r"(?:(?:Age(?:/Sex)?|आयु)\s*[:=-]\s*(\d{1,3})\s*(?:Yrs?|Years?|Y|वर्ष)?(?:\s*/\s*(M|F|Male|Female|पुरुष|महिला))?|"
    r"\b(\d{1,3})\s*(?:Yrs?|Y)\s*/\s*(M|F)\b)",
    re.I,
)
_TEXT_DIAG_RE = re.compile(r"(?:Diagnosis|निदान|K/C/O)\s*[:=-]?\s*([^\n.;]+)", re.I)
_TEXT_DOCTOR_RE = re.compile(r"\b(?:Dr|Doctor|Prof)\b\.?\s+([A-Z\u0900-\u097F][^\n,;()]{2,35})")
_FN_SUMMARY_NAME_RE = re.compile(r"(?:Discharge_Summary|Case_Sheet|Patient)_([A-Z][a-z]+_[A-Z][a-z]+)", re.I)

_HINDI_STOPWORDS = frozenset({
    "था", "थी", "थे", "हैं", "है", "नहीं", "दिन", "वर्ष", "साल", "ग्राम", "मकान", "जिला", "तहसील",
    "महिला", "पुरुष", "बुखार", "रोगी", "मरीज़", "पिता", "पति", "माता", "नाम", "पता", "मोबाइल",
    "पंजीकरण", "निदान", "तारीख", "भर्ती", "छुट्टी", "ओपीडी", "डिस्चार्ज", "सारांश", "अस्पताल", "डॉ",
    "s/o", "d/o", "w/o", "c/o", "naam", "pata", "gaon", "jila", "umar", "ling",
})


def _load_policy(policy_path: Path | None) -> dict:
    p = policy_path or (Path(__file__).resolve().parent / "config" / "policy.yaml")
    if p.is_file():
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    return {}


def _year_from_str(s: str) -> int | None:
    m = re.search(r"\b(19\d{2}|20[0-2]\d)\b", fold_digits(str(s)))
    return int(m.group(1)) if m else None


def _norm_aadhaar(s: str) -> str:
    d = re.sub(r"\D", "", fold_digits(str(s)))
    return d if (len(d) == 12 and d[0] not in "01") else ""


def _norm_abha(s: str) -> str:
    d = re.sub(r"\D", "", fold_digits(str(s)))
    return d if (len(d) == 14 and d.startswith("91")) else ""


def _parse_json_conditions(item: dict) -> list[str]:
    out: list[str] = []
    dx = item.get("diagnosis")
    if isinstance(dx, list):
        for entry in dx:
            if isinstance(entry, dict) and entry.get("display"):
                out.append(str(entry["display"]))
            elif isinstance(entry, str):
                out.append(entry)
    elif isinstance(dx, str) and dx:
        out.append(dx)
    return out


def _add_name_to_lexicon(name: str, tag: str, extra_tokens: set[str], exclusions: set[str]) -> None:
    raw = " ".join(str(name).strip().split())
    if not raw or len(raw) < 3:
        return
    raw_clean = re.sub(r"^(?:S/O|D/O|W/O|C/O)\s+", "", raw, flags=re.I)
    raw_clean = re.sub(r"\s+(?:ji|behenji|bahenji|bhaiya|bhai|babu|sahab|saheb|didi|chachu)$", "", raw_clean, flags=re.I)
    low_full = normalize_match(raw_clean)
    if not low_full or low_full in exclusions or low_full in _SAFE_CLINICAL_STOPWORDS or low_full in _HINDI_STOPWORDS:
        return
    if any(w in low_full for w in ("hospital", "clinic", "pathology", "diagnostics", "centre", "seva sadan", "medical college")):
        return
    extra_tokens.add(f"{tag}::{raw_clean}")
    if "," in raw_clean:
        comma_parts = [p.strip() for p in raw_clean.split(",", 1) if p.strip()]
        if len(comma_parts) == 2:
            extra_tokens.add(f"{tag}::{comma_parts[1]} {comma_parts[0]}")
    for tok in raw_clean.split():
        cleaned_t = tok.strip(".,;:")
        tl = normalize_match(cleaned_t)
        if len(cleaned_t) >= 3 and tl not in exclusions and tl not in _SAFE_CLINICAL_STOPWORDS and tl not in _HINDI_STOPWORDS:
            if not re.fullmatch(r"\d+", tl):
                extra_tokens.add(f"{tag}::{cleaned_t}")


def _extract_from_text_file(ing: IngestedFile) -> tuple[RecordProfile | None, set[str], set[str], set[str], set[str]]:
    """Extract structured/cue-based RecordProfile and candidate tokens from clinical text."""
    txt = fold_digits(ing.text)
    rel_l = ing.rel_path.lower()
    head = "\n".join(txt.splitlines()[:4])
    hosp = ""
    for k in ("sanjeevani", "arogya", "jeevan jyoti", "district hospital"):
        if k in head.lower() or k.replace(" ", "") in rel_l:
            hosp = k
            break

    doctors: set[str] = set()
    for dm in _TEXT_DOCTOR_RE.finditer(txt):
        doctors.add(normalize_match(dm.group(1)))

    mrns: list[str] = []
    for m in _TEXT_MRN_EXPLICIT_RE.finditer(txt):
        mrns.append(m.group(0))
    for m in _TEXT_MRN_LBL_RE.finditer(txt):
        mrns.append(m.group(1))
    for m in _TEXT_MRN_EXPLICIT_RE.finditer(ing.rel_path):
        mrns.append(m.group(0))

    phones: list[str] = []
    for m in _TEXT_PHONE_RE.finditer(txt):
        np = norm_phone(m.group(0))
        if np:
            phones.append(np)
    for m in _TEXT_PHONE_RE.finditer(ing.rel_path):
        np = norm_phone(m.group(0))
        if np:
            phones.append(np)

    aadhaar = ""
    if m_a := _TEXT_AADHAAR_RE.search(txt):
        aadhaar = _norm_aadhaar(m_a.group(0))
    abha = ""
    if m_ab := _TEXT_ABHA_RE.search(txt):
        abha = _norm_abha(m_ab.group(0))
    pan = ""
    if m_p := _TEXT_PAN_RE.search(txt):
        pan = m_p.group(0)
    email = ""
    if m_e := _TEXT_EMAIL_RE.search(txt):
        email = m_e.group(0)

    patient_names: list[str] = []
    for m in _TEXT_PATIENT_RE.finditer(txt):
        nm = (m.group(1) or m.group(2) or "").strip()
        if nm:
            patient_names.append(nm)
    for m in _TEXT_PATIENT_FALLBACK_RE.finditer(txt):
        for g in m.groups():
            if g and g.strip():
                patient_names.append(g.strip())
                break
    if not patient_names:
        if m_fn := _FN_SUMMARY_NAME_RE.search(ing.rel_path):
            patient_names.append(m_fn.group(1).replace("_", " "))

    rel_names: list[str] = []
    for m in _TEXT_REL_RE.finditer(txt):
        for g in m.groups():
            if g and g.strip():
                rel_names.append(g.strip())
                break

    villages: list[str] = []
    for m in _TEXT_VILLAGE_RE.finditer(txt):
        v = (m.group(1) or m.group(2) or "").strip()
        if v:
            villages.append(v)
    for m in _TEXT_ADDR_VIL_RE.finditer(txt):
        v = m.group(1).strip()
        if v and not any(k in v.lower() for k in ("mohalla", "ward", "house", "makan", "near ", "behind ", "मोहल्ला", "मकान", "के पास")):
            villages.append(v)

    districts: set[str] = set()
    for m in _TEXT_DIST_RE.finditer(txt):
        d = (m.group(1) or m.group(2) or "").strip()
        if d:
            districts.add(d)
    tehsils: set[str] = set()
    for m in _TEXT_TEHSIL_RE.finditer(txt):
        t = (m.group(1) or m.group(2) or "").strip()
        if t:
            tehsils.add(t)

    pin = ""
    if m_pin := _TEXT_PIN_RE.search(txt):
        pin = m_pin.group(1)

    sex = ""
    age: int | None = None
    for m_as in _TEXT_AGE_SEX_RE.finditer(txt):
        a_str = m_as.group(1) or m_as.group(3)
        s_str = m_as.group(2) or m_as.group(4) or ""
        if a_str and age is None:
            av = int(a_str)
            if 0 <= av <= 115:
                age = av
        if s_str and not sex:
            sex = s_str
    if not sex:
        if "महिला" in txt or "behenji" in txt.lower() or "w/o" in txt.lower() or "d/o" in txt.lower():
            sex = "F"
        elif "पुरुष" in txt or "sahab" in txt.lower() or "bhaiya" in txt.lower() or "s/o" in txt.lower():
            sex = "M"

    by_val: int | None = None
    by_exact = True
    if m_dob := _TEXT_DOB_RE.search(txt):
        by_val = int(m_dob.group(1))
    elif age is not None:
        by_val = 2026 - age
        by_exact = False

    conds: list[str] = []
    for m in _TEXT_DIAG_RE.finditer(txt):
        for seg in re.split(r"[;|]+", m.group(1)):
            c_clean = re.sub(r"\([^)]*\)", "", seg).strip()
            if c_clean:
                conds.append(c_clean)

    has_any_identity = bool(mrns or aadhaar or abha or pan or email or phones or patient_names)
    prof = None
    if has_any_identity:
        # Prefer global prefixed MRN if multiple MRNs present on same document
        best_mrn = ""
        extra_mrns: list[str] = []
        for mv in mrns:
            _, scope = norm_mrn(mv)
            if not best_mrn or scope == "global":
                if best_mrn:
                    extra_mrns.append(best_mrn)
                best_mrn = mv
            else:
                extra_mrns.append(mv)
        # Filter patient_names that actually came from non-relative context, pick longest clean name
        clean_pnames = [p for p in patient_names if normalize_match(p) not in doctors]
        best_name = max(clean_pnames, key=len) if clean_pnames else ""
        best_rel = rel_names[0] if rel_names else ""
        # Strip relationship word ('Bhaiya' etc.) from WhatsApp sender when matching relative name
        best_rel_clean = re.sub(r"\s+(?:bhaiya|bhai|ji|behenji|didi|uncle|aunty)$", "", best_rel, flags=re.I).strip()
        prof = RecordProfile(
            file_rel=ing.rel_path,
            loc="doc",
            hospital=hosp,
            aadhaar=aadhaar,
            abha=abha,
            pan=pan,
            email=email,
            mrn=best_mrn,
            sex=sex,
            birth_year=by_val,
            extra_strong_ids=extra_mrns,
            phone=phones[0] if phones else "",
            full_name=best_name,
            relative_name=best_rel_clean,
            village=villages[0] if villages else "",
            district=sorted(districts)[0] if districts else "",
            pin=pin,
            age=age,
            birth_year_is_exact=by_exact,
            conditions=conds,
        )

    exclusions = doctors | {normalize_match(d) for d in districts} | {normalize_match(t) for t in tehsils}
    return prof, set(patient_names), set(rel_names), set(villages), exclusions


def _extract_profiles_and_lexicon(
    ingested: list[IngestedFile],
) -> tuple[list[RecordProfile], set[str]]:
    """Pass 1: extract multi-format RecordProfiles and clean corpus lexicon for dynamic propagation."""
    profiles: list[RecordProfile] = []
    raw_persons: set[str] = set()
    raw_rels: set[str] = set()
    raw_villages: set[str] = set()
    exclusions: set[str] = set()

    for ing in ingested:
        if ing.fmt in ("csv", "tsv") and ing.csv_rows:
            hdr = ing.csv_rows[0]
            rows = ing.csv_rows[1:]
            col_vals = [[r[c] if c < len(r) else "" for r in rows[:20]] for c in range(len(hdr))]
            kinds = [_classify_column(h, col_vals[i]) for i, h in enumerate(hdr)]
            has_identity_col = any(k in ("aadhaar", "abha", "pan", "email", "mrn", "phone", "name", "first_name", "last_name") for k in kinds)

            for r_idx, row in enumerate(rows):
                kwargs: dict = {
                    "file_rel": ing.rel_path,
                    "loc": f"row:{r_idx}",
                    "extra_strong_ids": [],
                    "conditions": [],
                }
                fname, lname, pname = "", "", ""
                for c_idx, kind in enumerate(kinds):
                    val = (row[c_idx] if c_idx < len(row) else "").strip()
                    if not val:
                        continue
                    if kind == "doctor":
                        exclusions.add(normalize_match(re.sub(r"^(?:dr|doctor)\.?\s+", "", val, flags=re.I)))
                    elif kind == "district":
                        kwargs["district"] = val
                        exclusions.add(normalize_match(val))
                    elif kind == "tehsil":
                        exclusions.add(normalize_match(val))
                    elif kind == "aadhaar":
                        kwargs["aadhaar"] = _norm_aadhaar(val)
                    elif kind == "abha":
                        kwargs["abha"] = _norm_abha(val)
                    elif kind == "pan":
                        kwargs["pan"] = val.upper()
                    elif kind == "email":
                        kwargs["email"] = val.casefold()
                    elif kind == "phone":
                        np = norm_phone(val)
                        if np:
                            kwargs["phone"] = np
                    elif kind == "mrn":
                        kwargs["mrn"] = val
                    elif kind == "first_name":
                        fname = val
                        raw_persons.add(val)
                    elif kind == "last_name":
                        lname = val
                        raw_persons.add(val)
                    elif kind == "name":
                        pname = val
                        raw_persons.add(val)
                    elif kind == "relative":
                        clean_rel = re.sub(r"^(?:S/O|D/O|W/O|C/O)\s+", "", val, flags=re.I).strip()
                        kwargs["relative_name"] = clean_rel
                        raw_rels.add(clean_rel)
                    elif kind == "village":
                        kwargs["village"] = val
                        raw_villages.add(val)
                    elif kind == "pin":
                        kwargs["pin"] = re.sub(r"\D", "", fold_digits(val))[:6]
                    elif kind == "dob":
                        by = _year_from_str(val)
                        if by:
                            kwargs["birth_year"] = by
                            kwargs["birth_year_is_exact"] = True
                    elif kind == "age":
                        m_a = re.search(r"\d+", fold_digits(val))
                        if m_a:
                            kwargs["age"] = int(m_a.group(0))
                    elif kind == "age_sex":
                        m_as = re.match(r"^\s*(\d+)\s*/\s*([MF])", fold_digits(val), re.I)
                        if m_as:
                            kwargs["age"] = int(m_as.group(1))
                            kwargs["sex"] = m_as.group(2).upper()
                    elif kind == "sex":
                        kwargs["sex"] = val
                    elif kind == "other":
                        if hdr[c_idx].lower() == "sex":
                            kwargs["sex"] = val
                        elif hdr[c_idx].lower() in ("procedure", "diagnosis", "condition"):
                            kwargs["conditions"].append(val)
                        elif hdr[c_idx].lower() in ("remarks", "notes"):
                            if np := _TEXT_PHONE_RE.search(val):
                                pnorm = norm_phone(np.group(0))
                                if pnorm:
                                    kwargs["phone"] = pnorm
                full = f"{fname} {lname}".strip() if (fname or lname) else pname
                if full:
                    kwargs["full_name"] = full
                    raw_persons.add(full)
                if kwargs.get("birth_year") is None and kwargs.get("age") is not None:
                    kwargs["birth_year"] = 2026 - int(kwargs["age"])
                    kwargs["birth_year_is_exact"] = False
                if has_identity_col or kwargs.get("phone"):
                    profiles.append(RecordProfile(**kwargs))

        elif ing.fmt == "fhir" and isinstance(ing.parsed_json, dict):
            org_name = ""
            conds: list[str] = []
            patient_res = None
            for ent in ing.parsed_json.get("entry") or []:
                res = ent.get("resource") if isinstance(ent, dict) else None
                if not isinstance(res, dict):
                    continue
                rt = res.get("resourceType")
                if rt == "Organization" and res.get("name"):
                    org_name = str(res["name"])
                elif rt == "Practitioner":
                    for nm in res.get("name") or []:
                        if isinstance(nm, dict) and nm.get("text"):
                            exclusions.add(normalize_match(re.sub(r"^(?:dr|doctor)\.?\s+", "", nm["text"], flags=re.I)))
                elif rt == "Condition":
                    code_obj = res.get("code") or {}
                    if isinstance(code_obj, dict):
                        txt_c = code_obj.get("text") or ((code_obj.get("coding") or [{}])[0].get("display") if code_obj.get("coding") else "")
                        if txt_c:
                            conds.append(str(txt_c))
                elif rt == "Patient":
                    patient_res = res
                elif rt == "RelatedPerson":
                    for nm in res.get("name") or []:
                        if isinstance(nm, dict) and nm.get("text"):
                            raw_rels.add(str(nm["text"]))

            if isinstance(patient_res, dict):
                kwargs = {
                    "file_rel": ing.rel_path,
                    "loc": "doc",
                    "hospital": org_name,
                    "sex": str(patient_res.get("gender") or ""),
                    "birth_year": _year_from_str(patient_res.get("birthDate") or ""),
                    "birth_year_is_exact": True,
                    "extra_strong_ids": [],
                    "conditions": conds,
                }
                for ident in patient_res.get("identifier") or []:
                    if not isinstance(ident, dict):
                        continue
                    val = str(ident.get("value") or "").strip()
                    sys_s = str(ident.get("system") or "").lower()
                    if not val:
                        continue
                    if "aadhaar" in sys_s or "uidai" in sys_s:
                        kwargs["aadhaar"] = _norm_aadhaar(val)
                    elif "healthid" in sys_s or "abha" in sys_s:
                        kwargs["abha"] = _norm_abha(val)
                    elif not kwargs.get("mrn"):
                        kwargs["mrn"] = val
                    else:
                        kwargs["extra_strong_ids"].append(val)
                for nm in patient_res.get("name") or []:
                    if isinstance(nm, dict):
                        t = nm.get("text") or " ".join(list(nm.get("given") or []) + ([nm["family"]] if nm.get("family") else []))
                        if t:
                            kwargs["full_name"] = str(t)
                            raw_persons.add(str(t))
                for tc in patient_res.get("telecom") or []:
                    if not isinstance(tc, dict):
                        continue
                    v = str(tc.get("value") or "")
                    if tc.get("system") == "phone" and v:
                        if np := norm_phone(v):
                            kwargs["phone"] = np
                    elif tc.get("system") == "email" and v:
                        kwargs["email"] = v.casefold()
                for addr in patient_res.get("address") or []:
                    if isinstance(addr, dict):
                        if addr.get("city"):
                            kwargs["village"] = str(addr["city"])
                            raw_villages.add(str(addr["city"]))
                        if addr.get("district"):
                            kwargs["district"] = str(addr["district"])
                            exclusions.add(normalize_match(str(addr["district"])))
                        if addr.get("postalCode"):
                            kwargs["pin"] = re.sub(r"\D", "", str(addr["postalCode"]))[:6]
                for ct in patient_res.get("contact") or []:
                    if isinstance(ct, dict) and isinstance(ct.get("name"), dict) and ct["name"].get("text"):
                        rname = str(ct["name"]["text"])
                        if not kwargs.get("relative_name"):
                            kwargs["relative_name"] = rname
                        raw_rels.add(rname)
                profiles.append(RecordProfile(**kwargs))

        elif ing.fmt == "json" and isinstance(ing.parsed_json, dict):
            top = ing.parsed_json
            hosp = ""
            if isinstance(top.get("facility"), dict):
                hosp = str(top["facility"].get("name") or "")
            elif isinstance(top.get("_export_meta"), dict):
                hosp = str(top["_export_meta"].get("hospital") or "")
            elif isinstance(top.get("lab"), str):
                hosp = top["lab"]

            if isinstance(top.get("referred_by"), str):
                exclusions.add(normalize_match(re.sub(r"^(?:dr|doctor)\.?\s+", "", top["referred_by"], flags=re.I)))

            list_key = None
            for k, v in top.items():
                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                    sample = [x for x in v[:4] if isinstance(x, dict)]
                    if any(("patient_ref" in x or "uhid" in x or "mrn" in x or "visit_id" in x or "dob" in x or "patient_name" in x) for x in sample) or (
                        k.casefold() == "patients" and any("name" in x for x in sample)
                    ):
                        list_key = k
                        break

            top_mrn = ""
            top_name = ""
            top_aadhaar = ""
            meta_obj = top.get("_export_meta")
            if isinstance(meta_obj, dict):
                meta_blob = " ".join(str(mv) for mv in meta_obj.values() if isinstance(mv, str)) + " " + ing.rel_path
                if mm := _TEXT_MRN_EXPLICIT_RE.search(meta_blob):
                    top_mrn = mm.group(0)
                if ma := _TEXT_AADHAAR_RE.search(meta_blob):
                    top_aadhaar = _norm_aadhaar(ma.group(0))
                if mn := re.search(r"([A-Z][a-z]{2,}_[A-Z][a-z]{2,})(?:_[A-Z0-9-]{4,})?(?:\.[a-z0-9]+)?$", meta_blob):
                    top_name = mn.group(1).replace("_", " ")
                    raw_persons.add(top_name)

            if list_key is not None:
                pk = list_key.replace("~", "~0").replace("/", "~1")
                for idx, item in enumerate(top[list_key]):
                    if isinstance(item.get("doctor"), str):
                        exclusions.add(normalize_match(re.sub(r"^(?:dr|doctor)\.?\s+", "", item["doctor"], flags=re.I)))
                    ids_sub = item.get("ids") if isinstance(item.get("ids"), dict) else {}
                    mrn = str(item.get("uhid") or item.get("patient_ref") or item.get("mrn") or "").strip()
                    aadhaar = _norm_aadhaar(str(
                        item.get("aadhaar")
                        or item.get("aadhar_no")
                        or item.get("aadhaar_no")
                        or item.get("aadhar")
                        or ids_sub.get("aadhar_no")
                        or ids_sub.get("aadhaar_no")
                        or ids_sub.get("aadhaar")
                        or ""
                    ))
                    abha = _norm_abha(str(item.get("abha") or ids_sub.get("abha") or ""))
                    phone = ""
                    ct = item.get("contact")
                    if isinstance(ct, dict) and ct.get("mobile"):
                        phone = norm_phone(str(ct["mobile"])) or ""
                    elif item.get("phone"):
                        phone = norm_phone(str(item["phone"])) or ""
                    nm_obj = item.get("name") or item.get("patient_name")
                    fname_j = ""
                    if isinstance(nm_obj, dict):
                        parts = [str(nm_obj.get("first") or ""), str(nm_obj.get("last") or "")]
                        fname_j = " ".join(p for p in parts if p).strip()
                        if nm_obj.get("local"):
                            raw_persons.add(str(nm_obj["local"]))
                    elif isinstance(nm_obj, str):
                        fname_j = nm_obj
                    if not (mrn or aadhaar or abha or phone or fname_j):
                        mrn = top_mrn
                        aadhaar = top_aadhaar
                        fname_j = top_name
                    if fname_j:
                        raw_persons.add(fname_j)
                    rel_j = ""
                    gd = item.get("guardian")
                    if isinstance(gd, dict) and gd.get("name"):
                        rel_j = str(gd["name"])
                    elif isinstance(gd, str):
                        rel_j = re.sub(r"^(?:S/O|D/O|W/O)\s+", "", gd, flags=re.I)
                    if rel_j:
                        raw_rels.add(rel_j)
                    addr_j = item.get("address") if isinstance(item.get("address"), dict) else {}
                    vil_j = str(addr_j.get("village") or addr_j.get("city") or "")
                    if vil_j:
                        raw_villages.add(vil_j)
                    dist_j = str(addr_j.get("district") or "")
                    if dist_j:
                        exclusions.add(normalize_match(dist_j))
                    if addr_j.get("tehsil"):
                        exclusions.add(normalize_match(str(addr_j["tehsil"])))
                    pin_j = re.sub(r"\D", "", str(addr_j.get("postalCode") or addr_j.get("pin") or ""))[:6]
                    by_j = _year_from_str(str(item.get("dob") or ""))
                    age_j = int(item["age"]) if isinstance(item.get("age"), (int, float)) else None
                    if mrn or aadhaar or abha or phone or fname_j:
                        profiles.append(RecordProfile(
                            file_rel=ing.rel_path,
                            loc=f"/{pk}/{idx}",
                            hospital=hosp,
                            aadhaar=aadhaar,
                            abha=abha,
                            mrn=mrn,
                            sex=str(item.get("sex") or item.get("gender") or ""),
                            birth_year=by_j if by_j else ((2026 - age_j) if age_j is not None else None),
                            phone=phone,
                            full_name=fname_j,
                            relative_name=rel_j,
                            village=vil_j,
                            district=dist_j,
                            pin=pin_j,
                            age=age_j,
                            birth_year_is_exact=bool(by_j),
                            conditions=_parse_json_conditions(item),
                        ))
            elif isinstance(top.get("patient"), dict):
                pt = top["patient"]
                nm = str(pt.get("name") or "")
                if nm:
                    raw_persons.add(nm)
                ph = norm_phone(str(pt.get("phone") or "")) or ""
                if not ph:
                    if mp := _TEXT_PHONE_RE.search(ing.rel_path):
                        ph = norm_phone(mp.group(0)) or ""
                uh = str(pt.get("hospital_uhid") or pt.get("uhid") or pt.get("mrn") or "")
                age_p = int(pt["age"]) if isinstance(pt.get("age"), (int, float)) else None
                # Also extract attendant relative in remarks string if present
                rem = str(top.get("remarks") or "")
                rel_r = ""
                if mr := _TEXT_REL_RE.search(rem):
                    rel_r = next((g.strip() for g in mr.groups() if g and g.strip()), "")
                    if rel_r:
                        raw_rels.add(rel_r)
                if nm or ph or uh:
                    profiles.append(RecordProfile(
                        file_rel=ing.rel_path,
                        loc="doc",
                        hospital=hosp,
                        mrn=uh,
                        sex=str(pt.get("sex") or ""),
                        birth_year=(2026 - age_p) if age_p is not None else None,
                        phone=ph,
                        full_name=nm,
                        relative_name=rel_r,
                        age=age_p,
                        birth_year_is_exact=False,
                    ))
            elif isinstance(top.get("patient"), str) and top["patient"].strip():
                nm_s = top["patient"].strip()
                raw_persons.add(nm_s)
                ph_s = ""
                if mp := _TEXT_PHONE_RE.search(ing.rel_path):
                    ph_s = norm_phone(mp.group(0)) or ""
                profiles.append(RecordProfile(
                    file_rel=ing.rel_path,
                    loc="doc",
                    hospital=hosp,
                    phone=ph_s,
                    full_name=nm_s,
                ))
            # Also collect patient index dictionary keys (e.g. misc/patient_index.json 'by_name')
            if isinstance(top.get("by_name"), dict):
                for knm in top["by_name"].keys():
                    if isinstance(knm, str) and knm.strip():
                        raw_persons.add(knm.strip())

        elif ing.fmt == "text":
            prof, pns, rns, vns, exs = _extract_from_text_file(ing)
            raw_persons.update(pns)
            raw_rels.update(rns)
            raw_villages.update(vns)
            exclusions.update(exs)
            if prof is not None:
                profiles.append(prof)

    # Assemble deduplicated, safe tagged lexicon
    extra_tokens: set[str] = set()
    for p in raw_persons:
        _add_name_to_lexicon(p, "PERSON", extra_tokens, exclusions)
    for r in raw_rels:
        _add_name_to_lexicon(r, "REL", extra_tokens, exclusions)
    for v in raw_villages:
        vc = " ".join(v.strip().split())
        if len(vc) >= 3 and normalize_match(vc) not in exclusions:
            extra_tokens.add(f"VILLAGE::{vc}")

    return profiles, extra_tokens


def run_pipeline(inp_dir: Path, out_dir: Path, policy_path: Path | None = None) -> int:
    """Execute deterministic end-to-end Secret Wards sanitization pipeline."""
    install_safe_error_handlers()
    t0 = time.monotonic()

    secret = os.environ.get("RAKSHA_SECRET", "")
    if not secret:
        sys.stderr.write("ERROR: RAKSHA_SECRET is required and must be non-empty.\n")
        return 2

    policy = _load_policy(policy_path)
    secret_bytes = secret.encode("utf-8")
    keys = derive_keys(secret_bytes)
    max_file_bytes = int(policy.get("max_file_bytes", 50 * 1024 * 1024))
    max_json_depth = int(policy.get("max_json_depth", 100))
    min_shift = int(policy.get("date_shift_min_days", 30))
    max_shift = int(policy.get("date_shift_max_days", 365))

    discovered = discover_files(inp_dir, max_file_bytes=max_file_bytes)
    ingested: list[IngestedFile] = []
    quarantined: list[QuarantinedFile] = []

    for df in discovered:
        res = ingest_file(df, max_json_depth=max_json_depth)
        if isinstance(res, QuarantinedFile):
            quarantined.append(res)
        else:
            ingested.append(res)

    # Pass 1: Extract rich multi-format profiles & dynamic dataset lexicon
    profiles, extra_tokens_raw = _extract_profiles_and_lexicon(ingested)
    extra_tokens = frozenset(extra_tokens_raw)
    anchor_map, cluster_privacy = build_clusters(profiles, cfg=policy)

    used_psns: set[str] = set()
    anchor_to_psn: dict[str, str] = {}
    for anchor in sorted(set(anchor_map.values())):
        anchor_to_psn[anchor] = issue_psn(
            keys.pseudonym,
            anchor,
            used_psns,
            prefix=str(policy.get("psn_prefix", "PSN-")),
            n_chars=int(policy.get("psn_chars", 10)),
        )

    def _shift_fn(anchor: str) -> int:
        return shift_days_for_key(keys.dateshift, anchor, min_days=min_shift, max_days=max_shift)

    used_paths: set[str] = set()
    sanitized_blobs: dict[str, str] = {}
    file_entries: list[dict] = []
    all_records: list[dict] = []
    identifiers_detected = 0
    records_generalized = 0

    for q in quarantined:
        file_entries.append({
            "input_sha256": q.sha256,
            "output": None,
            "status": "quarantined",
            "reason": q.reason,
        })

    for ing in ingested:
        rel_out, _ = sanitize_rel_path(ing.rel_path, keys.filename, used_paths, extra_tokens=extra_tokens)
        out_record_path = f"sanitized/{rel_out}"

        if ing.fmt in ("csv", "tsv") and ing.csv_rows is not None:
            n_rows = len(ing.csv_rows)
            n_cols = len(ing.csv_rows[0]) if ing.csv_rows else 0
            row_psns: dict[int, str | None] = {}
            row_priv: dict[int, dict] = {}
            for r_idx in range(max(0, n_rows - 1)):
                anc = anchor_map.get((ing.rel_path, f"row:{r_idx}"))
                row_psns[r_idx] = anchor_to_psn[anc] if anc else None
                if anc and anc in cluster_privacy:
                    row_priv[r_idx] = cluster_privacy[anc]
            out_txt, recs, pii_hits, gen_hits = sanitize_csv_tsv(
                ing.csv_rows,
                ing.delimiter or ",",
                out_record_path,
                row_psns,
                _shift_fn,
                policy,
                extra_tokens=extra_tokens,
                row_privacy=row_priv,
            )
            ok, v_err = verify_sanitized_file(
                ing.fmt, ing.delimiter, n_rows, n_cols, rel_out, out_txt, secret_bytes
            )

        elif ing.fmt == "fhir" and isinstance(ing.parsed_json, dict):
            anc = anchor_map.get((ing.rel_path, "doc"))
            psn = anchor_to_psn[anc] if anc else None
            priv_opts = cluster_privacy.get(anc, {}) if anc else {}
            out_txt, recs, pii_hits, gen_hits = sanitize_fhir_bundle(
                ing.parsed_json,
                out_record_path,
                psn,
                keys.pseudonym,
                _shift_fn,
                policy,
                extra_tokens=extra_tokens,
                privacy_opts=priv_opts,
            )
            ok, v_err = verify_sanitized_file("fhir", None, None, None, rel_out, out_txt, secret_bytes)

        elif ing.fmt == "json" and ing.parsed_json is not None:
            loc_psns: dict[str, str | None] = {}
            loc_priv: dict[str, dict] = {}
            for (f_rel, loc), anc in anchor_map.items():
                if f_rel == ing.rel_path:
                    loc_psns[loc] = anchor_to_psn[anc]
                    if anc in cluster_privacy:
                        loc_priv[loc] = cluster_privacy[anc]
            out_txt, recs, pii_hits, gen_hits = sanitize_json_doc(
                ing.parsed_json,
                out_record_path,
                loc_psns,
                _shift_fn,
                policy,
                extra_tokens=extra_tokens,
                loc_privacy=loc_priv,
            )
            ok, v_err = verify_sanitized_file("json", None, None, None, rel_out, out_txt, secret_bytes)

        else:
            anc = anchor_map.get((ing.rel_path, "doc"))
            psn = anchor_to_psn[anc] if anc else None
            priv_opts = cluster_privacy.get(anc, {}) if anc else {}
            out_txt, recs, pii_hits, gen_hits = sanitize_text_doc(
                ing.text,
                out_record_path,
                psn,
                _shift_fn,
                policy,
                extra_tokens=extra_tokens,
                privacy_opts=priv_opts,
            )
            ok, v_err = verify_sanitized_file("text", None, None, None, rel_out, out_txt, secret_bytes)

        if not ok:
            file_entries.append({
                "input_sha256": ing.sha256,
                "output": None,
                "status": "quarantined",
                "reason": v_err or "verification_failed",
            })
            continue

        if ing.newline_style == "\r\n" and ing.fmt == "text":
            out_txt = out_txt.replace("\n", "\r\n")

        sanitized_blobs[rel_out] = out_txt
        all_records.extend(recs)
        identifiers_detected += pii_hits
        records_generalized += gen_hits
        file_entries.append({
            "input_sha256": ing.sha256,
            "output": out_record_path,
            "status": "sanitized",
        })

    file_entries.sort(key=lambda e: (e["input_sha256"], e.get("output") or ""))
    counts = {
        "files_total": len(file_entries),
        "files_sanitized": sum(1 for e in file_entries if e["status"] == "sanitized"),
        "files_quarantined": sum(1 for e in file_entries if e["status"] == "quarantined"),
        "records_processed": len(all_records),
        "identifiers_detected": identifiers_detected,
        "records_linked": sum(1 for r in all_records if r.get("patient") is not None),
        "records_generalized": records_generalized,
        "records_suppressed": 0,
        "records_quarantined": sum(1 for e in file_entries if e["status"] == "quarantined"),
    }

    seconds = time.monotonic() - t0
    rss_mb = peak_rss_mb()
    write_outputs(out_dir, sanitized_blobs, file_entries, all_records, counts, seconds, rss_mb)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Secret Wards offline privacy firewall (Knight Rebels)")
    ap.add_argument("--input", required=True, help="Input dataset directory")
    ap.add_argument("--output", required=True, help="Output directory for sanitized/, report.json, records.jsonl")
    ap.add_argument("--policy", default=None, help="Optional YAML privacy policy file")
    args = ap.parse_args()
    return run_pipeline(Path(args.input), Path(args.output), Path(args.policy) if args.policy else None)


if __name__ == "__main__":
    raise SystemExit(main())
