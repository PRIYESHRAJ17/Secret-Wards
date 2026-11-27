"""Schema-preserving JSON tree sanitizer across nested registration, OPD, and diagnostic reports."""
from __future__ import annotations

import json
from typing import Callable

import regex as re

from src.detect.arbitrate import clean_text_with_arbitration
from src.privacy import (
    band_age,
    band_ages_in_text,
    dob_to_year,
    generalize_pin,
    shift_all_dates_in_text,
    shift_date_token,
    shift_iso_str,
)
from src.surfaces import decode_and_sanitize_base64, sanitize_header, sanitize_metadata_str
from src.textnorm import fold_digits

_NON_PERSON_PARENTS = frozenset({
    "facility", "hospital", "lab", "laboratory", "panels", "panel",
    "test", "tests", "department", "organization", "org", "doctor", "practitioner",
    "referred_by", "author", "prescriber", "clinician", "device", "system", "wards",
})
_REL_PARENTS = frozenset({"guardian", "relative", "attendant", "contact", "next_of_kin", "kin"})
_PATIENT_PARENTS = frozenset({"patient", "person", "subject", "member", "name", ""})

_AADHAAR_KEY_RE = re.compile(r"^(?:aadhaar|aadhar|aadhar_no|aadhaar_no|aadhaar_number|aadhar_number|uid|abha|abha_no|abha_number|abha_address)$", re.I)
_MRN_KEY_RE = re.compile(r"^(?:uhid|mrn|patient_ref|hospital_uhid|ipd|ipd_no|patient_id)$", re.I)
_ID_KEY_RE = re.compile(r"^(?:pan|payer_pan|pmjay_id|policy_no|insurance_id)$", re.I)
_PHONE_KEY_RE = re.compile(r"^(?:phone|mobile|mob|tel|contact_no|emergency_phone)$", re.I)
_EMAIL_KEY_RE = re.compile(r"^(?:email|e_mail|mail)$", re.I)
_REL_KEY_RE = re.compile(r"^(?:guardian|relative|attendant|father_name|husband_name|mother_name)$", re.I)
_NAME_KEY_RE = re.compile(r"^(?:name|full_name|patient|patient_name|first|first_name|last|last_name|local|surname)$", re.I)
_DOB_KEY_RE = re.compile(r"^(?:dob|birth_date|birthdate|date_of_birth)$", re.I)
_AGE_KEY_RE = re.compile(r"^(?:age|age_yrs|patient_age)$", re.I)
_ADDR_KEY_RE = re.compile(r"^(?:line|street|address_line|house|house_no|makan|landmark)$", re.I)
_LOC_KEY_RE = re.compile(r"^(?:mohalla|locality)$", re.I)
_VILLAGE_KEY_RE = re.compile(r"^(?:village|city|gram|town)$", re.I)
_TEHSIL_KEY_RE = re.compile(r"^(?:tehsil|taluka|sub_district)$", re.I)
_DISTRICT_KEY_RE = re.compile(r"^(?:district|distt)$", re.I)
_PIN_KEY_RE = re.compile(r"^(?:pin|pincode|postal_code|postalcode|zip)$", re.I)
_DATE_KEY_RE = re.compile(r"^(?:visit_date|collected|reported|admission_date|discharge_date|date|registered_on)$", re.I)
_META_KEY_RE = re.compile(r"^(?:source_path|file_path|exported_file|raw_path)$", re.I)
_PROTECTED_VAL_KEYS = frozenset({"referred_by", "doctor", "consultant", "hospital", "lab", "facility", "department", "test", "loinc", "unit", "range", "system", "exported_by"})


def _clean_json_node(
    node,
    parent_key: str,
    psn: str | None,
    sdays: int,
    policy: dict,
    counts: list[int],
    extra_tokens: set[str] | None,
    state: dict | None = None,
    priv_opts: dict | None = None,
):
    """Recursively sanitize a JSON node preserving key paths and handling parent context."""
    if state is None:
        state = {"psn_placed": False}
    opts = priv_opts or {}
    age_w = int(opts.get("age_band_width", policy.get("age_band_years", 5)))
    elderly_open = int(opts.get("elderly_open_band", policy.get("elderly_open_band", 85)))
    pin_dig = int(opts.get("pin_prefix_digits", policy.get("pin_prefix_digits", 3)))
    dob_w = int(opts.get("coarsen_dob_width", 5))
    suppress_dist = bool(opts.get("suppress_district", False))

    if isinstance(node, list):
        out_list = []
        for item in node:
            if isinstance(item, (dict, list)):
                out_list.append(_clean_json_node(item, parent_key, psn, sdays, policy, counts, extra_tokens, state, opts))
            elif isinstance(item, str) and item.strip():
                if parent_key.casefold() in ("line", "address", "street") and parent_key.casefold() not in _NON_PERSON_PARENTS:
                    out_list.append("[ADDRESS]")
                    counts[0] += 1
                else:
                    dec, is_b64, bh = decode_and_sanitize_base64(
                        item, lambda t: clean_text_with_arbitration(t, extra_tokens=extra_tokens)
                    )
                    if is_b64 and bh > 0:
                        out_list.append(dec)
                        counts[0] += bh
                    else:
                        cl, ch = clean_text_with_arbitration(item, extra_tokens=extra_tokens)
                        counts[0] += ch
                        out_list.append(cl)
            else:
                out_list.append(item)
        return out_list

    if not isinstance(node, dict):
        if isinstance(node, str) and node.strip():
            kl_single = parent_key.casefold()
            if _DATE_KEY_RE.match(kl_single):
                sv = shift_iso_str(node, sdays)
                if sv == node:
                    sv = shift_date_token(node, sdays)
                counts[1] += 1
                return sv
            dec, is_b64, bh = decode_and_sanitize_base64(
                node, lambda t: clean_text_with_arbitration(t, extra_tokens=extra_tokens)
            )
            if is_b64 and bh > 0:
                counts[0] += bh
                return dec
            cl, ch = clean_text_with_arbitration(node, extra_tokens=extra_tokens)
            counts[0] += ch
            cl, ah = band_ages_in_text(cl, width=age_w, elderly_open=elderly_open)
            cl, dh = shift_all_dates_in_text(cl, sdays)
            counts[1] += ah + dh
            return cl
        return node

    out: dict = {}
    pk_low = parent_key.casefold()
    in_non_person = pk_low in _NON_PERSON_PARENTS
    in_rel = pk_low in _REL_PARENTS

    # Sanitize keys first so JSON keys containing PII become safe key_i
    orig_keys = list(node.keys())
    clean_keys, khits = sanitize_header(
        orig_keys,
        lambda s: clean_text_with_arbitration(s, extra_tokens=extra_tokens),
        extra_tokens=extra_tokens,
    )
    counts[0] += khits

    for orig_k, clean_k in zip(orig_keys, clean_keys):
        v = node[orig_k]
        kl = orig_k.casefold()

        if isinstance(v, dict):
            out[clean_k] = _clean_json_node(v, orig_k, psn, sdays, policy, counts, extra_tokens, state, opts)
            continue
        if isinstance(v, list):
            out[clean_k] = _clean_json_node(v, orig_k, psn, sdays, policy, counts, extra_tokens, state, opts)
            continue

        # Handle integers / floats carefully (Aadhaar / Phone / PIN / Age!)
        if isinstance(v, bool):
            out[clean_k] = v
            continue
        if isinstance(v, (int, float)):
            if _AGE_KEY_RE.match(kl) and not in_non_person:
                out[clean_k] = band_age(int(v), width=age_w, elderly_open=elderly_open)
                counts[1] += 1
            elif _AADHAAR_KEY_RE.match(kl) or _MRN_KEY_RE.match(kl) or _ID_KEY_RE.match(kl) or _PHONE_KEY_RE.match(kl) or (isinstance(v, int) and 200000000000 <= v <= 999999999999):
                out[clean_k] = None
                counts[0] += 1
            elif _PIN_KEY_RE.match(kl):
                out[clean_k] = generalize_pin(str(int(v)), prefix_digits=pin_dig)
                counts[1] += 1
            else:
                out[clean_k] = v
            continue

        if not isinstance(v, str):
            out[clean_k] = v
            continue

        if not v.strip():
            out[clean_k] = v
            continue

        if kl in _PROTECTED_VAL_KEYS or in_non_person:
            if _META_KEY_RE.match(kl):
                sm, mh = sanitize_metadata_str(v, lambda t: clean_text_with_arbitration(t, extra_tokens=extra_tokens))
                out[clean_k] = sm
                counts[0] += mh
            else:
                # Still check base64 or embedded phone/Aadhaar inside facility/doctor objects
                out[clean_k] = v
            continue

        if _MRN_KEY_RE.match(kl):
            if psn and not state["psn_placed"]:
                out[clean_k] = psn
                state["psn_placed"] = True
            elif psn:
                out[clean_k] = psn
                state["psn_placed"] = True
            else:
                out[clean_k] = "[ID]"
            counts[0] += 1
        elif _AADHAAR_KEY_RE.match(kl) or _ID_KEY_RE.match(kl):
            out[clean_k] = "[PAN]" if "pan" in kl else ("[INSURANCE_ID]" if ("pmjay" in kl or "policy" in kl) else "[ID]")
            counts[0] += 1
        elif _PHONE_KEY_RE.match(kl):
            out[clean_k] = "[PHONE]"
            counts[0] += 1
        elif _EMAIL_KEY_RE.match(kl):
            out[clean_k] = "[EMAIL]"
            counts[0] += 1
        elif _REL_KEY_RE.match(kl) or (in_rel and _NAME_KEY_RE.match(kl)):
            out[clean_k] = "[RELATIVE]"
            counts[0] += 1
        elif _NAME_KEY_RE.match(kl):
            if in_rel:
                out[clean_k] = "[RELATIVE]"
            elif kl in ("last", "last_name", "local", "surname"):
                out[clean_k] = "[PERSON]"
            elif psn and not state["psn_placed"]:
                out[clean_k] = psn
                state["psn_placed"] = True
            else:
                out[clean_k] = "[PERSON]"
            counts[0] += 1
        elif _DOB_KEY_RE.match(kl):
            out[clean_k] = dob_to_year(v, cohort_width=dob_w)
            counts[1] += 1
        elif _AGE_KEY_RE.match(kl):
            m_a = re.search(r"\d+", fold_digits(v))
            if m_a:
                out[clean_k] = band_age(int(m_a.group(0)), width=age_w, elderly_open=elderly_open)
                counts[1] += 1
            else:
                out[clean_k] = v
        elif _ADDR_KEY_RE.match(kl):
            out[clean_k] = "[ADDRESS]"
            counts[0] += 1
        elif _LOC_KEY_RE.match(kl):
            out[clean_k] = "[LOCALITY]"
            counts[0] += 1
        elif _VILLAGE_KEY_RE.match(kl):
            out[clean_k] = "[VILLAGE]"
            counts[0] += 1
        elif _TEHSIL_KEY_RE.match(kl):
            out[clean_k] = "[TEHSIL]"
            counts[1] += 1
        elif _DISTRICT_KEY_RE.match(kl):
            out[clean_k] = "[REGION]" if suppress_dist else v
            if suppress_dist:
                counts[1] += 1
        elif _PIN_KEY_RE.match(kl):
            out[clean_k] = generalize_pin(v, prefix_digits=pin_dig)
            counts[1] += 1
        elif _DATE_KEY_RE.match(kl):
            sv = shift_iso_str(v, sdays)
            if sv == v:
                sv = shift_date_token(v, sdays)
            out[clean_k] = sv
            counts[1] += 1
        elif _META_KEY_RE.match(kl):
            sm, mh = sanitize_metadata_str(v, lambda t: clean_text_with_arbitration(t, extra_tokens=extra_tokens))
            out[clean_k] = sm
            counts[0] += mh
        else:
            # Generic string: force Ward \d+ scrubbing inside address_note/address context first
            work_v = v
            if "address" in kl or "attendant" in kl or "guardian" in kl:
                work_v = re.sub(r"\bWard\s*(?:No\.?)?\s*\d+[A-Za-z]?\b", "[LOCALITY]", work_v, flags=re.I)
            dec, is_b64, bh = decode_and_sanitize_base64(
                work_v, lambda t: clean_text_with_arbitration(t, extra_tokens=extra_tokens)
            )
            if is_b64 and bh > 0:
                out[clean_k] = dec
                counts[0] += bh
            else:
                cleaned, ch = clean_text_with_arbitration(work_v, extra_tokens=extra_tokens)
                counts[0] += ch
                cleaned, ah = band_ages_in_text(cleaned, width=age_w, elderly_open=elderly_open)
                cleaned, dh = shift_all_dates_in_text(cleaned, sdays)
                counts[1] += ah + dh
                out[clean_k] = cleaned

    return out


def sanitize_json_doc(
    obj: object,
    rel_out: str,
    loc_psns: dict[str, str | None],
    shift_fn: Callable[[str], int],
    policy: dict,
    extra_tokens: set[str] | None = None,
    loc_privacy: dict[str, dict] | None = None,
) -> tuple[str, list[dict], int, int]:
    """Sanitize a generic JSON document (patient lists, OPD visits, or single diagnostic reports)."""
    counts = [0, 0]
    records: list[dict] = []

    if isinstance(obj, dict):
        list_key = None
        for k, v in obj.items():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                sample = [x for x in v[:4] if isinstance(x, dict)]
                if any(("patient_ref" in x or "uhid" in x or "mrn" in x or "visit_id" in x or "dob" in x or "patient_name" in x) for x in sample) or (
                    k.casefold() == "patients" and any("name" in x for x in sample)
                ):
                    list_key = k
                    break
        if list_key is not None:
            out_top: dict = {}
            orig_keys = list(obj.keys())
            clean_keys, khits = sanitize_header(
                orig_keys,
                lambda s: clean_text_with_arbitration(s, extra_tokens=extra_tokens),
                extra_tokens=extra_tokens,
            )
            counts[0] += khits
            for orig_k, clean_k in zip(orig_keys, clean_keys):
                if orig_k == list_key:
                    new_items = []
                    pk = orig_k.replace("~", "~0").replace("/", "~1")
                    for idx, item in enumerate(obj[orig_k]):
                        loc = f"/{pk}/{idx}"
                        psn = loc_psns.get(loc)
                        opts = (loc_privacy or {}).get(loc, {})
                        sdays = shift_fn(psn or f"{rel_out}:{loc}")
                        st = {"psn_placed": False}
                        cleaned_item = _clean_json_node(item, orig_k, psn, sdays, policy, counts, extra_tokens, st, opts)
                        new_items.append(cleaned_item)
                        records.append({"file": rel_out, "loc": loc, "patient": psn if (psn and st["psn_placed"]) else None})
                    out_top[clean_k] = new_items
                else:
                    # Use document-level shift for top-level non-list fields when single-record or export meta
                    top_psn = loc_psns.get("doc")
                    top_shift = shift_fn(top_psn or f"{rel_out}:top") if orig_k != "_export_meta" else 0
                    out_top[clean_k] = _clean_json_node(
                        obj[orig_k], orig_k, top_psn, top_shift, policy, counts, extra_tokens, {"psn_placed": False}, {}
                    )
            return json.dumps(out_top, ensure_ascii=False, indent=2) + "\n", records, counts[0], counts[1]

    # Single-record JSON document (e.g. lab diagnostic report)
    psn = loc_psns.get("doc")
    opts = (loc_privacy or {}).get("doc", {})
    sdays = shift_fn(psn or f"{rel_out}:doc")
    st = {"psn_placed": False}
    cleaned_doc = _clean_json_node(obj, "", psn, sdays, policy, counts, extra_tokens, st, opts)
    records.append({"file": rel_out, "loc": "doc", "patient": psn if (psn and st["psn_placed"]) else None})
    return json.dumps(cleaned_doc, ensure_ascii=False, indent=2) + "\n", records, counts[0], counts[1]
