"""Format-preserving CSV/TSV sanitizer with header guard, accurate column classification, and linkage consistency."""
from __future__ import annotations

import csv
import io
from typing import Callable

import regex as re

from src.detect.arbitrate import clean_text_with_arbitration
from src.privacy import band_age, dob_to_year, generalize_pin, shift_date_token
from src.surfaces import decode_and_sanitize_base64, sanitize_header
from src.textnorm import fold_digits


def _classify_column(hdr: str, values: list[str]) -> str:
    """Classify English/Hinglish/CamelCase CSV/TSV column safely without substring collisions."""
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", (hdr or "").strip())
    h = re.sub(r"[\s_-]+", " ", camel_split.casefold()).strip()
    if not h:
        return "other"
    if re.search(r"\b(?:aadhaar|aadhar|uidai)\b", h):
        return "aadhaar"
    if re.search(r"\babha addr", h):
        return "email"
    if re.search(r"\b(?:abha|health id)\b", h):
        return "abha"
    if re.search(r"\b(?:payer )?pan\b", h):
        return "pan"
    if re.search(r"\b(?:pmjay|policy|insurance|rsby|esic)\b", h):
        return "insurance"
    if re.search(r"\b(?:email|e mail|mail)\b", h):
        return "email"
    if re.search(r"\b(?:phone|mobile|mob|telephone|tel|contact no|sampark)\b", h):
        return "phone"
    if re.search(r"\b(?:uhid|mrn|patient id|pat id|patient ref|hospital uhid|ipd|opd|reg no|reg id|registration no)\b", h):
        return "mrn"
    if re.search(r"\b(?:bill no|claim no|invoice)\b", h):
        return "id"
    if re.search(r"\b(?:sambandh|relation)\b", h):
        return "other"
    if re.search(r"\b(?:pita|abhibhavak|guardian|relative|attendant|father|husband|mother|spouse|kin)\b", h):
        return "relative"
    if re.search(r"\b(?:ref doctor|doctor|consultant|physician|clinician)\b", h):
        return "doctor"
    if re.search(r"\b(?:first name|fname|given name)\b", h):
        return "first_name"
    if re.search(r"\b(?:last name|lname|surname|family name)\b", h):
        return "last_name"
    if re.search(r"\b(?:patient name|rogi naam|full name|pt name|naam|name)\b", h):
        return "name"
    if re.search(r"\b(?:dob|birth date|date of birth|birthdate|janm tithi|janm dinank)\b", h):
        return "dob"
    if re.search(r"\b(?:age sex|age/sex)\b", h):
        return "age_sex"
    if re.search(r"\b(?:age|umar)\b", h):
        return "age"
    if re.search(r"\b(?:sex|gender|ling)\b", h):
        return "sex"
    if re.search(r"\b(?:street|address|pata|house|h no|makan)\b", h):
        return "address"
    if re.search(r"\b(?:mohalla|locality|ward)\b", h):
        return "locality"
    if re.search(r"\b(?:landmark)\b", h):
        return "landmark"
    if re.search(r"\b(?:village|city|gram|gaon|town)\b", h):
        return "village"
    if re.search(r"\b(?:tehsil|taluka|subdistrict)\b", h):
        return "tehsil"
    if re.search(r"\b(?:district|distt|jila|zila)\b", h):
        return "district"
    if re.search(r"\b(?:pin|zip|pincode|pin code|postal code)\b", h):
        return "pin"
    if re.search(r"\b(?:date|registered|registration date|reg date|admission|discharge|collected|reported|visited)\b", h):
        return "date"
    if re.search(r"\b(?:remarks|notes|summary|comment|history)\b", h):
        return "notes"
    if re.search(r"\b(?:result|value|amount|inr|beds|occupied|cases)\b", h):
        return "clinical_num"
    del values
    return "other"


def sanitize_csv_tsv(
    rows: list[list[str]],
    delimiter: str,
    rel_out: str,
    row_psns: dict[int, str | None],
    shift_fn: Callable[[str], int],
    policy: dict,
    extra_tokens: set[str] | None = None,
    row_privacy: dict[int, dict] | None = None,
) -> tuple[str, list[dict], int, int]:
    """Sanitize CSV/TSV matrix preserving exact dimensions and delimiter."""
    if not rows:
        return "", [], 0, 0

    raw_header = rows[0]
    data_rows = rows[1:]
    col_vals = [[r[c] if c < len(r) else "" for r in data_rows[:20]] for c in range(len(raw_header))]
    col_kinds = [_classify_column(h, col_vals[i]) for i, h in enumerate(raw_header)]

    clean_hdr, hdr_hits = sanitize_header(
        raw_header,
        lambda s: clean_text_with_arbitration(s, extra_tokens=extra_tokens),
        extra_tokens=extra_tokens,
    )
    out_rows: list[list[str]] = [clean_hdr]
    records: list[dict] = []
    pii_hits = hdr_hits
    gen_hits = 0

    default_age_w = int(policy.get("age_band_years", 5))
    elderly_open = int(policy.get("elderly_open_band", 85))
    default_pin_dig = int(policy.get("pin_prefix_digits", 3))

    has_patient_id_col = any(k == "mrn" for k in col_kinds)
    has_name_col = any(k in ("name", "first_name", "last_name") for k in col_kinds)

    for r_idx, row in enumerate(data_rows):
        psn = row_psns.get(r_idx)
        rp = (row_privacy or {}).get(r_idx, {})
        age_w = int(rp.get("age_band_width", default_age_w))
        pin_dig = int(rp.get("pin_prefix_digits", default_pin_dig))
        dob_w = int(rp.get("coarsen_dob_width", 5))
        suppress_dist = bool(rp.get("suppress_district", False))

        # Determine date order hint across this row / header
        order_hint = "mdy" if any("mm/dd" in raw_header[c].lower() for c in range(len(raw_header))) else "dmy"
        shift_anchor = psn or f"{rel_out}:row:{r_idx}"
        sdays = shift_fn(shift_anchor)

        # Decide which single primary column carries PSN-* cleanly without repeating across all columns
        psn_target_col = -1
        if psn:
            for idx_c, kind in enumerate(col_kinds):
                if kind == "mrn" and idx_c < len(row) and row[idx_c].strip():
                    psn_target_col = idx_c
                    break
            if psn_target_col == -1:
                for idx_c, kind in enumerate(col_kinds):
                    if kind in ("name", "first_name", "last_name") and idx_c < len(row) and row[idx_c].strip():
                        psn_target_col = idx_c
                        break

        psn_written = False
        new_row: list[str] = []
        for c_idx in range(len(raw_header)):
            val = row[c_idx] if c_idx < len(row) else ""
            kind = col_kinds[c_idx]
            if not val.strip():
                new_row.append(val)
                continue

            if c_idx == psn_target_col and psn:
                new_row.append(psn)
                psn_written = True
                pii_hits += 1
                continue

            if kind in ("name", "first_name", "last_name"):
                new_row.append("[PERSON]")
                pii_hits += 1
            elif kind == "relative":
                new_row.append("[RELATIVE]")
                pii_hits += 1
            elif kind in ("aadhaar", "abha", "mrn", "id"):
                new_row.append("[ID]")
                pii_hits += 1
            elif kind == "pan":
                new_row.append("[PAN]")
                pii_hits += 1
            elif kind == "insurance":
                new_row.append("[INSURANCE_ID]")
                pii_hits += 1
            elif kind == "phone":
                new_row.append("[PHONE]")
                pii_hits += 1
            elif kind == "email":
                new_row.append("[EMAIL]")
                pii_hits += 1
            elif kind == "dob":
                new_row.append(dob_to_year(val, cohort_width=dob_w))
                gen_hits += 1
            elif kind == "age":
                m_a = re.search(r"\d+", fold_digits(val))
                if m_a:
                    new_row.append(band_age(int(m_a.group(0)), width=age_w, elderly_open=elderly_open))
                    gen_hits += 1
                else:
                    new_row.append(val)
            elif kind == "age_sex":
                m_as = re.match(r"^\s*(\d+)\s*(.*)$", fold_digits(val))
                if m_as:
                    b = band_age(int(m_as.group(1)), width=age_w, elderly_open=elderly_open)
                    new_row.append(f"{b}{m_as.group(2)}")
                    gen_hits += 1
                else:
                    new_row.append(val)
            elif kind == "address":
                new_row.append("[ADDRESS]")
                pii_hits += 1
            elif kind == "locality":
                new_row.append("[LOCALITY]")
                pii_hits += 1
            elif kind == "landmark":
                new_row.append("[LANDMARK]")
                pii_hits += 1
            elif kind == "village":
                new_row.append("[VILLAGE]")
                pii_hits += 1
            elif kind == "tehsil":
                new_row.append("[TEHSIL]")
                gen_hits += 1
            elif kind == "district":
                new_row.append("[REGION]" if suppress_dist else val)
                if suppress_dist:
                    gen_hits += 1
            elif kind == "pin":
                new_row.append(generalize_pin(val, prefix_digits=pin_dig))
                gen_hits += 1
            elif kind == "date":
                new_row.append(shift_date_token(val, sdays, order_hint=order_hint))
                gen_hits += 1
            elif kind in ("doctor", "sex", "clinical_num"):
                new_row.append(val)
            else:
                dec_b64, is_b64, b_hits = decode_and_sanitize_base64(
                    val, lambda t: clean_text_with_arbitration(t, extra_tokens=extra_tokens)
                )
                if is_b64 and b_hits > 0:
                    new_row.append(dec_b64)
                    pii_hits += b_hits
                else:
                    cleaned, c_hits = clean_text_with_arbitration(val, extra_tokens=extra_tokens)
                    if c_hits > 0:
                        pii_hits += c_hits
                    new_row.append(cleaned)
        out_rows.append(new_row)
        # Guarantee records.jsonl consistency: claim patient ONLY when psn appears in exported row
        claimed = psn if (psn and psn_written and (has_patient_id_col or has_name_col)) else None
        records.append({"file": rel_out, "loc": f"row:{r_idx}", "patient": claimed})

    buf = io.StringIO(newline="")
    writer = csv.writer(buf, delimiter=delimiter, lineterminator="\n")
    writer.writerows(out_rows)
    return buf.getvalue(), records, pii_hits, gen_hits
