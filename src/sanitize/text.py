"""Unstructured clinical text sanitizer (discharge summaries, prescriptions, WhatsApp, nursing notes)."""
from __future__ import annotations

from typing import Callable

import regex as re

from src.detect.arbitrate import clean_text_with_arbitration
from src.privacy import band_ages_in_text, shift_all_dates_in_text

_PATIENT_SLOT_RE = re.compile(
    r"((?:Patient\s*(?:Name)?|Pt\.?\s*Name|मरीज़\s*का\s*नाम|रोगी\s*का\s*नाम|नाम|UHID|पंजीकरण\s*सं\.?)\s*[:=-]\s*)(\[PERSON\]|\[ID\])",
    re.I,
)
_PIN3_RE = re.compile(r"\b([1-8]\d{2})\*{3}\b")
_DIST_CLAUSE_RE = re.compile(
    r"(?:(\b(?:Distt?\.?|District)\s*[:=-]?\s*)[A-Z][a-zA-Z\s]{2,24}?(?=\s*(?:,|;|\n|-|\[|$))|(जिला\s+)[\u0900-\u097F]+)"
)


def sanitize_text_doc(
    text: str,
    rel_out: str,
    psn: str | None,
    shift_fn: Callable[[str], int],
    policy: dict,
    extra_tokens: set[str] | None = None,
    privacy_opts: dict | None = None,
) -> tuple[str, list[dict], int, int]:
    """Scrub PII in unstructured text while banding ages, coarsening high-risk PINs/districts, and shifting dates."""
    opts = privacy_opts or {}
    age_w = int(opts.get("age_band_width", policy.get("age_band_years", 5)))
    elderly_open = int(opts.get("elderly_open_band", policy.get("elderly_open_band", 85)))
    pin_dig = int(opts.get("pin_prefix_digits", policy.get("pin_prefix_digits", 3)))
    suppress_dist = bool(opts.get("suppress_district", False))

    sdays = shift_fn(psn or f"{rel_out}:doc")
    cleaned, pii_hits = clean_text_with_arbitration(text, extra_tokens=extra_tokens)
    cleaned, age_hits = band_ages_in_text(cleaned, width=age_w, elderly_open=elderly_open)
    cleaned, date_hits = shift_all_dates_in_text(cleaned, sdays)

    if pin_dig == 0:
        cleaned = _PIN3_RE.sub("[PIN]", cleaned)
    elif pin_dig <= 2:
        cleaned = _PIN3_RE.sub(lambda m: f"{m.group(1)[:pin_dig]}{'*' * (6 - pin_dig)}", cleaned)

    if suppress_dist:
        cleaned = _DIST_CLAUSE_RE.sub(lambda m: f"{m.group(1) or m.group(2)}[REGION]", cleaned)

    psn_written = False
    if psn:
        if _PATIENT_SLOT_RE.search(cleaned):
            cleaned = _PATIENT_SLOT_RE.sub(rf"\g<1>{psn}", cleaned, count=1)
            psn_written = True
        elif "[PERSON]" in cleaned:
            cleaned = cleaned.replace("[PERSON]", psn, 1)
            psn_written = True
        elif "[ID]" in cleaned:
            cleaned = cleaned.replace("[ID]", psn, 1)
            psn_written = True

    records = [{"file": rel_out, "loc": "doc", "patient": psn if (psn and psn_written) else None}]
    return cleaned, records, pii_hits, age_hits + date_hits
