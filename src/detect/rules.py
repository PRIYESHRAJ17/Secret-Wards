"""Multilingual PII regex & cue detector for English, Devanagari Hindi, and Hinglish."""
from __future__ import annotations

from dataclasses import dataclass

import regex as re


@dataclass
class CandidateSpan:
    start: int
    end: int
    kind: str
    confidence: float
    family: str  # ID | CONTACT | PERSON | RELATIVE | LOCATION | DATE | CLINICAL-KEEP
    replacement: str = "[REDACTED]"


# Direct identifiers (Latin + Indic-folded digits)
_AADHAAR_RE = re.compile(r"(?<!\d)(?:[2-9]\d{3}[\s-]\d{4}[\s-]\d{4}|[2-9]\d{11})(?!\d)")
_AADHAAR_MASKED_RE = re.compile(r"\b[xX*]{4}[\s-]?[xX*]{4}[\s-]?\d{4}\b")
_ABHA_NUM_RE = re.compile(r"(?<!\d)91[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)")
_ABHA_ADDR_RE = re.compile(r"\b[A-Za-z0-9._-]+@(?:abdm|sbx|ndhm)\b", re.I)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_INSURANCE_RE = re.compile(r"\b(?:PMJAY-[A-Z]{2}-\d{6,}|POL/\d{2,}/\d+|RSBY[-/]\d+|ESIC[-/]\d+)\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
_MASKED_PHONE_RE = re.compile(r"\b[6-9]\d[xX*]{4,}\d{2,4}\b")
_MRN_EXPLICIT_RE = re.compile(
    r"\b(?:[A-Z]{2,5}[-/]\d{2,4}[-/]\d{4,}|[A-Z]{2,5}/(?:LOCAL|IPD|OPD)/\d{3,}|(?:UHID|JJH|DHH\d{2,4})-\d{5,}|ADM\d{5,})\b"
)
_MRN_LABELED_RE = re.compile(
    r"(?:UHID|IPD(?:\s*No\.?)?|OPD(?:\s*No\.?)?|MRN|Adm(?:ission)?\.?\s*No\.?|Patient\s*ID|Reg(?:istration)?\.?\s*No\.?|पंजीकरण\s*सं\.?|आईपीडी\s*सं\.?)\s*[:=-]\s*([A-Za-z0-9][A-Za-z0-9/-]{3,24})(?=\s|$|,|;)",
    re.I,
)

# Names (English, Hindi Devanagari, Hinglish)
_PATIENT_CUE_EN_RE = re.compile(
    r"(?m)(?:^|\s)(?:Patient\s*(?:Name)?|Pt\.?\s*Name)\s*[:=-]\s*([^\n\t]+?)(?=\s{2,}|\s+(?:Age(?:/Sex)?|Sex|DOB|Mob(?:ile)?|Phone|UHID|IPD|MRN|Reg)|$)",
    re.I,
)
_BARE_NAME_LINE_RE = re.compile(
    r"(?m)^Name\s*[:=-]\s*([A-Z\u0900-\u097F][^\n\t,;]{1,45}?)(?=\s{2,}|\s+(?:Age|Sex|DOB|Mob)|$)"
)
_RELATIVE_CUE_EN_RE = re.compile(
    r"(?:\b(?:Attendant(?:\s*\([^)]*\))?|Guardian|Next\s+of\s+Kin|Father(?:'s)?\s+Name|Husband(?:'s)?\s+Name)\s*[:=-]\s*([^\n,;]+?)(?=\s*(?:,|;|\n|\bMob|\bPhone|\bWard|$))|\b(?:S/[Oo]|D/[Oo]|W/[Oo])\s+([A-Z][a-z]{1,25}(?:\s+[A-Z][a-z]{1,25}){0,2})(?:\s*\([^)]*\))?|\bC/[Oo]\s+([A-Z][a-z]{1,25}(?:\s+[A-Z][a-z]{1,25}){1,2}))"
)
_POSSESSIVE_NAME_RE = re.compile(
    r"\b([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20})?)'s\s+(?:attendant|wife|husband|son|daughter|father|mother|relative|spouse|brother|sister|family)\b"
)
_SUBJECT_BEFORE_KIN_RE = re.compile(
    r"(?m)(?:^|[.!?\n]\s*)([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20})?),\s*(?:S/[Oo]|D/[Oo]|W/[Oo]|C/[Oo]|age\s*\d|\d{1,3}\s*(?:yrs?|y\b)|\d{1,3}/[MF])"
)
_CLINICAL_NOTE_CUE_RE = re.compile(
    r"(?:\b(?:Report\s+of|Referral\s*:|Called\s+by|received\s+from|witnessed\s+by|signed\s+by|collected\s+by|accompanied\s+by|brought\s+by)\s*)([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20}){0,2})(?=\s*(?:\(|,|'s|\bji\b|\bbhaiya\b|\bbhai\b|\bsahab\b|\bbehenji\b|\d|\.|$))",
    re.I,
)
_PAREN_ROLE_NAME_RE = re.compile(
    r"\b([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20}){0,2})\s*\([^)\n]{0,40}\b(?:attendant|relative|visitor|family|father|mother|wife|husband|son|daughter|spouse|kin)\b[^)\n]*\)",
    re.I,
)
_PREFIX_TITLE_EN_RE = re.compile(
    r"\b(?:Mr\.|Mrs\.|Ms\.|Smt\.|Shri|Sri|Mohd\.|Md\.)\s+[A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20}){0,2}\b"
)
_NAME_BEFORE_KCO_RE = re.compile(
    r"(?:\d{1,2}:\d{2}\s*[-–]\s*|[.!?\n]\s*)([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20}){0,2})\s*-\s*(?:K/C/O|H/O|C/O)\b"
)
_HINGLISH_HONORIFIC_RE = re.compile(
    r"\b([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20}){0,2})\s+(?:ji|behenji|bahenji|bahanji|bhaiya|bhai|babu|sahab|saheb|chacha|chachu|didi)\b"
)
_WHATSAPP_SENDER_RE = re.compile(
    r"(?m)^\[[^\]]{6,30}\]\s*([^:\n<]{2,45}?):"
)

# Hindi Devanagari Names & Relatives
_HI_PATIENT_RE = re.compile(
    r"(?:मरीज़\s*का\s*नाम|रोगी\s*का\s*नाम|नाम)\s*[:=-]\s*([\u0900-\u097F][\u0900-\u097F\s.]{1,40}?)(?=\s{2,}|\s+(?:आयु|उम्र|लिंग|पता|ग्राम|पंजीकरण)|$|\n)"
)
_HI_RELATIVE_RE = re.compile(
    r"(?:पिता\s*का\s*नाम|पति\s*का\s*नाम|माता\s*का\s*नाम|अभिभावक|परिजन|अटेंडेंट)\s*[:=-]\s*([\u0900-\u097F][\u0900-\u097F\s.]{1,40}?)(?=\s{2,}|\s+(?:आयु|उम्र|पता|मोबाइल)|$|\n)"
)
_HI_KIN_TITLE_RE = re.compile(
    r"(?:(?:श्री|श्रीमती|सुश्री)\s+[\u0900-\u097F]{2,}(?:\s+[\u0900-\u097F]{2,}){0,2}|(?:पुत्र|पुत्री|पत्नी|पति)\s+(?:श्री|श्रीमती\s+)?[\u0900-\u097F]{2,}(?:\s+[\u0900-\u097F]{2,}){0,2}|[\u0900-\u097F]{2,}(?:\s+[\u0900-\u097F]{2,}){0,2}\s+(?:जी|बहनजी|भाई|भैया|बाबू|साहब|दीदी))"
)
_HI_SUBJECT_KO_RE = re.compile(
    r"(?m)(?:^|\n|[।?!]\s*)([\u0900-\u097F]{2,}(?:\s+[\u0900-\u097F]{2,}){1,2})\s+(?:को|ने)\s+(?:\d+\s*दिन|बुखार|दर्द|खांसी|उल्टी|दस्त|कमजोरी|तबीयत|इलाज|भर्ती)"
)

# Addresses, houses, localities, landmarks, villages, PINs (Latin & Devanagari)
_HOUSE_RE = re.compile(
    r"(?:\b(?:H\.?\s*No\.?|House(?:\s*No\.?)?|Makan\s*No\.?)\s*[:#-]?\s*\d+[A-Za-z0-9/-]*\b|मकान\s*(?:नं\.?|संख्या)\s*[:#-]?\s*\d+[A-Za-z0-9/-]*)",
    re.I,
)
_LOCALITY_RE = re.compile(
    r"(?:\b(?:Ward(?:\s*No\.?)?)\s*\d+[A-Za-z]?\b|\b(?:Mohalla|Basti|Colony|Gali)\s+[A-Z0-9][A-Za-z0-9\s-]{1,30}?(?=\s*(?:,|;|\n|Tehsil|Distt|$))|(?:मोहल्ला|बस्ती|कॉलोनी|वार्ड(?:\s*नं\.?)?)\s+[\u0900-\u097F0-9][\u0900-\u097F0-9\s-]{1,32}?(?=\s*(?:,|;|\n|तहसील|जिला|-|$)))"
)
_LANDMARK_RE = re.compile(
    r"(?:\b(?:near|behind|opp\.?|opposite|beside|next\s+to)\s+[A-Z][A-Za-z0-9\s.'-]{2,38}?(?=\s*(?:,|;|\n|Tehsil|Distt|Gram|$))|(?:[^\n,;]{2,40}?)\s+के\s+(?:पास|पीछे|सामने|निकट))",
    re.I,
)
_VILLAGE_LABELED_RE = re.compile(
    r"(?:\b(?:Gram|Village|Vill\.?)\s*[:=-]?\s*([A-Z\u0900-\u097F][^\n,;]{1,34}?)(?=\s*(?:,|;|\n|Tehsil|तहसील|Distt|जिला|-|\d|$))|ग्राम\s*[:=-]?\s*([^\n,;]{2,34}?)(?=\s*(?:,|;|\n|तहसील|जिला|-|\d|$)))"
)
_PIN_IN_TEXT_RE = re.compile(
    r"(?:(?:\b(?:pin(?:\s*code)?|zip)|पिन(?:\s*कोड)?)\s*[:=-]?\s*|[-–,]\s+)([1-8]\d{5})(?!\d)(?!\s*(?:/uL|cells|cumm|mmHg|mg|mcg|IU|ml))"
)
_ADDR_BLOCK_RE = re.compile(r"(?m)(?:Address(?:\s*\([^)]*\))?|पता)\s*:\s*([^\n]+)")
_ADDR_VILLAGE_BEFORE_TEHSIL_RE = re.compile(
    r",\s*([^,\n]+?)(?=\s*,\s*(?:Tehsil|तहसील|Distt\.?|District|जिला)\b)"
)
_TEHSIL_CLAUSE_RE = re.compile(
    r"(?:,\s*|\b)(?:Tehsil|तहसील)\s*[:=-]?\s*[A-Z\u0900-\u097F][^\n,;-]{1,28}"
)


def _add_group(spans: list[CandidateSpan], pat: re.Pattern[str], text: str, group: int, kind: str, conf: float, family: str, repl: str) -> None:
    for m in pat.finditer(text):
        s, e = m.span(group)
        if s < e:
            val = text[s:e].strip()
            if val:
                spans.append(CandidateSpan(s, e, kind, conf, family, repl))


def find_pii_spans(norm_text: str) -> list[CandidateSpan]:
    """Detect all explicit, cue-based, multilingual, and address PII spans."""
    spans: list[CandidateSpan] = []
    has_digit = any("0" <= c <= "9" for c in norm_text)
    has_at = "@" in norm_text
    has_deva = any("\u0900" <= c <= "\u097F" for c in norm_text)

    if has_digit:
        _add_group(spans, _AADHAAR_RE, norm_text, 0, "AADHAAR", 0.99, "ID", "[ID]")
        _add_group(spans, _AADHAAR_MASKED_RE, norm_text, 0, "AADHAAR_MASKED", 0.98, "ID", "[ID]")
        _add_group(spans, _ABHA_NUM_RE, norm_text, 0, "ABHA_NUMBER", 0.99, "ID", "[ID]")
        _add_group(spans, _PAN_RE, norm_text, 0, "PAN", 0.98, "ID", "[PAN]")
        _add_group(spans, _INSURANCE_RE, norm_text, 0, "INSURANCE_ID", 0.96, "ID", "[INSURANCE_ID]")
        _add_group(spans, _PHONE_RE, norm_text, 0, "PHONE", 0.97, "CONTACT", "[PHONE]")
        _add_group(spans, _MASKED_PHONE_RE, norm_text, 0, "PHONE", 0.96, "CONTACT", "[PHONE]")
        _add_group(spans, _MRN_EXPLICIT_RE, norm_text, 0, "MRN", 0.96, "ID", "[ID]")
        _add_group(spans, _MRN_LABELED_RE, norm_text, 1, "MRN", 0.95, "ID", "[ID]")
        _add_group(spans, _HOUSE_RE, norm_text, 0, "HOUSE", 0.94, "LOCATION", "[ADDRESS]")

    if has_at:
        _add_group(spans, _ABHA_ADDR_RE, norm_text, 0, "ABHA_ADDRESS", 0.99, "ID", "[ID]")
        _add_group(spans, _EMAIL_RE, norm_text, 0, "EMAIL", 0.99, "CONTACT", "[EMAIL]")

    # Names & relatives
    _add_group(spans, _PATIENT_CUE_EN_RE, norm_text, 1, "PATIENT_NAME", 0.96, "PERSON", "[PERSON]")
    _add_group(spans, _BARE_NAME_LINE_RE, norm_text, 1, "PATIENT_NAME", 0.90, "PERSON", "[PERSON]")
    for m in _RELATIVE_CUE_EN_RE.finditer(norm_text):
        grp = 1 if m.group(1) else (2 if m.group(2) else 3)
        s, e = m.span(grp)
        if s < e:
            spans.append(CandidateSpan(s, e, "RELATIVE_NAME", 0.93, "RELATIVE", "[RELATIVE]"))
    if "'" in norm_text or "’" in norm_text:
        _add_group(spans, _POSSESSIVE_NAME_RE, norm_text, 1, "PATIENT_NAME", 0.90, "PERSON", "[PERSON]")
    _add_group(spans, _SUBJECT_BEFORE_KIN_RE, norm_text, 1, "PATIENT_NAME", 0.92, "PERSON", "[PERSON]")
    _add_group(spans, _CLINICAL_NOTE_CUE_RE, norm_text, 1, "PATIENT_NAME", 0.91, "PERSON", "[PERSON]")
    _add_group(spans, _PAREN_ROLE_NAME_RE, norm_text, 1, "RELATIVE_NAME", 0.93, "RELATIVE", "[RELATIVE]")
    _add_group(spans, _PREFIX_TITLE_EN_RE, norm_text, 0, "PATIENT_NAME", 0.88, "PERSON", "[PERSON]")
    _add_group(spans, _NAME_BEFORE_KCO_RE, norm_text, 1, "PATIENT_NAME", 0.91, "PERSON", "[PERSON]")
    _add_group(spans, _HINGLISH_HONORIFIC_RE, norm_text, 0, "PATIENT_NAME", 0.93, "PERSON", "[PERSON]")
    if "[" in norm_text:
        _add_group(spans, _WHATSAPP_SENDER_RE, norm_text, 1, "RELATIVE_NAME", 0.94, "RELATIVE", "[RELATIVE]")

    # Hindi Devanagari names
    if has_deva:
        _add_group(spans, _HI_PATIENT_RE, norm_text, 1, "PATIENT_NAME", 0.96, "PERSON", "[PERSON]")
        _add_group(spans, _HI_RELATIVE_RE, norm_text, 1, "RELATIVE_NAME", 0.95, "RELATIVE", "[RELATIVE]")
        _add_group(spans, _HI_KIN_TITLE_RE, norm_text, 0, "RELATIVE_NAME", 0.90, "RELATIVE", "[PERSON]")
        _add_group(spans, _HI_SUBJECT_KO_RE, norm_text, 1, "PATIENT_NAME", 0.93, "PERSON", "[PERSON]")

    # Address parts & PIN
    _add_group(spans, _LOCALITY_RE, norm_text, 0, "LOCALITY", 0.90, "LOCATION", "[LOCALITY]")
    _add_group(spans, _LANDMARK_RE, norm_text, 0, "LANDMARK", 0.89, "LOCATION", "[LANDMARK]")
    for m in _VILLAGE_LABELED_RE.finditer(norm_text):
        grp = 1 if m.group(1) else 2
        s, e = m.span(grp)
        if s < e:
            spans.append(CandidateSpan(s, e, "VILLAGE", 0.92, "LOCATION", "[VILLAGE]"))

    # Village directly preceding Tehsil / Distt inside Address lines (when not House/Mohalla/Ward/Landmark)
    if "address" in norm_text.lower() or "पता" in norm_text:
        for am in _ADDR_BLOCK_RE.finditer(norm_text):
            line_val = am.group(1)
            base = am.start(1)
            for vm in _ADDR_VILLAGE_BEFORE_TEHSIL_RE.finditer(line_val):
                seg = vm.group(1).strip()
                if not seg:
                    continue
                low = seg.casefold()
                if any(k in low for k in ("mohalla", "ward", "house", "h.no", "makan", "near ", "behind ", "opp", "मोहल्ला", "वार्ड", "मकान", "के पास", "gram", "ग्राम")):
                    continue
                spans.append(CandidateSpan(base + vm.start(1), base + vm.end(1), "VILLAGE", 0.88, "LOCATION", "[VILLAGE]"))

    if has_digit:
        for pm in _PIN_IN_TEXT_RE.finditer(norm_text):
            pre = norm_text[max(0, pm.start() - 12):pm.start()]
            if "/" in pre[-3:] or ":" in pre[-2:]:
                continue
            spans.append(CandidateSpan(pm.start(1), pm.end(1), "PIN", 0.86, "LOCATION", "__PIN3__"))

    # Coarsen sub-district (Tehsil) inside text to reduce Sweeney cell uniqueness
    if "tehsil" in norm_text.lower() or "तहसील" in norm_text:
        for tm in _TEHSIL_CLAUSE_RE.finditer(norm_text):
            raw_t = tm.group(0)
            pref = ", [TEHSIL]" if raw_t.lstrip().startswith(",") else "[TEHSIL]"
            spans.append(CandidateSpan(tm.start(), tm.end(), "LOCALITY", 0.82, "LOCATION", pref))

    return spans
