"""Challenge-2 clinical phrase & token protection before PII redaction."""
from __future__ import annotations

import regex as re

from src.detect.rules import CandidateSpan

_ADDR_LINE_RE = re.compile(
    r"(?:\b(?:Address(?:_note)?|Attendant|Mohalla|Gram|Tehsil|Distt\.?|District|H\.?No\.?|House|Makan)\b|C/O\s+\[|पता|मकान|मोहल्ला|ग्राम|तहसील|जिला)",
    re.I,
)
_RES_WARD_AFTER_RE = re.compile(r"^\s*,?\s*(?:Mohalla|मोहल्ला|Gram|ग्राम|near|behind|H\.?No)", re.I)

_CLINICAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Clinicians with title (requires capitalized or Devanagari name after Dr./Prof., avoids Hinglish 'Dr ne bola')
    ("DOCTOR", re.compile(r"\b(?:Dr|Doctor|Prof)\b\.?\s+[A-Z\u0900-\u097F][a-zA-Z\u0900-\u097F.'’-]{1,25}(?:\s+[A-Z\u0900-\u097F][a-zA-Z\u0900-\u097F.'’-]{1,25}){0,2}(?:\s*\([^)\n]{2,25}\))?")),
    # ASHA community health worker mentions (case-sensitive 'ASHA' so patient name 'Asha' is never protected!)
    ("ASHA", re.compile(r"\bASHA\b(?:\s+(?:workers?|did[iíy]|supervisors?|facilitators?|kits?))?")),
    # Known disease eponyms
    ("EPONYM", re.compile(r"\b(?:Parkinson(?:'s|’s)?|Alzheimer(?:'s|’s)?|Cushing(?:'s|’s)?|Addison(?:'s|’s)?|Crohn(?:'s|’s)?|Bell(?:'s|’s)?|Raynaud(?:'s|’s)?|Graves(?:'|’)?|Hashimoto(?:'s|’s)?|Hodgkin(?:'s|’s)?|Sjogren(?:'s|’s)?|Wilson(?:'s|’s)?|Hansen(?:'s|’s)?|Down(?:'s|’s)?)\s+(?:disease|syndrome|palsy|phenomenon|lymphoma|crisis)\b", re.I)),
    # History / Rule-out / Known case of (stop before Attendant / S/o / D/o / W/o)
    ("HISTORY_OF", re.compile(r"\b(?:K/C/O|k/c/o|H/O|h/o|R/O|r/o)\s+[^\n.;]{1,75}?(?=\s*(?:\.|;|\n|\bAttendant\b|\b(?:S|D|W)/[Oo]\b|$))")),
    # Clinical C/O complaint (must NOT match 'C/O <PersonName>' inside attendant/address lines)
    ("COMPLAINT_OF", re.compile(r"\b(?:C/O|c/o)\s+(?:(?!(?:[A-Z][a-z]+\s+[A-Z][a-z]+\s*(?:,|\n|$)))[a-z0-9][^\n.;]{1,75})(?=\s*(?:\.|;|\n|$))")),
    # Drug orders & strengths/frequencies
    ("RX_DRUG", re.compile(r"\b(?:Tab\.?|Cap\.?|Inj\.?|Syr\.?|Syrup|Oint\.?|Drop|Drops|Sachet|Susp\.?)\s+[A-Za-z0-9+\s/.-]{2,55}?(?:\b\d+(?:\.\d+)?\s*(?:mg|g|gm|mcg|ug|ml|mL|IU|units?|%|mg/dL)\b|\b[01]-[01]-[01]\b|\b(?:OD|BD|TDS|QID|HS|SOS)\b)")),
    ("FREQ_DOSE", re.compile(r"\b(?:[01]-[01]-[01]|OD|BD|TDS|QID|HS|SOS|q\d+h)\b(?:\s*[x×]\s*\d+\s*(?:days?|wks?|weeks?|months?|d))?", re.I)),
    ("DOSE_VAL", re.compile(r"\b\d+(?:\.\d+)?\s*(?:mg/dL|mg|gm?|mcg|ug|mL|ml|IU|mIU/L|mmol/L|units?|/uL|/min|mmHg)\b", re.I)),
    ("VITALS", re.compile(r"\b(?:BP|Pulse|PR|Temp|Temperature|SpO2|SPO2|RR|RBS|HbA1c|Hb|WBC|Plt|Platelets?)\s*[:=]?\s*\d+(?:\.\d+)?(?:/\d+(?:\.\d+)?)?(?:\s*(?:mmHg|/min|°?[FC]|%|mg/dL|g/dL|/uL))?", re.I)),
    ("ICD10_LOINC", re.compile(r"\b(?:[A-TV-Z]\d{2}(?:\.\d{1,2})?|\d{3,5}-\d)\b")),
    # Hospital Facility & Diagnostic lab proper names
    ("HOSPITAL", re.compile(r"(?<!Patient\s)(?<!Name:\s)\b[A-Z][A-Za-z&.-]+(?:\s+[A-Z][A-Za-z&.-]+){0,4}\s+(?:Charitable\s+Hospital|Multispeciality\s+Hospital|Medical\s+College|Seva\s+Sadan|District\s+Hospital(?:\s+[A-Z][a-z]+)?|Hospital|Pathology|Diagnostics|Clinic|Nursing\s+Home)\b")),
]

_HOSPITAL_WARD_RE = re.compile(r"\bWard\s*(?:No\.?)?\s*\d+[A-Za-z]?(?:\s*\([^)\n]{2,25}\))?", re.I)


def find_clinical_spans(norm_text: str) -> list[CandidateSpan]:
    """Identify protected clinical spans that should never be redacted as PII."""
    spans: list[CandidateSpan] = []
    for kind, pat in _CLINICAL_PATTERNS:
        for m in pat.finditer(norm_text):
            if kind == "COMPLAINT_OF":
                line_start = norm_text.rfind("\n", 0, m.start()) + 1
                prefix = norm_text[line_start:m.start()]
                if _ADDR_LINE_RE.search(prefix) or "attendant" in prefix.lower():
                    continue
            spans.append(CandidateSpan(m.start(), m.end(), kind, 1.0, "CLINICAL-KEEP"))

    # Protect Hospital/Census Ward numbers ONLY when not inside a residential address clause
    for m in _HOSPITAL_WARD_RE.finditer(norm_text):
        line_start = norm_text.rfind("\n", 0, m.start()) + 1
        line_end = norm_text.find("\n", m.end())
        if line_end == -1:
            line_end = len(norm_text)
        line = norm_text[line_start:line_end]
        after = norm_text[m.end():line_end]
        if _ADDR_LINE_RE.search(line) and not "(" in m.group(0):
            continue
        if _RES_WARD_AFTER_RE.search(after):
            continue
        spans.append(CandidateSpan(m.start(), m.end(), "HOSPITAL_WARD", 1.0, "CLINICAL-KEEP"))

    return spans
