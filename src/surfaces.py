"""Hidden-channel surface guards: filenames, CSV headers, metadata strings, and base64 blobs."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from pathlib import Path
from typing import Callable

import regex as re

from src.textnorm import fold_digits, normalize_match

_DEVA_RE = re.compile(r"[\u0900-\u097F]")
_PHONE_COMP_RE = re.compile(r"(?<!\d)(?:\+?91[-_ ]?)?[6-9]\d{4}[-_ ]?\d{5}(?!\d)")
_LONG_DIGITS_RE = re.compile(r"(?<!\d)\d{7,}(?!\d)")
_MRN_STEM_RE = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:[A-Za-z]{2,5}[-_/]\d{2,4}[-_/]\d{4,}|(?:uhid|jjh|snj|dhh\d{0,4}|adm|ipd|opd|ip)[-_]?(?:\d{2,4}[-_])?\d{4,})(?:$|[^A-Za-z0-9])",
    re.I,
)
_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}")
_WIN_PATH_TAIL_RE = re.compile(r"([A-Za-z]:\\[^\n\"']+|/(?:home|var|tmp|mnt|exports|data)/[^\n\"']+)")
_SUMMARY_NAME_STEM_RE = re.compile(
    r"^(?:discharge_summary|case_sheet|referral|patient)_[A-Z][a-z]{2,}_[A-Z][a-z]{2,}",
)
_TITLECASE_PAIR_RE = re.compile(r"([A-Z][a-z]{2,})[_-]([A-Z][a-z]{2,})")
_SAFE_FN_WORDS = frozenset({
    "discharge", "summary", "report", "patient", "clinical", "note", "notes", "hospital",
    "medical", "clinic", "ward", "nursing", "opd", "ipd", "case", "sheet", "consent",
    "form", "dir", "charitable", "seva", "sadan", "district", "legacy", "export",
})
_B64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=\r\n]+$")
_SAFE_DIRS = frozenset({
    "billing", "clean", "discharge", "fhir", "lab", "misc", "notes", "opd", "prescriptions", "registration",
})


def _hmac_comp(filename_key: bytes, comp: str, ext: str = "") -> str:
    dig = hmac.new(filename_key, comp.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
    return f"rec_{dig}{ext}"


_SCHEMA_HEADER_WORDS = frozenset({
    "reg", "no", "naam", "ling", "umar", "janm", "tithi", "pita", "pati", "ka", "pata", "gaon",
    "tehsil", "jila", "pin", "code", "zip", "mobile", "phone", "aadhar", "aadhaar", "registration",
    "date", "first", "last", "full", "patient", "name", "dob", "sex", "gender", "age", "address",
    "city", "village", "district", "state", "country", "bill", "claim", "package", "procedure",
    "admission", "discharge", "amount", "inr", "status", "sample", "ref", "doctor", "test", "result",
    "unit", "collected", "reported", "on", "id", "uhid", "mrn", "pmjay", "payer", "pan", "policy",
})


def looks_like_person_label(text: str) -> bool:
    """True when a space-separated label looks like a human proper name (not schema header)."""
    s = " ".join(text.strip().split())
    if not s or "_" in s or "/" in s:
        return False
    if _DEVA_RE.search(s):
        return True
    toks = s.split()
    if 2 <= len(toks) <= 4 and all(re.fullmatch(r"[A-Z][a-z]{2,}", t) for t in toks):
        if all(t.casefold() in _SCHEMA_HEADER_WORDS for t in toks):
            return False
        return True
    return False


def component_has_pii(comp: str, extra_tokens: set[str] | None = None) -> bool:
    """Detect PII inside filename stems or table headers without flagging snake_case field names."""
    if not comp:
        return False
    norm = fold_digits(comp)
    if _DEVA_RE.search(norm) or _PHONE_COMP_RE.search(norm) or _LONG_DIGITS_RE.search(norm):
        return True
    if _MRN_STEM_RE.search(norm) or _PAN_RE.search(norm) or _EMAIL_RE.search(norm):
        return True
    if _SUMMARY_NAME_STEM_RE.match(norm):
        return True
    for m_pair in _TITLECASE_PAIR_RE.finditer(norm):
        w1, w2 = m_pair.group(1).casefold(), m_pair.group(2).casefold()
        if w1 not in _SAFE_FN_WORDS or w2 not in _SAFE_FN_WORDS:
            return True
    if extra_tokens:
        # Split on punctuation & underscores so ID_Name or Summary_First_Last match cleanly
        norm_low = normalize_match(re.sub(r"[_/\\-]+", " ", comp))
        padded = f" {norm_low} "
        for raw in extra_tokens:
            val = raw.split("::", 1)[-1]
            tok = normalize_match(val)
            if len(tok) >= 3 and f" {tok} " in padded:
                return True
    return False


def sanitize_header(
    header: list[str],
    clean_fn: Callable[[str], tuple[str, int]],
    extra_tokens: set[str] | None = None,
) -> tuple[list[str], int]:
    """Replace PII-bearing CSV/TSV column headers with col_<i> while keeping clinical/schema headers."""
    out: list[str] = []
    hits = 0
    for idx, col in enumerate(header):
        col_s = col.strip()
        if not col_s:
            out.append(col)
            continue
        # Only inspect header if NOT pure lowercase snake_case clinical field name
        is_snake_field = bool(re.fullmatch(r"[a-z][a-z0-9_]*", col_s)) and not component_has_pii(col_s, extra_tokens)
        if is_snake_field:
            out.append(col)
            continue
        if component_has_pii(col_s, extra_tokens) or looks_like_person_label(col_s):
            out.append(f"col_{idx}")
            hits += 1
            continue
        cleaned, ch = clean_fn(col)
        if ch > 0 and cleaned != col:
            out.append(f"col_{idx}")
            hits += 1
        else:
            out.append(col)
    return out, hits


def sanitize_metadata_str(val: str, clean_fn: Callable[[str], tuple[str, int]]) -> tuple[str, int]:
    """Scrub PII in metadata paths/audit fields (e.g. Windows/POSIX export paths)."""
    hits = 0
    out_val = val
    m = _WIN_PATH_TAIL_RE.search(val)
    if m:
        sep = "\\" if "\\" in val else "/"
        parts = val.split(sep)
        new_parts: list[str] = []
        for p in parts:
            if p and (component_has_pii(p) or re.search(r"_[A-Za-z]*_\d{5,}", p) or re.search(r"[A-Z][a-z]+_[A-Z0-9_]+", p)):
                new_parts.append("[REDACTED]")
                hits += 1
            else:
                cp, ch = clean_fn(p)
                if ch > 0:
                    new_parts.append(cp)
                    hits += ch
                else:
                    new_parts.append(p)
        out_val = sep.join(new_parts)
    else:
        out_val, hits = clean_fn(val)
    return out_val, hits


def decode_and_sanitize_base64(
    b64_str: str,
    clean_fn: Callable[[str], tuple[str, int]],
) -> tuple[str, bool, int]:
    """Decode base64 payload if valid UTF-8 text, sanitize it, and re-encode strictly."""
    compact = "".join(b64_str.split())
    if len(compact) < 16 or not _B64_CHARS_RE.match(compact):
        return b64_str, False, 0
    padded = compact + "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return b64_str, False, 0
    if not raw or len(raw) < 10:
        return b64_str, False, 0
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return b64_str, False, 0
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    if printable < len(text) * 0.85:
        return b64_str, False, 0
    cleaned, hits = clean_fn(text)
    if cleaned != text or hits > 0:
        reenc = base64.b64encode(cleaned.encode("utf-8")).decode("ascii")
        return reenc, True, max(1, hits)
    return b64_str, True, 0


def sanitize_rel_path(
    rel_path: str,
    filename_key: bytes,
    used_paths: set[str],
    extra_tokens: set[str] | None = None,
) -> tuple[str, bool]:
    """Deterministically HMAC-rename any PII-bearing folder or filename component."""
    p = Path(rel_path)
    parts = list(p.parts)
    changed = False
    new_parts: list[str] = []
    for idx, comp in enumerate(parts):
        is_last = idx == len(parts) - 1
        stem = Path(comp).stem if is_last else comp
        ext = Path(comp).suffix.lower() if is_last else ""
        if not is_last and comp in _SAFE_DIRS:
            new_parts.append(comp)
            continue
        if component_has_pii(stem, extra_tokens):
            changed = True
            new_parts.append(_hmac_comp(filename_key, comp, ext))
        else:
            new_parts.append(comp)

    candidate = "/".join(new_parts)
    counter = 0
    while candidate in used_paths:
        counter += 1
        p2 = Path(candidate)
        stem2 = p2.stem
        ext2 = p2.suffix
        parent2 = p2.parent.as_posix()
        hashed = _hmac_comp(filename_key, f"{rel_path}#{counter}", ext2)
        candidate = hashed if parent2 in ("", ".") else f"{parent2}/{hashed}"
    used_paths.add(candidate)
    return candidate, changed
