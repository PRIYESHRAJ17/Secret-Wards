"""Privacy transformations: HMAC date shifts, named-month shifts, age banding, DOB & PIN coarsening."""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac

import regex as re

from src.textnorm import fold_digits

_ISO_DT_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(.*)$")
_DMY_SLASH_RE = re.compile(r"\b(\d{1,2})([/-])(\d{1,2})\2((?:19|20)?\d{2})\b")
_ISO_INLINE_RE = re.compile(r"(?<!\d)((?:19|20)\d{2})-(\d{2})-(\d{2})(?!\d)")

_MONTHS = {
    "jan": 1, "january": 1, "जनवरी": 1,
    "feb": 2, "february": 2, "फरवरी": 2,
    "mar": 3, "march": 3, "मार्च": 3,
    "apr": 4, "april": 4, "अप्रैल": 4,
    "may": 5, "मई": 5,
    "jun": 6, "june": 6, "जून": 6,
    "jul": 7, "july": 7, "जुलाई": 7,
    "aug": 8, "august": 8, "अगस्त": 8,
    "sep": 9, "sept": 9, "september": 9, "सितंबर": 9, "सितम्बर": 9,
    "oct": 10, "october": 10, "अक्टूबर": 10, "अक्तूबर": 10,
    "nov": 11, "november": 11, "नवंबर": 11, "नवम्बर": 11,
    "dec": 12, "december": 12, "दिसंबर": 12, "दिसम्बर": 12,
}
_MONTH_NAMES_FULL = [
    "", "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]
_NAMED_DATE_RE = re.compile(
    r"\b(\d{1,2})\s+(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t|tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?|जनवरी|फरवरी|मार्च|अप्रैल|मई|जून|जुलाई|अगस्त|सितंबर|सितम्बर|अक्टूबर|अक्तूबर|नवंबर|नवम्बर|दिसंबर|दिसम्बर)(?:\s*,?\s*((?:19|20)\d{2}))?(?=\s|$|[,.;)!?])",
    re.I,
)

# Age banding in free text while protecting durations ("x 12 yrs", "8 yrs back")
_AGE_BAND_SKIP_CTX = re.compile(r"(?:x\s*$|for\s*$|after\s*$|back|ago|\d-\d)", re.I)
_TEXT_AGE_RE = re.compile(
    r"(?:(Age(?:/Sex)?|Umar|आयु)\s*[:=-]\s*)(\d{1,3})(\s*(?:Yrs?/?|Years?/?|Y\b|वर्ष)?)",
    re.I,
)
_WA_AGE_RE = re.compile(r"(?<=\s)(\d{1,3})(\s*Y\s*/\s*[MF]\b)", re.I)
_EXACT_AGE_UNIT_RE = re.compile(
    r"(?<![-/\d])(\d{1,3})(\s*(?:Yrs|Years)\s*/\s*[MF]\b|\s*वर्ष(?:\s*/\s*(?:पुरुष|महिला))?)",
    re.I,
)


def shift_days_for_key(
    date_key: bytes,
    anchor: str,
    min_days: int = 30,
    max_days: int = 365,
) -> int:
    """Compute a deterministic signed shift in [-max_days, -min_days] U [min_days, max_days]."""
    dig = hmac.new(date_key, f"shift|{anchor}".encode("utf-8"), hashlib.sha256).digest()
    span = max(1, max_days - min_days + 1)
    mag = min_days + (int.from_bytes(dig[:4], "big") % span)
    sign = -1 if (dig[4] & 1) else 1
    return sign * mag


def band_age(age: int, width: int = 5, elderly_open: int = 85) -> str:
    """Map an integer age to a clinical utility band ('45-49', '85+')."""
    if age < 0:
        return "[AGE]"
    if age >= elderly_open:
        return f"{elderly_open}+"
    lo = (age // width) * width
    hi = lo + width - 1
    return f"{lo}-{hi}"


def dob_to_year(dob_val: str, cohort_width: int = 1) -> str:
    """Generalize DOB string to year (or coarse 5/10-year birth cohort for A4 defense)."""
    s = fold_digits(str(dob_val)).strip()
    m = re.search(r"\b(19\d{2}|20[0-2]\d)\b", s)
    if not m:
        return "[DATE]"
    y = int(m.group(1))
    if cohort_width > 1:
        y = (y // cohort_width) * cohort_width
    return str(y)


def generalize_pin(pin: str, prefix_digits: int = 3) -> str:
    """Preserve top prefix_digits of 6-digit Indian PIN code (226010 -> 226***)."""
    d = re.sub(r"\D", "", fold_digits(str(pin)))
    if len(d) != 6:
        return "[PIN]" if prefix_digits <= 0 else "[PIN]"
    if prefix_digits <= 0:
        return "[PIN]"
    return f"{d[:prefix_digits]}{'*' * (6 - prefix_digits)}"


def shift_iso_str(iso_val: str, days: int) -> str:
    """Shift ISO date or datetime string preserving timezone/time tail and interval exactness."""
    s = fold_digits(str(iso_val)).strip()
    m = _ISO_DT_RE.match(s)
    if not m:
        return iso_val
    try:
        d = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return iso_val
    nd = d + dt.timedelta(days=days)
    return f"{nd.isoformat()}{m.group(4)}"


def shift_date_token(token: str, days: int, order_hint: str = "dmy") -> str:
    """Shift ISO, DD/MM/YYYY, MM/DD/YYYY, DD/MM/YY, or named-month date token consistently."""
    s = fold_digits(token.strip())
    m_iso = _ISO_DT_RE.match(s)
    if m_iso and not m_iso.group(4):
        try:
            d = dt.date(int(m_iso.group(1)), int(m_iso.group(2)), int(m_iso.group(3)))
            return (d + dt.timedelta(days=days)).isoformat()
        except ValueError:
            return token

    m_sep = _DMY_SLASH_RE.fullmatch(s)
    if m_sep:
        a, sep, b, y_raw = int(m_sep.group(1)), m_sep.group(2), int(m_sep.group(3)), m_sep.group(4)
        two_dig = len(y_raw) == 2
        y = (2000 + int(y_raw) if int(y_raw) <= 40 else 1900 + int(y_raw)) if two_dig else int(y_raw)
        if b > 12 and 1 <= a <= 12:
            mo, day, use_mdy = a, b, True
        elif a > 12 and 1 <= b <= 12:
            day, mo, use_mdy = a, b, False
        elif order_hint == "mdy" and 1 <= a <= 12:
            mo, day, use_mdy = a, b, True
        else:
            day, mo, use_mdy = a, b, False
        try:
            nd = dt.date(y, mo, day) + dt.timedelta(days=days)
        except ValueError:
            return token
        yy = f"{nd.year % 100:02d}" if two_dig else f"{nd.year:04d}"
        return f"{nd.month:02d}{sep}{nd.day:02d}{sep}{yy}" if use_mdy else f"{nd.day:02d}{sep}{nd.month:02d}{sep}{yy}"

    m_named = _NAMED_DATE_RE.fullmatch(s)
    if m_named:
        day = int(m_named.group(1))
        mo = _MONTHS[m_named.group(2).lower()]
        yr = int(m_named.group(3)) if m_named.group(3) else 2026
        try:
            nd = dt.date(yr, mo, day) + dt.timedelta(days=days)
        except ValueError:
            return token
        mname = _MONTH_NAMES_FULL[nd.month]
        return f"{nd.day} {mname} {nd.year}" if m_named.group(3) else f"{nd.day} {mname}"

    return token


def shift_all_dates_in_text(text: str, days: int, order_hint: str = "dmy") -> tuple[str, int]:
    """Shift ISO, delimited numeric, and named-month dates inside free text without altering IDs/DOB."""
    hits = 0

    def _sub_iso(m: re.Match[str]) -> str:
        nonlocal hits
        pre = text[max(0, m.start() - 12):m.start()].lower()
        if "dob" in pre or "birth" in pre:
            hits += 1
            return dob_to_year(m.group(0), cohort_width=5)
        try:
            d = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return m.group(0)
        hits += 1
        return (d + dt.timedelta(days=days)).isoformat()

    out = _ISO_INLINE_RE.sub(_sub_iso, text)

    # Choose document-level mdy vs dmy order if unambiguous MM/DD dates appear (>12 in 2nd position)
    local_hint = order_hint
    for m in _DMY_SLASH_RE.finditer(out):
        if int(m.group(3)) > 12 and int(m.group(1)) <= 12:
            local_hint = "mdy"
            break

    def _sub_dmy(m: re.Match[str]) -> str:
        nonlocal hits
        pre = out[max(0, m.start() - 18):m.start()].lower()
        if "dob" in pre or "birth" in pre or "जन्म" in pre:
            hits += 1
            return dob_to_year(m.group(0), cohort_width=5)
        a, b = int(m.group(1)), int(m.group(3))
        if not (1 <= a <= 31 and 1 <= b <= 31):
            return m.group(0)
        shifted = shift_date_token(m.group(0), days, order_hint=local_hint)
        if shifted != m.group(0):
            hits += 1
        return shifted

    out = _DMY_SLASH_RE.sub(_sub_dmy, out)

    def _sub_named(m: re.Match[str]) -> str:
        nonlocal hits
        pre = out[max(0, m.start() - 12):m.start()].lower()
        if "dob" in pre or "birth" in pre:
            return m.group(0)
        shifted = shift_date_token(m.group(0), days, order_hint=local_hint)
        if shifted != m.group(0):
            hits += 1
        return shifted

    out = _NAMED_DATE_RE.sub(_sub_named, out)
    return out, hits


def band_ages_in_text(text: str, width: int = 5, elderly_open: int = 85) -> tuple[str, int]:
    """Band explicit patient ages inside free text without touching clinical durations."""
    hits = 0

    def _sub_lbl(m: re.Match[str]) -> str:
        nonlocal hits
        a = int(fold_digits(m.group(2)))
        if 0 <= a <= 115:
            hits += 1
            return f"{m.group(1)}: {band_age(a, width=width, elderly_open=elderly_open)}{m.group(3)}"
        return m.group(0)

    out = _TEXT_AGE_RE.sub(_sub_lbl, text)

    def _sub_wa(m: re.Match[str]) -> str:
        nonlocal hits
        a = int(fold_digits(m.group(1)))
        if 0 <= a <= 115:
            hits += 1
            return f"{band_age(a, width=width, elderly_open=elderly_open)}{m.group(2)}"
        return m.group(0)

    out = _WA_AGE_RE.sub(_sub_wa, out)

    def _sub_unit(m: re.Match[str]) -> str:
        nonlocal hits
        pre = out[max(0, m.start() - 14):m.start()]
        if _AGE_BAND_SKIP_CTX.search(pre):
            return m.group(0)
        a = int(fold_digits(m.group(1)))
        if 0 <= a <= 115:
            hits += 1
            return f"{band_age(a, width=width, elderly_open=elderly_open)}{m.group(2)}"
        return m.group(0)

    out = _EXACT_AGE_UNIT_RE.sub(_sub_unit, out)
    return out, hits
