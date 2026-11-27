"""Deterministic text/Unicode normalization with original offset preservation and Indic transliteration."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

_ZERO_WIDTH = frozenset("\u200b\u200c\u200d\ufeff\u00ad\u2060\u200e\u200f")
_DIGIT_TRANS = str.maketrans(
    "०१२३४५६७८९"
    "০১২৩৪৫৬৭৮৯"
    "૦૧૨૩૪૫૬૭૮૯"
    "੦੧੨੩੪੫੬੭੮੯",
    "0123456789" * 4,
)
_HOMOGLYPH_TRANS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "у": "y", "к": "k", "м": "m", "т": "t",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
})

_DEVA_CONSONANTS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n",
    "च": "ch", "छ": "chh", "ज": "j", "झ": "jh", "ञ": "n",
    "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n",
    "त": "t", "थ": "th", "द": "d", "ध": "dh", "न": "n",
    "प": "p", "फ": "ph", "ब": "b", "भ": "bh", "म": "m",
    "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh",
    "ष": "sh", "स": "s", "ह": "h",
    "क़": "q", "ख़": "kh", "ग़": "gh", "ज़": "z", "फ़": "f", "ड़": "r", "ढ़": "rh",
}
_DEVA_VOWELS = {
    "अ": "a", "आ": "aa", "इ": "i", "ई": "ee", "उ": "u", "ऊ": "oo",
    "ए": "e", "ऐ": "ai", "ओ": "o", "औ": "au", "ऋ": "ri", "ऑ": "o", "ऍ": "e",
}
_DEVA_MATRAS = {
    "ा": "a", "ि": "i", "ी": "ee", "ु": "u", "ू": "oo",
    "े": "e", "ै": "ai", "ो": "o", "ौ": "au", "ृ": "ri",
    "ॉ": "o", "ॅ": "e", "ं": "n", "ँ": "n", "ः": "h", "्": "",
}
_TITLE_TOKENS = frozenset({
    "shri", "shree", "sri", "smt", "shrimati", "kumari", "km",
    "mr", "mrs", "ms", "miss", "master", "ji", "behenji", "bahenji",
    "bahanji", "bhaiya", "bhai", "babu", "sahab", "saheb", "chacha", "chachu", "didi",
})
_NAME_ALIASES = {
    "md": "mohammad",
    "mohd": "mohammad",
    "mo": "mohammad",
    "mohammed": "mohammad",
    "muhammad": "mohammad",
    "muhammed": "mohammad",
}
_HONORIFIC_RE = re.compile(r"\b(?:mr|mrs|ms|smt|shri|shree|sri|shrimati|dr|prof)\.?\s+", re.I)


@dataclass
class NormText:
    original: str
    normalized: str
    orig_spans: list[tuple[int, int]]


def fold_digits(text: str) -> str:
    return text.translate(_DIGIT_TRANS)


def normalize_with_offsets(text: str) -> NormText:
    """Apply NFKC + homoglyph + Indic-digit folding + zero-width strip keeping offset map."""
    out_chars: list[str] = []
    spans: list[tuple[int, int]] = []
    for i, ch in enumerate(text):
        if ch in _ZERO_WIDTH:
            continue
        folded = unicodedata.normalize("NFKC", ch).translate(_HOMOGLYPH_TRANS).translate(_DIGIT_TRANS)
        for nc in folded:
            # Strip Latin combining accents while keeping Devanagari matras intact
            if unicodedata.category(nc) == "Mn" and not ("\u0900" <= nc <= "\u097f"):
                continue
            out_chars.append(nc)
            spans.append((i, i + 1))
    return NormText(original=text, normalized="".join(out_chars), orig_spans=spans)


def map_span_to_original(norm_text: NormText, n_start: int, n_end: int) -> tuple[int, int]:
    """Map [n_start, n_end) slice in normalized string back to [o_start, o_end) in original."""
    if n_start >= n_end or not norm_text.orig_spans:
        return (0, 0)
    s_idx = min(n_start, len(norm_text.orig_spans) - 1)
    e_idx = min(max(n_end - 1, s_idx), len(norm_text.orig_spans) - 1)
    return (norm_text.orig_spans[s_idx][0], norm_text.orig_spans[e_idx][1])


def normalize_match(text: str) -> str:
    """Casefolded, NFKC-normalized, zero-width-free, digit-folded, diacritic-stripped match key."""
    s = unicodedata.normalize("NFKC", text)
    s = "".join(ch for ch in s if ch not in _ZERO_WIDTH)
    s = s.translate(_HOMOGLYPH_TRANS).translate(_DIGIT_TRANS)
    nfd = unicodedata.normalize("NFD", s)
    s = "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")
    return " ".join(s.casefold().split())


def deva_to_latin(text: str) -> str:
    """Deterministic Devanagari-to-Latin phonetic transliterator."""
    out: list[str] = []
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if i + 1 < n and text[i + 1] == "\u093c" and (ch + "\u093c") in _DEVA_CONSONANTS:
            cons = _DEVA_CONSONANTS[ch + "\u093c"]
            i += 2
            if i < n and text[i] in _DEVA_MATRAS:
                out.append(cons + _DEVA_MATRAS[text[i]])
                i += 1
            else:
                out.append(cons + ("a" if i < n and text[i].isalnum() else ""))
            continue
        if ch in _DEVA_CONSONANTS:
            cons = _DEVA_CONSONANTS[ch]
            i += 1
            if i < n and text[i] in _DEVA_MATRAS:
                out.append(cons + _DEVA_MATRAS[text[i]])
                i += 1
            else:
                out.append(cons + ("a" if i < n and text[i].isalnum() else ""))
        elif ch in _DEVA_VOWELS:
            out.append(_DEVA_VOWELS[ch])
            i += 1
        elif ch in _DEVA_MATRAS:
            out.append(_DEVA_MATRAS[ch])
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def consonant_skeleton(text: str) -> str:
    """Cross-script phonetic consonant skeleton invariant to Devanagari/Latin vowel drift."""
    s = normalize_match(deva_to_latin(text))
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = s.replace("ksh", "x").replace("ph", "f").replace("sh", "s").replace("w", "v").replace("z", "j")
    s = re.sub(r"([bcdfgjklmnpqrstvx])h", r"\1", s)
    s = re.sub(r"(.)\1+", r"\1", s)
    toks: list[str] = []
    for tok in s.split():
        aliased = _NAME_ALIASES.get(tok, tok)
        if aliased != tok:
            aliased = re.sub(r"([bcdfgjklmnpqrstvx])h", r"\1", aliased)
            aliased = re.sub(r"(.)\1+", r"\1", aliased)
        sk = re.sub(r"[aeiouy]+$", "", re.sub(r"[aeiou]", "", aliased)) or re.sub(r"[aeiou]", "", aliased) or aliased
        toks.append(sk)
    return " ".join(toks)


def canonical_name_parts(name: str) -> tuple[str, list[str], str]:
    """Return (latin_norm_full, core_tokens, consonant_skeleton) stripping honorifics."""
    raw = str(name)
    if "," in raw:
        cparts = [p.strip() for p in raw.split(",", 1)]
        if len(cparts) == 2 and all(1 <= len(p.split()) <= 2 for p in cparts):
            raw = f"{cparts[1]} {cparts[0]}"
    s = _HONORIFIC_RE.sub(" ", deva_to_latin(raw))
    s = re.sub(r"[^a-zA-Z\s]", " ", normalize_match(s))
    raw_toks = [_NAME_ALIASES.get(t, t) for t in s.split() if len(t) >= 2]
    core = [t for t in raw_toks if t not in _TITLE_TOKENS]
    if not core:
        core = raw_toks
    full = " ".join(core)
    return full, core, consonant_skeleton(full)


def norm_phone(s: str) -> str | None:
    """Normalize an Indian phone number (including +91 / 0091 / 0 prefixes) to 10 digits starting [6-9], or None."""
    d = re.sub(r"\D", "", fold_digits(unicodedata.normalize("NFKC", str(s))))
    if len(d) == 14 and d.startswith("0091"):
        d = d[4:]
    elif len(d) == 12 and d.startswith("91"):
        d = d[2:]
    elif len(d) == 11 and d.startswith("0"):
        d = d[1:]
    if len(d) == 10 and d[0] in "6789":
        return d
    return None


def norm_mrn(s: str) -> tuple[str, str]:
    """Return (canonical_mrn, scoped_kind) recognizing general prefixed multi-hospital MRNs."""
    raw = unicodedata.normalize("NFKC", fold_digits(str(s))).strip().lstrip("#").upper()
    canon = re.sub(r"[^A-Z0-9]", "", raw)
    if re.match(r"^(?:UHID|JJH|SNJ|DHH)\d", canon) or re.match(r"^[A-Z]{2,5}\d{7,}$", canon):
        return canon, "global"
    return canon, "local"
