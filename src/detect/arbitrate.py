"""Deterministic clinical-vs-PII span arbitration with cached fast corpus lexicon matching."""
from __future__ import annotations

from functools import lru_cache

import regex as re

from src.detect.clinical import find_clinical_spans
from src.detect.rules import CandidateSpan, find_pii_spans
from src.textnorm import map_span_to_original, normalize_with_offsets

_WORD_SPLIT_RE = re.compile(r"[\p{L}\p{N}]+")

_SAFE_CLINICAL_STOPWORDS = frozenset({
    "routine", "normal", "stable", "fever", "pain", "cough", "diabetes", "hypertension", "typhoid",
    "malaria", "dengue", "anaemia", "anemia", "patient", "doctor", "hospital", "clinic", "medical",
    "centre", "center", "pathology", "diagnostics", "laboratory", "summary", "discharge", "notes",
    "note", "medicine", "surgery", "general", "emergency", "icu", "ward", "bed", "tablet", "capsule",
    "injection", "syrup", "india", "uttar", "pradesh", "lucknow", "sitapur", "barabanki", "hardoi",
    "sultanpur", "unnao", "raebareli", "rae bareli", "male", "female", "purush", "mahila",
    "morning", "evening", "night", "today", "yesterday", "review", "advice", "advise", "history",
    "complaints", "diagnosis", "treatment", "report", "sample", "blood", "serum", "sugar", "urine",
    "pulse", "temp", "spo2", "weight", "day", "days", "week", "weeks", "month", "months", "year", "years",
})


def _overlaps(a: CandidateSpan, b: CandidateSpan) -> bool:
    return a.start < b.end and b.start < a.end


@lru_cache(maxsize=8)
def _compile_lexicon(
    tokens_key: tuple[str, ...],
) -> tuple[frozenset[str], tuple[re.Pattern[str], ...], dict[str, str]]:
    """Compile and cache alternation regexes + fast O(1) word-trigger filter."""
    tagged: dict[str, tuple[str, str]] = {}
    trigger_words: set[str] = set()
    repl_map_types = {
        "VILLAGE": "[VILLAGE]",
        "LOC": "[LOCALITY]",
        "REL": "[RELATIVE]",
        "ID": "[ID]",
        "PERSON": "[PERSON]",
    }
    for raw in tokens_key:
        if "::" in raw:
            prefix, val = raw.split("::", 1)
            repl = repl_map_types.get(prefix, "[PERSON]")
        else:
            val = raw
            repl = "[PERSON]"
        v = " ".join(val.strip().split())
        if len(v) < 3 or v.casefold() in _SAFE_CLINICAL_STOPWORDS:
            continue
        tagged[v.casefold()] = (v, repl)
        for w in _WORD_SPLIT_RE.findall(v.casefold()):
            if len(w) >= 2:
                trigger_words.add(w)

    ordered = sorted(tagged.values(), key=lambda kv: (-len(kv[0]), kv[0]))
    repl_map = {v.casefold(): repl for v, repl in ordered}
    patterns: list[re.Pattern[str]] = []
    batch_size = 150
    for i in range(0, len(ordered), batch_size):
        chunk = [re.escape(v) for v, _ in ordered[i:i + batch_size]]
        patterns.append(
            re.compile(r"(?<![\p{L}\p{N}])(?:" + "|".join(chunk) + r")(?=(?:'s|’s)?(?![\p{L}\p{N}]))", re.I)
        )
    return frozenset(trigger_words), tuple(patterns), repl_map


def _find_lexicon_spans(norm_text: str, extra_tokens: set[str] | frozenset[str] | None) -> list[CandidateSpan]:
    if not extra_tokens:
        return []
    key = tuple(sorted(extra_tokens)) if isinstance(extra_tokens, (set, frozenset)) else tuple(extra_tokens)
    trigger_words, patterns, repl_map = _compile_lexicon(key)
    if not trigger_words:
        return []
    text_words = set(_WORD_SPLIT_RE.findall(norm_text.casefold()))
    if text_words.isdisjoint(trigger_words):
        return []

    spans: list[CandidateSpan] = []
    for pat in patterns:
        for m in pat.finditer(norm_text):
            matched = " ".join(m.group(0).strip().split()).casefold()
            repl = repl_map.get(matched, "[PERSON]")
            kind = (
                "VILLAGE" if repl == "[VILLAGE]"
                else ("LOCALITY" if repl == "[LOCALITY]"
                      else ("RELATIVE_NAME" if repl == "[RELATIVE]" else "PATIENT_NAME"))
            )
            fam = (
                "LOCATION" if repl in ("[VILLAGE]", "[LOCALITY]")
                else ("RELATIVE" if repl == "[RELATIVE]" else "PERSON")
            )
            spans.append(CandidateSpan(m.start(), m.end(), kind, 0.87, fam, repl))
    return spans


def arbitrate_spans(
    norm_text: str,
    pii_cands: list[CandidateSpan],
    clin_cands: list[CandidateSpan],
) -> list[CandidateSpan]:
    """Resolve overlaps between clinical protections and PII candidates deterministically."""
    del norm_text
    kept: list[CandidateSpan] = []
    for p in pii_cands:
        if p.family == "CLINICAL-KEEP":
            continue
        if p.kind not in ("AADHAAR", "ABHA_NUMBER", "ABHA_ADDRESS", "EMAIL", "PAN", "PHONE", "AADHAAR_MASKED"):
            if any(_overlaps(p, c) for c in clin_cands):
                continue
        kept.append(p)

    kept.sort(key=lambda s: (-s.confidence, -(s.end - s.start), s.start))
    selected: list[CandidateSpan] = []
    for cand in kept:
        if any(_overlaps(cand, s) for s in selected):
            continue
        selected.append(cand)
    selected.sort(key=lambda s: s.start)
    return selected


def clean_text_with_arbitration(
    text: str,
    extra_tokens: set[str] | frozenset[str] | None = None,
) -> tuple[str, int]:
    """Scrub PII in text using clinical protection + rules + corpus lexicon."""
    if not text:
        return text, 0
    nt = normalize_with_offsets(text)
    clin = find_clinical_spans(nt.normalized)
    pii = find_pii_spans(nt.normalized)
    if extra_tokens:
        pii.extend(_find_lexicon_spans(nt.normalized, extra_tokens))
    chosen = arbitrate_spans(nt.normalized, pii, clin)
    if not chosen:
        return text, 0

    orig_edits: list[tuple[int, int, str]] = []
    last_end = 0
    for sp in sorted(chosen, key=lambda s: (s.start, -(s.end - s.start))):
        os_, oe = map_span_to_original(nt, sp.start, sp.end)
        if oe <= os_ or os_ < last_end:
            continue
        repl = sp.replacement
        if repl == "__PIN3__":
            raw_pin = nt.normalized[sp.start:sp.end]
            repl = f"{raw_pin[:3]}***"
        orig_edits.append((os_, oe, repl))
        last_end = oe

    if not orig_edits:
        return text, 0

    out: list[str] = []
    cur = 0
    for os_, oe, repl in orig_edits:
        out.append(text[cur:os_])
        out.append(repl)
        cur = oe
    out.append(text[cur:])
    return "".join(out), len(orig_edits)
