"""Whole-surface leak and canary scanner across all 7 hygiene channels (SCORING.md:125).

Channels checked:
  1. sanitized_content   - all files under {output}/sanitized/
  2. sanitized_filenames - relative paths & directory names under {output}/sanitized/
  3. report_json         - {output}/report.json
  4. records_jsonl       - {output}/records.jsonl
  5. logs_and_other      - {output}/logs/ and any unexpected files under {output}/
  6. stdout_stderr       - captured stdout/stderr strings (optional)
  7. temp_dirs           - TMPDIR/HOME/fs-diff leftover paths & contents (optional)
"""
from __future__ import annotations

import argparse
import base64
import binascii
import html
import json
import os
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

_ZW_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u00ad\u2060]")
_INDIC_DIGITS = str.maketrans("०१२३४५६७८९০১২৩৪৫৬৭৮৯", "01234567890123456789")
_HOMOGLYPHS = str.maketrans({
    # Cyrillic lowercase & uppercase lookalikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "у": "y", "к": "k",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "І": "I",
    # Greek lookalikes
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
})

_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")
_UESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4})+")

# Minimal Devanagari -> Latin table for leak-variant generation (no runtime dependency)
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
    "ए": "e", "ऐ": "ai", "ओ": "o", "औ": "au", "ऋ": "ri",
}
_DEVA_MATRAS = {
    "ा": "a", "ि": "i", "ी": "ee", "ु": "u", "ू": "oo",
    "े": "e", "ै": "ai", "ो": "o", "ौ": "au", "ृ": "ri",
    "ं": "n", "ँ": "n", "ः": "h", "्": "",
}


def strip_diacritics(text: str) -> str:
    nfd = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")


def norm_scoring(text: str) -> str:
    """Normalization matching SCORING.md:43-45 (NFKC, homoglyphs, ZW, Indic digits, diacritics, casefold)."""
    s = unicodedata.normalize("NFKC", text)
    s = _ZW_RE.sub("", s)
    s = s.translate(_HOMOGLYPHS).translate(_INDIC_DIGITS)
    s = strip_diacritics(s)
    return " ".join(s.casefold().split())


def deva_to_latin_approx(text: str) -> str:
    """Deterministic lightweight Devanagari->Latin transliterator for variant scanning."""
    out: list[str] = []
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        # Check two-char nukta consonant
        if i + 1 < n and text[i + 1] == "\u093c" and (ch + "\u093c") in _DEVA_CONSONANTS:
            cons = _DEVA_CONSONANTS[ch + "\u093c"]
            i += 2
            if i < n and text[i] in _DEVA_MATRAS:
                out.append(cons + _DEVA_MATRAS[text[i]])
                i += 1
            else:
                out.append(cons + "a")
            continue
        if ch in _DEVA_CONSONANTS:
            cons = _DEVA_CONSONANTS[ch]
            i += 1
            if i < n and text[i] in _DEVA_MATRAS:
                out.append(cons + _DEVA_MATRAS[text[i]])
                i += 1
            else:
                out.append(cons + ("a" if i < n and text[i] != " " else ""))
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
    """Vowel-agnostic consonant skeleton matching R-101."""
    s = norm_scoring(deva_to_latin_approx(text))
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = s.replace("ksh", "x").replace("ph", "f").replace("sh", "s")
    s = s.replace("w", "v").replace("z", "j")
    # Drop aspiration h after consonants
    s = re.sub(r"([bcdfgjklmnpqrstvx])h", r"\1", s)
    # Collapse doubled letters
    s = re.sub(r"(.)\1+", r"\1", s)
    # Strip vowels inside words
    tokens = []
    for tok in s.split():
        sk = re.sub(r"[aeiou]", "", tok)
        tokens.append(sk if sk else tok)
    return " ".join(tokens)


def decode_hidden_payloads(text: str) -> str:
    """Decode base64, hex, \\uXXXX, HTML entities, and %-encoding per SCORING.md:45-46."""
    extras: list[str] = []
    if "&" in text:
        unesc = html.unescape(text)
        if unesc != text:
            extras.append(unesc)
    if "%" in text:
        unq = urllib.parse.unquote(text)
        if unq != text:
            extras.append(unq)
    for m in _UESC_RE.finditer(text):
        try:
            extras.append(m.group(0).encode("ascii").decode("unicode_escape"))
        except UnicodeDecodeError:
            pass
    for m in _B64_RE.finditer(text):
        tok = m.group(0)
        try:
            dec = base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="ignore")
            if dec and sum(ch.isprintable() for ch in dec) >= len(dec) * 0.7:
                extras.append(dec)
        except (binascii.Error, ValueError):
            pass
    for m in _HEX_RE.finditer(text):
        tok = m.group(0)
        try:
            dec = bytes.fromhex(tok).decode("utf-8", errors="ignore")
            if dec and sum(ch.isprintable() for ch in dec) >= len(dec) * 0.8:
                extras.append(dec)
        except ValueError:
            pass
    return text + ("\n" + "\n".join(extras) if extras else "")


def _read_text_with_hidden(path: Path) -> str:
    try:
        raw = path.read_bytes()[:50 * 1024 * 1024]
    except OSError:
        return ""
    return decode_hidden_payloads(raw.decode("utf-8", errors="replace"))


def build_variant_forms(surface: str, include_skeleton: bool = False) -> list[str]:
    """Return normalized variants (exact norm, digits-only if >=6, translit, optional skeleton)."""
    forms: list[str] = []
    ns = norm_scoring(surface)
    if ns:
        forms.append(ns)
    digits = re.sub(r"\D", "", ns)
    if len(digits) >= 6:
        forms.append(digits)
    if any("\u0900" <= ch <= "\u097f" for ch in surface):
        tl = norm_scoring(deva_to_latin_approx(surface))
        if tl and tl not in forms:
            forms.append(tl)
    if include_skeleton:
        sk = consonant_skeleton(surface)
        if len(sk.replace(" ", "")) >= 5 and sk not in forms:
            forms.append(sk)
    return forms


@dataclass
class LeakFinding:
    channel: str
    target_kind: str  # "canary" | "secret" | "pii"
    location: str
    variant: str


@dataclass
class ScanReport:
    canary_hits: int = 0
    secret_hits: int = 0
    pii_hits: int = 0
    channels_clean: dict[str, bool] = field(default_factory=dict)
    leftover_temp_files: list[str] = field(default_factory=list)
    findings: list[LeakFinding] = field(default_factory=list)


def scan_output_tree(
    out_dir: Path,
    canaries: list[str] | None = None,
    secret: str | None = None,
    pii_surfaces: list[str] | None = None,
    stdout_stderr: str = "",
    temp_paths: list[Path] | None = None,
    check_skeleton: bool = True,
) -> ScanReport:
    """Scan all 7 hygiene channels for canary, secret, and optional PII variants."""
    canaries = canaries or []
    pii_surfaces = pii_surfaces or []

    # Collect text blobs per channel
    channel_blobs: dict[str, list[tuple[str, str]]] = {
        "sanitized_content": [],
        "sanitized_filenames": [],
        "report_json": [],
        "records_jsonl": [],
        "logs_and_other": [],
        "stdout_stderr": [],
        "temp_dirs": [],
    }

    san = out_dir / "sanitized"
    if san.is_dir():
        for dp, dn, fn in os.walk(san):
            dn.sort()
            for d in dn:
                rel_d = (Path(dp) / d).relative_to(san).as_posix()
                channel_blobs["sanitized_filenames"].append((rel_d, rel_d))
            for n in sorted(fn):
                fp = Path(dp) / n
                rel_f = fp.relative_to(san).as_posix()
                channel_blobs["sanitized_filenames"].append((rel_f, rel_f))
                channel_blobs["sanitized_content"].append((f"sanitized/{rel_f}", _read_text_with_hidden(fp)))

    rj = out_dir / "report.json"
    if rj.is_file():
        channel_blobs["report_json"].append(("report.json", _read_text_with_hidden(rj)))

    recj = out_dir / "records.jsonl"
    if recj.is_file():
        channel_blobs["records_jsonl"].append(("records.jsonl", _read_text_with_hidden(recj)))

    if out_dir.is_dir():
        for item in sorted(out_dir.rglob("*")):
            rel = item.relative_to(out_dir).as_posix()
            if rel == "sanitized" or rel.startswith("sanitized/") or rel in ("report.json", "records.jsonl"):
                continue
            if item.is_file():
                channel_blobs["logs_and_other"].append((rel, _read_text_with_hidden(item)))
            elif item.is_dir():
                channel_blobs["logs_and_other"].append((rel, rel))

    if stdout_stderr:
        channel_blobs["stdout_stderr"].append(("stdout_stderr", decode_hidden_payloads(stdout_stderr)))

    leftover_temps: list[str] = []
    for tp in temp_paths or []:
        if tp.exists():
            if tp.is_file():
                leftover_temps.append(str(tp))
                channel_blobs["temp_dirs"].append((tp.name, _read_text_with_hidden(tp)))
            elif tp.is_dir():
                for child in sorted(tp.rglob("*")):
                    if child.is_file():
                        leftover_temps.append(str(child))
                        channel_blobs["temp_dirs"].append((child.name, _read_text_with_hidden(child)))

    report = ScanReport(leftover_temp_files=leftover_temps)
    canary_hit_surfaces: set[str] = set()

    # Precompute normalized + skeleton representations of each channel blob
    prepped: dict[str, list[tuple[str, str, str, str]]] = {}
    for ch, items in channel_blobs.items():
        prepped[ch] = [
            (loc, raw, norm_scoring(raw), consonant_skeleton(raw) if check_skeleton else "")
            for loc, raw in items
        ]

    for ch, entries in prepped.items():
        ch_clean = True
        for loc, raw, ntext, sktext in entries:
            digits_only = re.sub(r"\D", "", ntext)
            # 1. Secret check (exact raw and normalized)
            if secret and (secret in raw or norm_scoring(secret) in ntext):
                ch_clean = False
                report.secret_hits += 1
                report.findings.append(LeakFinding(ch, "secret", loc, "<SECRET>"))
            # 2. Canary check
            for can in canaries:
                for var in build_variant_forms(can, include_skeleton=check_skeleton):
                    is_skel = check_skeleton and var == consonant_skeleton(can) and var != norm_scoring(can)
                    hay = sktext if is_skel else (digits_only if var.isdigit() else ntext)
                    if var and (
                        (len(var.split()) > 1 and var in hay)
                        or (len(var.split()) == 1 and len(var) >= 5 and re.search(r"(?<!\w)" + re.escape(var) + r"(?!\w)", hay))
                    ):
                        ch_clean = False
                        canary_hit_surfaces.add(can)
                        report.findings.append(LeakFinding(ch, "canary", loc, var))
                        break
            # 3. Optional PII surface check
            for surf in pii_surfaces:
                for var in build_variant_forms(surf, include_skeleton=False):
                    hay = digits_only if var.isdigit() else ntext
                    if var and var in hay:
                        ch_clean = False
                        report.pii_hits += 1
                        report.findings.append(LeakFinding(ch, "pii", loc, var))
                        break
        if ch == "temp_dirs" and leftover_temps and ch_clean:
            # SCORING.md:125 -> leftover temp files without PII score 0.5, not 1.0
            report.channels_clean[ch] = False
        else:
            report.channels_clean[ch] = ch_clean

    report.canary_hits = len(canary_hit_surfaces)
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Whole-surface leak scanner across 7 channels")
    ap.add_argument("--output", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--secret", default="")
    args = ap.parse_args()
    truth = json.loads(Path(args.truth).read_text(encoding="utf-8"))
    canaries = [
        e["surface"]
        for f in truth["files"].values()
        for u in f["units"].values()
        for e in u["entities"]
        if e.get("type") == "CANARY"
    ]
    rep = scan_output_tree(Path(args.output), canaries=canaries, secret=args.secret or None)
    print(json.dumps({
        "canary_hits": rep.canary_hits,
        "secret_hits": rep.secret_hits,
        "channels_clean": rep.channels_clean,
        "findings_count": len(rep.findings),
    }, indent=2))
    return 0 if (rep.canary_hits == 0 and rep.secret_hits == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
