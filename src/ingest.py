"""Deterministic discovery, raw SHA-256, safe decoding, content-first sniffing, and quarantine."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from dataclasses import dataclass
from pathlib import Path

_UNDEF_CP1252 = frozenset({0x81, 0x8D, 0x8F, 0x90, 0x9D})
_BINARY_EXTS = frozenset({
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".xml", ".hl7", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".bin", ".exe", ".dll",
})


@dataclass
class DiscoveredFile:
    rel_path: str
    abs_path: Path
    sha256: str
    raw_bytes: bytes | None = None
    early_quarantine: str | None = None


@dataclass
class IngestedFile:
    rel_path: str
    sha256: str
    fmt: str  # "csv" | "tsv" | "json" | "fhir" | "text"
    delimiter: str | None
    newline_style: str
    text: str
    parsed_json: object | None = None
    csv_rows: list[list[str]] | None = None


@dataclass
class QuarantinedFile:
    rel_path: str
    sha256: str
    reason: str


def discover_files(inp_dir: Path, max_file_bytes: int = 50 * 1024 * 1024) -> list[DiscoveredFile]:
    """Walk input deterministically in sorted relative POSIX order and hash raw bytes."""
    root_resolved = inp_dir.resolve()
    items: list[tuple[str, Path]] = []
    for dp, dn, fn in os.walk(inp_dir, followlinks=False):
        dn.sort()
        for name in sorted(fn):
            p = Path(dp) / name
            rel = p.relative_to(inp_dir).as_posix()
            items.append((rel, p))
    items.sort(key=lambda kv: kv[0].encode("utf-8"))

    out: list[DiscoveredFile] = []
    for rel, p in items:
        if p.is_symlink():
            try:
                target = p.resolve(strict=True)
                target.relative_to(root_resolved)
            except (OSError, ValueError):
                out.append(DiscoveredFile(rel_path=rel, abs_path=p, sha256=hashlib.sha256(rel.encode("utf-8")).hexdigest(), early_quarantine="unsafe_path"))
                continue
        try:
            sz = p.stat().st_size
        except OSError:
            out.append(DiscoveredFile(rel_path=rel, abs_path=p, sha256=hashlib.sha256(rel.encode("utf-8")).hexdigest(), early_quarantine="unreadable_file"))
            continue
        if sz > max_file_bytes:
            h = hashlib.sha256()
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            out.append(DiscoveredFile(rel_path=rel, abs_path=p, sha256=h.hexdigest(), early_quarantine="too_large"))
            continue
        raw = p.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        out.append(DiscoveredFile(rel_path=rel, abs_path=p, sha256=sha, raw_bytes=raw))
    return out


def _looks_like_truncated_utf8_or_corrupt(raw: bytes) -> bool:
    """Reject corrupt byte streams per D-009 (undefined cp1252, 0xFE/0xFF, control chars, truncated UTF-8)."""
    if b"\x00" in raw:
        return True
    non_ascii = 0
    n = len(raw)
    i = 0
    while i < n:
        b = raw[i]
        if b < 0x20 and b not in (9, 10, 13):
            return True
        if b == 0x7F:
            return True
        if b >= 0x80:
            non_ascii += 1
            if b in _UNDEF_CP1252 or b in (0xFE, 0xFF):
                return True
            # Truncated UTF-8 2/3/4-byte lead followed by ASCII (< 0x80)
            if 0xC2 <= b <= 0xF4 and (i + 1 >= n or raw[i + 1] < 0x80):
                return True
        i += 1
    # Legacy cp1252 medical exports only use occasional punctuation/symbols
    if non_ascii > max(20, int(0.05 * n)):
        return True
    return False


def decode_safe(raw: bytes) -> tuple[str | None, str | None]:
    """Losslessly decode UTF-8-BOM, BOM UTF-16, strict UTF-8, or validated cp1252 (D-009)."""
    if not raw or not raw.strip():
        return None, "empty_file"
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            txt = raw[3:].decode("utf-8", errors="strict")
            return (None, "corrupted_encoding") if "\x00" in txt else (txt, None)
        except UnicodeDecodeError:
            return None, "corrupted_encoding"
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        if len(raw) % 2 != 0:
            return None, "corrupted_encoding"
        try:
            txt = raw.decode("utf-16", errors="strict")
            return (None, "corrupted_encoding") if "\x00" in txt else (txt, None)
        except UnicodeDecodeError:
            return None, "corrupted_encoding"
    try:
        txt = raw.decode("utf-8", errors="strict")
        return (None, "corrupted_encoding") if "\x00" in txt else (txt, None)
    except UnicodeDecodeError:
        pass
    if _looks_like_truncated_utf8_or_corrupt(raw):
        return None, "corrupted_encoding"
    try:
        return raw.decode("cp1252", errors="strict"), None
    except UnicodeDecodeError:
        return None, "corrupted_encoding"


def _json_depth_exceeds(text: str, limit: int) -> bool:
    """Iterative structural bracket/brace nesting depth guard (avoids Python RecursionError)."""
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch in "{[":
                depth += 1
                if depth > limit:
                    return True
            elif ch in "}]":
                depth = max(0, depth - 1)
    return False


def ingest_file(df: DiscoveredFile, max_json_depth: int = 100) -> IngestedFile | QuarantinedFile:
    """Sniff content, decode safely, parse structure, or return QuarantinedFile."""
    if df.early_quarantine:
        return QuarantinedFile(df.rel_path, df.sha256, df.early_quarantine)
    raw = df.raw_bytes or b""
    ext = Path(df.rel_path).suffix.lower()
    if ext in _BINARY_EXTS:
        return QuarantinedFile(df.rel_path, df.sha256, "unsupported_format")
    if raw.startswith((b"%PDF", b"\xff\xd8\xff", b"PK\x03\x04", b"\x89PNG")):
        return QuarantinedFile(df.rel_path, df.sha256, "unsupported_format")

    text, dec_err = decode_safe(raw)
    if dec_err or text is None:
        return QuarantinedFile(df.rel_path, df.sha256, dec_err or "corrupted_encoding")

    stripped = text.lstrip()
    if stripped.startswith(("<ClinicalDocument", "<?xml", "<html", "<!DOCTYPE")):
        return QuarantinedFile(df.rel_path, df.sha256, "unsupported_format")

    nl = "\r\n" if "\r\n" in text else "\n"

    # Reject JSON disguised under .csv/.tsv extension (mislabeled_format)
    if ext in (".csv", ".tsv"):
        if stripped.startswith(("{", "[")):
            return QuarantinedFile(df.rel_path, df.sha256, "unsupported_format")
        if ext == ".tsv":
            delim = "\t"
        else:
            # Sniff consistent pipe or semicolon delimiter before defaulting to comma
            first_lines = [ln for ln in text.splitlines()[:5] if ln.strip()]
            delim = ","
            if first_lines:
                for cand in ("|", ";", "\t"):
                    c0 = first_lines[0].count(cand)
                    if c0 >= 2 and all(ln.count(cand) == c0 for ln in first_lines[1:]):
                        delim = cand
                        break
        try:
            rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
        except csv.Error:
            return QuarantinedFile(df.rel_path, df.sha256, "malformed_structure")
        if not rows:
            return QuarantinedFile(df.rel_path, df.sha256, "empty_file")
        ncol = len(rows[0])
        if ncol == 0 or any(len(r) != ncol for r in rows[1:]):
            return QuarantinedFile(df.rel_path, df.sha256, "malformed_structure")
        fmt = "tsv" if delim == "\t" else "csv"
        return IngestedFile(df.rel_path, df.sha256, fmt, delim, nl, text, csv_rows=rows)

    if ext == ".json" or (stripped.startswith(("{", "[")) and ext not in (".txt", ".md", ".log", "")):
        if _json_depth_exceeds(text, max_json_depth):
            return QuarantinedFile(df.rel_path, df.sha256, "too_large")
        try:
            obj = json.loads(text)
        except (ValueError, RecursionError):
            return QuarantinedFile(df.rel_path, df.sha256, "malformed_structure")
        fmt = "fhir" if (isinstance(obj, dict) and obj.get("resourceType") == "Bundle") else "json"
        return IngestedFile(df.rel_path, df.sha256, fmt, None, nl, text, parsed_json=obj)

    if ext in (".txt", ".md", ".log", ""):
        if stripped.startswith(("{", "[")) and not _json_depth_exceeds(text, max_json_depth):
            try:
                obj = json.loads(text)
                if isinstance(obj, (dict, list)):
                    fmt = "fhir" if (isinstance(obj, dict) and obj.get("resourceType") == "Bundle") else "json"
                    return IngestedFile(df.rel_path, df.sha256, fmt, None, nl, text, parsed_json=obj)
            except (ValueError, RecursionError):
                pass
        return IngestedFile(df.rel_path, df.sha256, "text", None, nl, text)

    return QuarantinedFile(df.rel_path, df.sha256, "unsupported_format")
