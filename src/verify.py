"""Post-sanitization verification (R-51): zero-secret, UTF-8, structural, and FHIR checks."""
from __future__ import annotations

import base64
import binascii
import csv
import io
import json

import regex as re

_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_STRONG_SURVIVOR_RE = re.compile(r"(?<!\d)91-\d{4}-\d{4}-\d{4}(?!\d)|\b[A-Z]{5}\d{4}[A-Z]\b|\bPMJAY-[A-Z]{2}-\d{6,12}\b")


def _decode_b64_runs(text: str) -> str:
    extras = []
    for m in _B64_RE.finditer(text):
        tok = m.group(0)
        try:
            extras.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            pass
    return text + "\n" + "\n".join(extras) if extras else text


def _fhir_refs_resolve(obj: dict) -> bool:
    if obj.get("resourceType") != "Bundle" or not isinstance(obj.get("entry"), list):
        return False
    known: set[str] = set()
    for ent in obj["entry"]:
        if not isinstance(ent, dict) or not isinstance(ent.get("resource"), dict):
            return False
        res = ent["resource"]
        if not res.get("resourceType") or not res.get("id"):
            return False
        if ent.get("fullUrl"):
            known.add(str(ent["fullUrl"]))
        known.add(f"{res['resourceType']}/{res['id']}")

    def check(node) -> bool:
        if isinstance(node, dict):
            ref = node.get("reference")
            if isinstance(ref, str) and ref.startswith(("urn:uuid:", "Patient/", "Practitioner/", "Encounter/")):
                if ref not in known:
                    return False
            return all(check(v) for v in node.values())
        if isinstance(node, list):
            return all(check(x) for x in node)
        return True

    return check(obj)


def verify_sanitized_file(
    fmt: str,
    delimiter: str | None,
    expected_rows: int | None,
    expected_cols: int | None,
    out_rel: str,
    content: str,
    secret_bytes: bytes,
) -> tuple[bool, str | None]:
    """Verify sanitized output before writing; return (ok, reason_if_failed)."""
    try:
        raw_utf8 = content.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False, "verification_failed"
    if secret_bytes and (secret_bytes in raw_utf8 or secret_bytes.decode("utf-8", errors="ignore") in out_rel):
        return False, "verification_failed"

    expanded = _decode_b64_runs(content)
    if _STRONG_SURVIVOR_RE.search(expanded) or _STRONG_SURVIVOR_RE.search(out_rel):
        return False, "verification_failed"

    if fmt in ("csv", "tsv") and delimiter:
        try:
            rows = list(csv.reader(io.StringIO(content, newline=""), delimiter=delimiter))
        except csv.Error:
            return False, "verification_failed"
        if expected_rows is not None and len(rows) != expected_rows:
            return False, "verification_failed"
        if expected_cols is not None and (not rows or any(len(r) != expected_cols for r in rows)):
            return False, "verification_failed"

    elif fmt in ("json", "fhir"):
        try:
            obj = json.loads(content)
        except ValueError:
            return False, "verification_failed"
        if fmt == "fhir" and not (isinstance(obj, dict) and _fhir_refs_resolve(obj)):
            return False, "verification_failed"

    return True, None
