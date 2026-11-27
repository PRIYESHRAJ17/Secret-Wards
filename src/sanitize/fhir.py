"""FHIR R4 Bundle sanitizer preserving referential integrity while scrubbing Patient, Contact, RelatedPerson, and Base64."""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
from typing import Callable

import regex as re

from src.detect.arbitrate import clean_text_with_arbitration
from src.privacy import band_ages_in_text, dob_to_year, generalize_pin, shift_iso_str
from src.surfaces import decode_and_sanitize_base64

_FHIR_DATE_KEYS = frozenset({
    "lastUpdated", "timestamp", "date", "issued", "onsetDateTime",
    "recordedDate", "effectiveDateTime", "performedDateTime", "authoredOn",
    "start", "end",
})


def _hmac_uuid(psn_key: bytes, raw_id: str) -> str:
    dig = bytearray(hmac.new(psn_key, f"fhir-uuid|{raw_id}".encode("utf-8"), hashlib.sha256).digest()[:16])
    dig[6] = (dig[6] & 0x0F) | 0x40
    dig[8] = (dig[8] & 0x3F) | 0x80
    hx = dig.hex()
    return f"{hx[:8]}-{hx[8:12]}-{hx[12:16]}-{hx[16:20]}-{hx[20:32]}"


def _remap_references(node, id_map: dict[str, str]):
    if isinstance(node, dict):
        if "reference" in node and isinstance(node["reference"], str):
            ref = node["reference"]
            if ref in id_map:
                node["reference"] = id_map[ref]
        for v in node.values():
            _remap_references(v, id_map)
    elif isinstance(node, list):
        for x in node:
            _remap_references(x, id_map)


def _shift_fhir_dates(node, days: int):
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if k in _FHIR_DATE_KEYS and isinstance(v, str) and v:
                node[k] = shift_iso_str(v, days)
            elif isinstance(v, (dict, list)):
                _shift_fhir_dates(v, days)
    elif isinstance(node, list):
        for x in node:
            _shift_fhir_dates(x, days)


def _scrub_fhir_address(addrs: list[dict], pin_dig: int, suppress_dist: bool) -> int:
    hits = 0
    for addr in addrs:
        if not isinstance(addr, dict):
            continue
        if "line" in addr:
            addr["line"] = ["[ADDRESS]"]
            hits += 1
        if "city" in addr:
            addr["city"] = "[VILLAGE]"
            hits += 1
        if "postalCode" in addr and addr["postalCode"]:
            addr["postalCode"] = generalize_pin(str(addr["postalCode"]), prefix_digits=pin_dig)
            hits += 1
        if suppress_dist and "district" in addr:
            addr["district"] = "[REGION]"
    return hits


def _scrub_fhir_telecom(telecoms: list[dict]) -> int:
    hits = 0
    for t in telecoms:
        if isinstance(t, dict) and "value" in t and t["value"]:
            sys_v = str(t.get("system", "")).lower()
            t["value"] = "[EMAIL]" if sys_v == "email" else "[PHONE]"
            hits += 1
    return hits


def sanitize_fhir_bundle(
    bundle: dict,
    rel_out: str,
    psn: str | None,
    psn_key: bytes,
    shift_fn: Callable[[str], int],
    policy: dict,
    extra_tokens: set[str] | None = None,
    privacy_opts: dict | None = None,
) -> tuple[str, list[dict], int, int]:
    """Sanitize a FHIR R4 Bundle safely preserving valid references and clinical resources."""
    doc = copy.deepcopy(bundle)
    opts = privacy_opts or {}
    pin_dig = int(opts.get("pin_prefix_digits", policy.get("pin_prefix_digits", 3)))
    dob_w = int(opts.get("coarsen_dob_width", 5))
    age_w = int(opts.get("age_band_width", policy.get("age_band_years", 5)))
    elderly_open = int(opts.get("elderly_open_band", policy.get("elderly_open_band", 85)))
    suppress_dist = bool(opts.get("suppress_district", False))

    sdays = shift_fn(psn or f"{rel_out}:doc")
    pii_hits = 0
    gen_hits = 0

    # 1. Deterministic UUID/reference remapping across Bundle + Entry resources
    id_map: dict[str, str] = {}
    if doc.get("id"):
        new_bid = _hmac_uuid(psn_key, f"bundle:{doc['id']}")
        doc["id"] = new_bid
        if isinstance(doc.get("identifier"), dict) and "value" in doc["identifier"]:
            doc["identifier"]["value"] = new_bid

    entries = doc.get("entry") or []
    for ent in entries:
        if not isinstance(ent, dict):
            continue
        res = ent.get("resource")
        if not isinstance(res, dict):
            continue
        rt = res.get("resourceType", "Resource")
        old_id = res.get("id")
        if old_id:
            new_id = _hmac_uuid(psn_key, f"{rt}:{old_id}")
            id_map[f"{rt}/{old_id}"] = f"{rt}/{new_id}"
            res["id"] = new_id
        fu = ent.get("fullUrl")
        if isinstance(fu, str) and fu.startswith("urn:uuid:"):
            new_fu = f"urn:uuid:{_hmac_uuid(psn_key, fu)}"
            id_map[fu] = new_fu
            ent["fullUrl"] = new_fu

    _remap_references(doc, id_map)
    _shift_fhir_dates(doc, sdays)

    if isinstance(doc.get("meta"), dict) and isinstance(doc["meta"].get("source"), str):
        doc["meta"]["source"] = "#[ID]"
        pii_hits += 1

    patient_label = psn or "[PERSON]"
    psn_written = False

    def _clean_str(s: str) -> str:
        nonlocal pii_hits, gen_hits
        cleaned, ch = clean_text_with_arbitration(s, extra_tokens=extra_tokens)
        pii_hits += ch
        cleaned, ah = band_ages_in_text(cleaned, width=age_w, elderly_open=elderly_open)
        gen_hits += ah
        return cleaned

    for ent in entries:
        res = ent.get("resource") if isinstance(ent, dict) else None
        if not isinstance(res, dict):
            continue
        rt = res.get("resourceType")

        if rt == "Patient":
            res["name"] = [{"text": patient_label}]
            if psn:
                psn_written = True
            pii_hits += 1
            if isinstance(res.get("identifier"), list):
                for ident in res["identifier"]:
                    if isinstance(ident, dict) and "value" in ident:
                        ident["value"] = psn if psn else "[ID]"
                        if psn:
                            psn_written = True
                        pii_hits += 1
            if isinstance(res.get("telecom"), list):
                pii_hits += _scrub_fhir_telecom(res["telecom"])
            if isinstance(res.get("birthDate"), str) and res["birthDate"]:
                res["birthDate"] = dob_to_year(res["birthDate"], cohort_width=dob_w)
                gen_hits += 1
            if isinstance(res.get("address"), list):
                pii_hits += _scrub_fhir_address(res["address"], pin_dig, suppress_dist)
            if isinstance(res.get("contact"), list):
                for ct in res["contact"]:
                    if not isinstance(ct, dict):
                        continue
                    if "name" in ct:
                        ct["name"] = {"text": "[RELATIVE]"}
                        pii_hits += 1
                    if isinstance(ct.get("telecom"), list):
                        pii_hits += _scrub_fhir_telecom(ct["telecom"])
                    if isinstance(ct.get("address"), dict):
                        pii_hits += _scrub_fhir_address([ct["address"]], pin_dig, suppress_dist)
            if isinstance(res.get("text"), dict) and isinstance(res["text"].get("div"), str):
                cleaned_div = _clean_str(res["text"]["div"])
                if psn and "[PERSON]" in cleaned_div:
                    cleaned_div = cleaned_div.replace("[PERSON]", psn, 1)
                    psn_written = True
                res["text"]["div"] = cleaned_div

        elif rt == "RelatedPerson":
            res["name"] = [{"text": "[RELATIVE]"}]
            pii_hits += 1
            if isinstance(res.get("telecom"), list):
                pii_hits += _scrub_fhir_telecom(res["telecom"])
            if isinstance(res.get("address"), list):
                pii_hits += _scrub_fhir_address(res["address"], pin_dig, suppress_dist)
            if isinstance(res.get("birthDate"), str) and res["birthDate"]:
                res["birthDate"] = dob_to_year(res["birthDate"], cohort_width=dob_w)
                gen_hits += 1

        elif rt == "Encounter":
            if isinstance(res.get("identifier"), list):
                for ident in res["identifier"]:
                    if isinstance(ident, dict) and "value" in ident:
                        ident["value"] = "[ID]"
                        pii_hits += 1

        elif rt == "DocumentReference":
            for ct in res.get("content") or []:
                att = ct.get("attachment") if isinstance(ct, dict) else None
                if isinstance(att, dict) and isinstance(att.get("data"), str) and att["data"]:
                    reenc, is_b64, b_hits = decode_and_sanitize_base64(
                        att["data"],
                        lambda t: clean_text_with_arbitration(t, extra_tokens=extra_tokens),
                    )
                    if is_b64:
                        att["data"] = reenc
                        pii_hits += max(1, b_hits) if b_hits else 0

        # Scrub Patient extensions (e.g. motherName, relative names) and recurse unknown extensions
        if isinstance(res.get("extension"), list):
            for ext_item in res["extension"]:
                if not isinstance(ext_item, dict):
                    continue
                if isinstance(ext_item.get("valueString"), str) and ext_item["valueString"]:
                    url_low = str(ext_item.get("url") or "").lower()
                    if any(w in url_low for w in ("mother", "father", "spouse", "guardian", "kin", "relative", "family", "attendant")):
                        ext_item["valueString"] = "[RELATIVE]"
                        pii_hits += 1
                    else:
                        ext_item["valueString"] = _clean_str(ext_item["valueString"])
                if isinstance(ext_item.get("valueHumanName"), dict):
                    ext_item["valueHumanName"] = {"text": "[RELATIVE]"}
                    pii_hits += 1

        # General subject.display & narrative scrubbing for clinical resources (keep Practitioner/Organization!)
        if isinstance(res.get("subject"), dict) and isinstance(res["subject"].get("display"), str):
            res["subject"]["display"] = patient_label
            if psn:
                psn_written = True
            pii_hits += 1
        if rt not in ("Patient", "RelatedPerson", "Practitioner", "Organization"):
            if isinstance(res.get("text"), dict) and isinstance(res["text"].get("div"), str):
                res["text"]["div"] = _clean_str(res["text"]["div"])
            if isinstance(res.get("note"), list):
                for nitem in res["note"]:
                    if isinstance(nitem, dict) and isinstance(nitem.get("text"), str):
                        nitem["text"] = _clean_str(nitem["text"])

    records = [{"file": rel_out, "loc": "doc", "patient": psn if (psn and psn_written) else None}]
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n", records, pii_hits, gen_hits
