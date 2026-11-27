"""Calibrated synthetic hospital dump generator for TRAIN and HELD-OUT-SHIFT splits.

Generates full multi-hospital dumps matching kit/dev/input and kit/dev/truth/truth.json
schemas (raksha-truth/1), plus attacker auxiliary files (registry.csv, known_facts.jsonl),
planted high-entropy canaries across all 7 channels, Challenge-2 meaning traps, twins/homonyms,
cross-script identities, and a format-fuzz suite.
"""
from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import io
import json
import random
import uuid
from pathlib import Path

from tools.gen.pools import (
    DIAGNOSES,
    DOCTORS,
    HELDOUT_CANARIES,
    HELDOUT_PEOPLE_POOL,
    HOSPITALS_HELDOUT,
    HOSPITALS_TRAIN,
    LAB_TESTS,
    LANDMARKS,
    MEDICATIONS,
    MOHALLAS,
    PLACES_HELDOUT,
    PLACES_TRAIN,
    TRAIN_CANARIES,
    TRAIN_PEOPLE_POOL,
)

_DEVANAGARI_DIGITS = str.maketrans("0123456789", "०१२३४५६७८९")
_HINDI_MONTHS = [
    "जनवरी", "फ़रवरी", "मार्च", "अप्रैल", "मई", "जून",
    "जुलाई", "अगस्त", "सितंबर", "अक्टूबर", "नवंबर", "दिसंबर",
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ent(
    etype: str,
    surface: str,
    person: str,
    role: str = "patient",
    script: str = "latin",
    channel: str = "content",
    match: str | None = None,
    critical: bool | None = None,
    canary: bool = False,
) -> dict:
    if match is None:
        if etype in ("PATIENT_NAME", "RELATIVE_NAME", "CANARY"):
            match = "name"
        elif etype in ("AADHAAR", "ABHA_NUMBER", "MRN", "PHONE"):
            match = "digits"
        elif etype == "PIN":
            match = "digits_exact"
        elif etype == "DOB":
            match = "dob"
        else:
            match = "text"
    if critical is None:
        critical = etype in (
            "PATIENT_NAME", "MRN", "PHONE", "AADHAAR", "ABHA_NUMBER",
            "ABHA_ADDRESS", "PAN", "INSURANCE_ID", "EMAIL", "CANARY",
        )
    obj = {
        "type": etype,
        "surface": surface,
        "person": person,
        "role": role,
        "script": script,
        "channel": channel,
        "match": match,
        "critical": critical,
    }
    if canary:
        obj["canary"] = True
    return obj


def _fmt_date(d: dt.date, style: str) -> str:
    if style == "dmy_slash":
        return d.strftime("%d/%m/%Y")
    if style == "mdy_slash":
        return d.strftime("%m/%d/%Y")
    if style == "dmy_dash":
        return d.strftime("%d-%m-%Y")
    if style == "dmy_short":
        return f"{d.day}-{d.month}-{str(d.year)[2:]}"
    if style == "dmy_text":
        return d.strftime("%d %b %Y")
    if style == "hindi_month":
        return f"{d.day} {_HINDI_MONTHS[d.month - 1]} {d.year}"
    if style == "deva_digits":
        return d.strftime("%d/%m/%Y").translate(_DEVANAGARI_DIGITS)
    return d.isoformat()


def _fmt_phone(phone10: str, style: str) -> str:
    if style == "plus91_space":
        return f"+91 {phone10[:5]} {phone10[5:]}"
    if style == "0091":
        return f"0091-{phone10}"
    if style == "paren0":
        return f"(0){phone10[:5]}.{phone10[5:]}"
    if style == "dash":
        return f"{phone10[:5]}-{phone10[5:]}"
    if style == "deva":
        return phone10.translate(_DEVANAGARI_DIGITS)
    return phone10


def _make_fhir_bundle(
    rng: random.Random,
    patient: dict,
    hosp: tuple[str, str],
    doc: tuple[str, str],
    dx: tuple[str, str, bool],
    med: tuple[str, str, str, str],
    adm_date: dt.date,
    dis_date: dt.date,
    att_text: str | None = None,
) -> dict:
    b_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    comp_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    pat_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    prac_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    enc_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    cond_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    med_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))

    entries = [
        {
            "fullUrl": f"urn:uuid:{comp_id}",
            "resource": {
                "resourceType": "Composition",
                "id": comp_id,
                "status": "final",
                "type": {"text": "Discharge summary"},
                "subject": {"reference": f"urn:uuid:{pat_id}", "display": patient["full_name"]},
                "encounter": {"reference": f"urn:uuid:{enc_id}"},
                "date": f"{dis_date.isoformat()}T11:00:00+05:30",
                "author": [{"reference": f"urn:uuid:{prac_id}", "display": doc[0]}],
                "title": "Discharge Summary",
                "section": [
                    {"title": "Diagnosis", "entry": [{"reference": f"urn:uuid:{cond_id}"}]},
                    {"title": "Medications", "entry": [{"reference": f"urn:uuid:{med_id}"}]},
                ],
            },
        },
        {
            "fullUrl": f"urn:uuid:{pat_id}",
            "resource": {
                "resourceType": "Patient",
                "id": pat_id,
                "text": {
                    "status": "generated",
                    "div": (
                        f'<div xmlns="http://www.w3.org/1999/xhtml">'
                        f'{patient["full_name"]}, {patient["age"]} yrs, {patient["gender"]}, {patient["mrn"]}</div>'
                    ),
                },
                "identifier": [
                    {"system": f"https://{hosp[1].lower()}.example/uhid", "value": patient["mrn"]},
                    {"system": "https://healthid.abdm.gov.in", "value": patient["abha"]},
                ],
                "name": [{"text": patient["full_name"], "given": [patient["first"]], "family": patient["last"]}],
                "telecom": [{"system": "phone", "value": f"+91-{patient['phone']}"}],
                "gender": "male" if patient["gender"] == "M" else "female",
                "birthDate": patient["dob"].isoformat(),
                "address": [
                    {
                        "line": [f"H.No. {patient['house']}, {patient['mohalla']}"],
                        "city": patient["village"],
                        "district": patient["district"],
                        "postalCode": patient["pin"],
                    }
                ],
            },
        },
        {
            "fullUrl": f"urn:uuid:{prac_id}",
            "resource": {
                "resourceType": "Practitioner",
                "id": prac_id,
                "name": [{"text": doc[0]}],
                "qualification": [{"code": {"text": doc[1]}}],
            },
        },
        {
            "fullUrl": f"urn:uuid:{enc_id}",
            "resource": {
                "resourceType": "Encounter",
                "id": enc_id,
                "status": "finished",
                "subject": {"reference": f"urn:uuid:{pat_id}"},
                "period": {
                    "start": f"{adm_date.isoformat()}T09:30:00+05:30",
                    "end": f"{dis_date.isoformat()}T11:00:00+05:30",
                },
            },
        },
        {
            "fullUrl": f"urn:uuid:{cond_id}",
            "resource": {
                "resourceType": "Condition",
                "id": cond_id,
                "code": {"coding": [{"system": "http://hl7.org/fhir/sid/icd-10", "code": dx[0], "display": dx[1]}]},
                "subject": {"reference": f"urn:uuid:{pat_id}"},
            },
        },
        {
            "fullUrl": f"urn:uuid:{med_id}",
            "resource": {
                "resourceType": "MedicationRequest",
                "id": med_id,
                "status": "active",
                "intent": "order",
                "medicationCodeableConcept": {"text": f"{med[0]} {med[1]}"},
                "subject": {"reference": f"urn:uuid:{pat_id}"},
                "dosageInstruction": [{"text": f"{med[2]} x {med[3]}"}],
            },
        },
    ]
    if att_text is not None:
        doc_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        b64 = base64.b64encode(att_text.encode("utf-8")).decode("ascii")
        entries.append(
            {
                "fullUrl": f"urn:uuid:{doc_id}",
                "resource": {
                    "resourceType": "DocumentReference",
                    "id": doc_id,
                    "status": "current",
                    "type": {"text": "Referral letter"},
                    "subject": {"reference": f"urn:uuid:{pat_id}"},
                    "content": [{"attachment": {"contentType": "text/plain", "language": "en", "data": b64}}],
                },
            }
        )
    return {
        "resourceType": "Bundle",
        "id": b_id,
        "meta": {"lastUpdated": f"{dis_date.isoformat()}T11:00:00+05:30", "source": f"#{patient['mrn']}"},
        "type": "document",
        "timestamp": f"{dis_date.isoformat()}T11:00:00+05:30",
        "entry": entries,
    }


def generate_dataset(
    out_root: Path,
    seed: str = "train-seed-1",
    split: str = "train",
    shift_axes: bool = False,
    n_patients: int = 24,
) -> dict:
    """Generate a complete synthetic hospital dump + truth.json + attacker files.

    Args:
        out_root: Destination folder (will contain input/, truth/truth.json, attacker/, dataset_manifest.json).
        seed: Deterministic seed string.
        split: "train" or "heldout_shift" (uses strictly disjoint name & place pools).
        shift_axes: If True, shifts headers (Hindi/abbrevs/missing), delimiters, encodings,
                    date formats, ID prefixes, JSON nesting, and evasion shapes.
        n_patients: Number of synthetic patients (default 24; population = 5x).
    """
    rng = random.Random(seed)
    pool = TRAIN_PEOPLE_POOL if split == "train" else HELDOUT_PEOPLE_POOL
    places = PLACES_TRAIN if split == "train" else PLACES_HELDOUT
    canaries = TRAIN_CANARIES if split == "train" else HELDOUT_CANARIES
    hospitals = HOSPITALS_TRAIN if split == "train" else HOSPITALS_HELDOUT

    inp_dir = out_root / "input"
    truth_dir = out_root / "truth"
    att_dir = out_root / "attacker"
    for d in (inp_dir, truth_dir, att_dir):
        d.mkdir(parents=True, exist_ok=True)

    ref_date = dt.date(2026, 11, 20)
    used_phones: set[str] = set()
    used_aadhaar: set[str] = set()

    def gen_phone() -> str:
        while True:
            p = str(rng.choice([6, 7, 8, 9])) + "".join(str(rng.randint(0, 9)) for _ in range(9))
            if p not in used_phones:
                used_phones.add(p)
                return p

    def gen_aadhaar() -> str:
        while True:
            a = str(rng.randint(2, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(11))
            if a not in used_aadhaar:
                used_aadhaar.add(a)
                return a

    patients: list[dict] = []
    # Reserve slot 0 & 1 for homonyms (identical Latin name, different village/age/relative/phone)
    # Slot 2 & 3 for shared-family-phone trap (same phone, different patient, same village)
    # Slot 4 for elderly re-identification trap (rare dx + 88 yrs + stay_days)
    # Slot 5 for fragmented-identity trap ("<first>, W/o <relative>")
    # Slot 6 for language/cross-script trap
    shared_family_phone = gen_phone()
    for idx in range(n_patients):
        if idx == 1:
            base = pool[0]  # Homonym of patient 0!
        else:
            base = pool[idx % len(pool)]
        first, d_first, last, d_last, gender, region = base
        rel_base = pool[(idx + 5) % len(pool)]
        rel_first, d_rel_first, _, _, _, _ = rel_base
        rel_name = f"{rel_first} {last}"
        d_rel_name = f"{d_rel_first} {d_last}"
        rel_type = "S/o" if gender == "M" else ("W/o" if idx % 3 == 0 else "D/o")

        if idx == 4:
            age = 88
        elif idx == 0:
            age = 47
        elif idx == 1:
            age = 31  # distinct age from homonym 0
        else:
            age = rng.randint(18, 78)
        dob = ref_date - dt.timedelta(days=age * 365 + rng.randint(10, 300))

        place_idx = (idx + 2) % len(places) if idx == 1 else idx % len(places)
        district, tehsil, village, d_village, pin_pfx = places[place_idx]
        pin = pin_pfx + f"{rng.randint(100, 999)}"
        house = str(rng.randint(10, 499))
        mohalla = MOHALLAS[idx % len(MOHALLAS)]
        landmark = LANDMARKS[idx % len(LANDMARKS)]

        phone = shared_family_phone if idx in (2, 3) else gen_phone()
        aadhaar = gen_aadhaar()
        abha = f"91-{rng.randint(1000,9999)}-{rng.randint(1000,9999)}-{rng.randint(1000,9999)}"
        abha_addr = f"{first.lower()}.{last.lower()}{rng.randint(10,99)}@abdm"
        pan = "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=5)) + f"{rng.randint(1000,9999)}" + rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        ins_id = f"PMJAY-{split[:2].upper()}-{rng.randint(1000000000, 9999999999)}"
        hosp = hospitals[idx % len(hospitals)]
        mrn = f"{hosp[1]}-26-{100000 + idx}"
        # Shared hospital-local numeric core across different hospitals for idx 7 & 8
        if idx in (7, 8):
            mrn = f"{hospitals[idx - 7][1]}/LOCAL/0042"
        email = f"{first.lower()}.{last.lower()}{idx}@example.org"
        rid = f"REG{split[:2].upper()}{100000 + idx}"

        traps = []
        if idx in (0, 1):
            traps.append("homonym")
        if idx in (2, 3):
            traps.append("shared_family_phone")
        if idx == 4:
            traps.append("reidentification")
        if idx == 5:
            traps.append("fragmented")
        if idx == 6:
            traps.append("language")

        patients.append({
            "pt_id": f"PT{idx:05d}",
            "person_id": f"P{idx:05d}",
            "rid": rid,
            "first": first,
            "last": last,
            "full_name": f"{first} {last}",
            "deva_name": f"{d_first} {d_last}",
            "gender": gender,
            "age": age,
            "dob": dob,
            "rel_type": rel_type,
            "rel_name": rel_name,
            "deva_rel_name": d_rel_name,
            "house": house,
            "mohalla": mohalla,
            "landmark": landmark,
            "village": village,
            "deva_village": d_village,
            "tehsil": tehsil,
            "district": district,
            "pin": pin,
            "phone": phone,
            "aadhaar": aadhaar,
            "abha": abha,
            "abha_addr": abha_addr,
            "pan": pan,
            "ins_id": ins_id,
            "mrn": mrn,
            "hosp": hosp,
            "email": email,
            "region": region,
            "traps": traps,
        })

    # Build population registry (5x patients)
    reg_rows: list[list[str]] = []
    for p in patients:
        has_leaked_contacts = rng.random() < 0.65
        reg_rows.append([
            p["rid"], p["full_name"], p["rel_type"], p["rel_name"], p["gender"], str(p["age"]),
            p["house"], p["mohalla"], p["village"], p["tehsil"], p["district"], p["pin"],
            p["phone"] if has_leaked_contacts else "",
            p["email"] if has_leaked_contacts else "",
            p["aadhaar"][-4:] if has_leaked_contacts else "",
        ])
    # Decoys (non-patients)
    decoy_rids: list[str] = []
    for d_idx in range(n_patients * 4):
        base = pool[(d_idx * 3 + 1) % len(pool)]
        rel_b = pool[(d_idx * 7 + 2) % len(pool)]
        pl = places[(d_idx + 1) % len(places)]
        drid = f"DEC{split[:2].upper()}{200000 + d_idx}"
        decoy_rids.append(drid)
        reg_rows.append([
            drid, f"{base[0]} {base[2]}", "S/o" if base[4] == "M" else "W/o",
            f"{rel_b[0]} {base[2]}", base[4], str(rng.randint(19, 85)),
            str(rng.randint(1, 499)), MOHALLAS[d_idx % len(MOHALLAS)], pl[2], pl[1], pl[0],
            pl[4] + f"{rng.randint(100, 999)}", "", "", "",
        ])
    rng.shuffle(reg_rows)
    reg_buf = io.StringIO()
    rw = csv.writer(reg_buf, lineterminator="\n")
    rw.writerow([
        "rid", "name", "relation", "relative_name", "gender", "age", "house_no",
        "mohalla", "village", "tehsil", "district", "pin", "phone", "email", "aadhaar_last4",
    ])
    rw.writerows(reg_rows)
    (att_dir / "registry.csv").write_bytes(reg_buf.getvalue().encode("utf-8"))

    truth_files: dict[str, dict] = {}
    known_facts: list[dict] = []

    def write_file(rel: str, raw: bytes, fmt: str, enc: str, delim: str | None, expect: str, units: dict):
        fp = inp_dir / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_bytes(raw)
        truth_files[rel] = {
            "sha256": _sha256(raw),
            "encoding": enc,
            "delimiter": delim,
            "format": fmt,
            "expect": expect,
            "units": units,
        }

    # 1. Registration CSV / TSV (shifted headers, delimiters, encodings in shift_axes)
    reg_delim = "|" if shift_axes else ","
    reg_enc = "utf-8-sig"
    reg_date_style = "dmy_text" if shift_axes else "dmy_slash"
    reg_hdr = (
        ["Pat_ID", "Rogi_Naam", "Ling", "Umar", "Janm_Dinank", "Sambandh", "Abhibhavak", "Pata", "Gram", "Zila", "PinCode", "Sampark", "Aadhar_No", "ABHA_ID", "ABHA_Addr", "RegDate"]
        if shift_axes else
        ["UHID", "Patient Name", "Gender", "Age", "DOB", "Relation", "Relative Name", "Address", "Village/Mohalla", "District", "PIN", "Mobile", "Aadhaar No", "ABHA No", "ABHA Address", "Reg Date"]
    )
    csv_buf = io.StringIO()
    cw = csv.writer(csv_buf, delimiter=reg_delim, lineterminator="\r\n" if shift_axes else "\n")
    cw.writerow(reg_hdr)
    reg_units: dict[str, dict] = {}
    for row_i, p in enumerate(patients):
        reg_dt = ref_date - dt.timedelta(days=rng.randint(30, 300))
        ph_fmt = _fmt_phone(p["phone"], "0091" if shift_axes else "plus91_space")
        name_val = f"{p['last']}, {p['first']}" if (shift_axes and row_i % 2 == 0) else p["full_name"]
        addr_val = f"H.No. {p['house']}, {p['mohalla']}, {p['landmark']}"
        row_vals = [
            p["mrn"], name_val, p["gender"], str(p["age"]), _fmt_date(p["dob"], reg_date_style),
            p["rel_type"], p["rel_name"], addr_val, p["village"], p["district"], p["pin"],
            ph_fmt, p["aadhaar"], p["abha"], p["abha_addr"], _fmt_date(reg_dt, reg_date_style),
        ]
        if shift_axes:
            # Swap first two columns in shifted variant
            row_vals[0], row_vals[1] = row_vals[1], row_vals[0]
        cw.writerow(row_vals)
        reg_units[f"row:{row_i}"] = {
            "loc": f"row:{row_i}",
            "patient": p["pt_id"],
            "cid": f"{p['pt_id']}#0",
            "link": "required",
            "tags": ["shifted_layout"] if shift_axes else [],
            "entities": [
                _ent("MRN", p["mrn"], p["person_id"]),
                _ent("PATIENT_NAME", name_val, p["person_id"]),
                _ent("DOB", _fmt_date(p["dob"], reg_date_style), p["person_id"]),
                _ent("RELATIVE_NAME", p["rel_name"], p["person_id"], role="relative"),
                _ent("HOUSE", f"H.No. {p['house']}", p["person_id"]),
                _ent("LOCALITY", p["mohalla"], p["person_id"]),
                _ent("LANDMARK", p["landmark"], p["person_id"]),
                _ent("VILLAGE", p["village"], p["person_id"]),
                _ent("PIN", p["pin"], p["person_id"]),
                _ent("PHONE", ph_fmt, p["person_id"]),
                _ent("AADHAAR", p["aadhaar"], p["person_id"]),
                _ent("ABHA_NUMBER", p["abha"], p["person_id"]),
                _ent("ABHA_ADDRESS", p["abha_addr"], p["person_id"]),
            ],
            "preserve": [{"text": p["district"], "kind": "district", "weight": 0.3}],
            "dates": [{"true": reg_dt.isoformat(), "event": "registration", "patient": p["pt_id"], "hint": "dmy", "path": "col:RegDate"}],
            "fields": [
                {"kind": "age", "true": p["age"], "patient": p["pt_id"]},
                {"kind": "gender", "true": p["gender"], "patient": p["pt_id"]},
                {"kind": "dob", "true": p["dob"].isoformat(), "patient": p["pt_id"]},
                {"kind": "district", "true": p["district"].lower(), "patient": p["pt_id"]},
                {"kind": "pin", "true": p["pin"], "patient": p["pt_id"]},
            ],
        }
    if shift_axes:
        # Swap header labels to match row swap
        reg_hdr_final = list(reg_hdr)
        reg_hdr_final[0], reg_hdr_final[1] = reg_hdr_final[1], reg_hdr_final[0]
        lines = csv_buf.getvalue().splitlines(keepends=True)
        hbuf = io.StringIO()
        csv.writer(hbuf, delimiter=reg_delim, lineterminator="\r\n").writerow(reg_hdr_final)
        reg_bytes = b"\xef\xbb\xbf" + (hbuf.getvalue() + "".join(lines[1:])).encode("utf-8")
        reg_rel = "registration/shifted_registry.csv"
    else:
        reg_bytes = b"\xef\xbb\xbf" + csv_buf.getvalue().encode("utf-8")
        reg_rel = "registration/hospital_main.csv"
    write_file(reg_rel, reg_bytes, "csv", reg_enc, reg_delim, "sanitize", reg_units)

    # 2. Legacy cp1252 CSV with MM/DD/YYYY dates + UTF-16 TSV with Hindi/Devanagari rows
    cp_buf = io.StringIO()
    cpw = csv.writer(cp_buf, delimiter=",", lineterminator="\r\n")
    cpw.writerow(["PatientID", "LastName", "FirstName", "Sex", "DOB (MM/DD/YYYY)", "Registered (MM/DD/YYYY)", "Phone", "Notes"])
    cp_units: dict[str, dict] = {}
    for ri, p in enumerate(patients[:6]):
        rdt = ref_date - dt.timedelta(days=20 + ri * 7)
        ph = _fmt_phone(p["phone"], "dash")
        cpw.writerow([
            p["mrn"], p["last"], p["first"], p["gender"],
            _fmt_date(p["dob"], "mdy_slash"), _fmt_date(rdt, "mdy_slash"), ph,
            "Temp 101.2\u00b0F on arrival \u2013 C/O fever x 3 days",
        ])
        cp_units[f"row:{ri}"] = {
            "loc": f"row:{ri}",
            "patient": p["pt_id"],
            "cid": f"{p['pt_id']}#0",
            "link": "required",
            "tags": ["mdy_dates"],
            "entities": [
                _ent("MRN", p["mrn"], p["person_id"]),
                _ent("PATIENT_NAME", p["last"], p["person_id"], critical=False),
                _ent("PATIENT_NAME", p["first"], p["person_id"], critical=False),
                _ent("DOB", _fmt_date(p["dob"], "mdy_slash"), p["person_id"]),
                _ent("PHONE", ph, p["person_id"]),
            ],
            "preserve": [{"text": "C/O fever x 3 days", "kind": "complaint", "weight": 1.0, "trap": "c/o-complaint"}],
            "dates": [{"true": rdt.isoformat(), "event": "registration:mdy", "patient": p["pt_id"], "hint": "mdy", "path": "col:Registered"}],
            "fields": [{"kind": "gender", "true": p["gender"], "patient": p["pt_id"]}],
        }
    write_file("registration/legacy_mdy.csv", cp_buf.getvalue().encode("cp1252"), "csv", "cp1252", ",", "sanitize", cp_units)

    tsv_buf = io.StringIO()
    tw = csv.writer(tsv_buf, delimiter="\t", lineterminator="\n")
    tw.writerow(["Reg No", "Naam", "Ling", "Umar", "Gaon", "Mobile No", "Date"])
    tsv_units: dict[str, dict] = {}
    for ri, p in enumerate(patients[6:14]):
        rdt = ref_date - dt.timedelta(days=15 + ri * 5)
        ph_deva = _fmt_phone(p["phone"], "deva")
        tw.writerow([p["mrn"], p["deva_name"], p["gender"], str(p["age"]), p["deva_village"], ph_deva, _fmt_date(rdt, "dmy_dash")])
        tsv_units[f"row:{ri}"] = {
            "loc": f"row:{ri}",
            "patient": p["pt_id"],
            "cid": f"{p['pt_id']}#0",
            "link": "required",
            "tags": ["hindi"],
            "entities": [
                _ent("MRN", p["mrn"], p["person_id"]),
                _ent("PATIENT_NAME", p["deva_name"], p["person_id"], script="deva"),
                _ent("VILLAGE", p["deva_village"], p["person_id"], script="deva"),
                _ent("PHONE", ph_deva, p["person_id"], script="deva"),
            ],
            "preserve": [],
            "dates": [{"true": rdt.isoformat(), "event": "registration:tsv", "patient": p["pt_id"], "hint": "dmy", "path": "col:Date"}],
            "fields": [{"kind": "age", "true": p["age"], "patient": p["pt_id"]}],
        }
    write_file("registration/deva_patients.tsv", tsv_buf.getvalue().encode("utf-16"), "tsv", "utf-16", "\t", "sanitize", tsv_units)

    # 3. Nested JSON with integer Aadhaar, \u09XX escapes, metadata PII, and dynamic JSON keys
    opd_visits = []
    opd_units: dict[str, dict] = {}
    for vi, p in enumerate(patients[:8]):
        vdate = ref_date - dt.timedelta(days=10 + vi * 4)
        dx = DIAGNOSES[vi % len(DIAGNOSES)]
        med = MEDICATIONS[vi % len(MEDICATIONS)]
        doc = DOCTORS[vi % len(DOCTORS)]
        opd_visits.append({
            "visit_id": f"OPD-{2000 + vi}",
            "patient_ref": p["mrn"],
            "patient_name": p["deva_name"] if shift_axes else p["full_name"],
            "aadhar_no": int(p["aadhaar"]),
            "visit_date": vdate.isoformat(),
            "doctor": doc[0],
            "complaints": f"C/O fever x 4 days; {dx[1]}",
            "prescription": f"Tab {med[0]} {med[1]} {med[2]} x {med[3]}",
        })
        opd_units[f"/visits/{vi}"] = {
            "loc": f"/visits/{vi}",
            "patient": p["pt_id"],
            "cid": f"{p['pt_id']}#0",
            "link": "required",
            "tags": ["numeric_aadhaar"],
            "entities": [
                _ent("MRN", p["mrn"], p["person_id"]),
                _ent("PATIENT_NAME", p["deva_name"] if shift_axes else p["full_name"], p["person_id"], script="deva" if shift_axes else "latin"),
                _ent("AADHAAR", p["aadhaar"], p["person_id"]),
            ],
            "preserve": [
                {"text": doc[0], "kind": "doctor", "weight": 0.5, "trap": "doctor"},
                {"text": dx[1], "kind": "diagnosis", "weight": 1.0},
                {"text": f"{med[0]} {med[1]}", "kind": "medication", "weight": 1.0},
                {"text": med[2], "kind": "frequency", "weight": 1.0, "trap": "1-0-1"},
            ],
            "dates": [{"true": vdate.isoformat(), "event": f"opd:{vi}", "patient": p["pt_id"], "hint": "iso", "path": "/visit_date"}],
            "fields": [],
        }
    c0_first, _, c0_last, _ = canaries[0]
    opd_obj = {
        "_export_meta": {
            "source_path": f"D:\\HIS\\exports\\{c0_first}_{c0_last}_998877\\visits.json",
            "hospital": hospitals[0][0],
        },
        "visits": opd_visits,
    }
    opd_units["@file"] = {
        "loc": "@file",
        "patient": None,
        "cid": None,
        "link": "none",
        "tags": ["meta_source"],
        "entities": [_ent("CANARY", f"{c0_first}_{c0_last}", "CANARY-0", channel="metadata", canary=True)],
        "preserve": [{"text": hospitals[0][0], "kind": "hospital", "weight": 0.3}],
        "dates": [],
        "fields": [],
    }
    # Use ensure_ascii=True to exercise \u09XX Devanagari escapes in JSON
    write_file(
        "opd/visits_escaped.json",
        (json.dumps(opd_obj, ensure_ascii=True, indent=2) + "\n").encode("utf-8"),
        "json", "utf-8", None, "sanitize", opd_units,
    )

    # JSON keyed by canary name & MRN
    c1_first, c1_dfirst, c1_last, c1_dlast = canaries[1]
    key_obj = {
        "generated": ref_date.isoformat(),
        "by_name": {f"{c1_first} {c1_last}": {"visits": 2, "ward": "Ward 3"}},
    }
    write_file(
        "misc/patient_index.json",
        (json.dumps(key_obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        "json", "utf-8", None, "sanitize",
        {
            "@file": {
                "loc": "@file", "patient": None, "cid": None, "link": "none", "tags": ["json_key_canary"],
                "entities": [_ent("CANARY", f"{c1_first} {c1_last}", "CANARY-1", channel="key", canary=True)],
                "preserve": [{"text": "Ward 3", "kind": "ward", "weight": 0.3, "trap": "hospital-ward"}],
                "dates": [], "fields": [],
            }
        },
    )

    # 4. FHIR R4 Bundles (including rare-dx elderly re-ID target & base64 attachment)
    for fi, p in enumerate(patients[:6]):
        adm = ref_date - dt.timedelta(days=40 - fi * 3)
        stay = 9 if fi == 4 else (4 + fi)
        dis = adm + dt.timedelta(days=stay)
        dx = DIAGNOSES[5] if fi == 4 else DIAGNOSES[fi % 5]
        med = MEDICATIONS[fi % len(MEDICATIONS)]
        doc = DOCTORS[fi % len(DOCTORS)]
        att = f"Referral for {p['full_name']} ({p['mrn']}). Continue {med[0]} {med[1]}." if fi == 0 else None
        bundle = _make_fhir_bundle(rng, p, p["hosp"], doc, dx, med, adm, dis, att_text=att)
        f_ents = [
            _ent("PATIENT_NAME", p["full_name"], p["person_id"]),
            _ent("MRN", p["mrn"], p["person_id"]),
            _ent("ABHA_NUMBER", p["abha"], p["person_id"]),
            _ent("PHONE", f"+91-{p['phone']}", p["person_id"]),
            _ent("DOB", p["dob"].isoformat(), p["person_id"]),
            _ent("HOUSE", f"H.No. {p['house']}", p["person_id"]),
            _ent("LOCALITY", p["mohalla"], p["person_id"]),
            _ent("VILLAGE", p["village"], p["person_id"]),
            _ent("PIN", p["pin"], p["person_id"]),
        ]
        if att is not None:
            f_ents.append(_ent("PATIENT_NAME", p["full_name"], p["person_id"], channel="base64"))
        write_file(
            f"fhir/bundle_{fi:03d}.json",
            (json.dumps(bundle, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
            "fhir", "utf-8", None, "sanitize",
            {
                "doc": {
                    "loc": "doc",
                    "patient": p["pt_id"],
                    "cid": f"{p['pt_id']}#0",
                    "link": "required",
                    "tags": ["fhir"] + (["reid_trap"] if fi == 4 else []),
                    "entities": f_ents,
                    "preserve": [
                        {"text": doc[0], "kind": "doctor", "weight": 0.5, "trap": "doctor"},
                        {"text": dx[1], "kind": "diagnosis", "weight": 1.0},
                        {"text": dx[0], "kind": "diagnosis_code", "weight": 1.0},
                        {"text": f"{med[0]} {med[1]}", "kind": "medication", "weight": 1.0},
                        {"text": p["district"], "kind": "district", "weight": 0.3},
                    ],
                    "dates": [
                        {"true": adm.isoformat(), "event": "admission", "patient": p["pt_id"], "hint": "iso", "path": "/entry/3/resource/period/start"},
                        {"true": dis.isoformat(), "event": "discharge", "patient": p["pt_id"], "hint": "iso", "path": "/entry/3/resource/period/end"},
                    ],
                    "fields": [
                        {"kind": "age", "true": p["age"], "patient": p["pt_id"]},
                        {"kind": "gender", "true": p["gender"], "patient": p["pt_id"]},
                        {"kind": "dob", "true": p["dob"].isoformat(), "patient": p["pt_id"]},
                        {"kind": "district", "true": p["district"].lower(), "patient": p["pt_id"]},
                        {"kind": "pin", "true": p["pin"], "patient": p["pt_id"]},
                    ],
                }
            },
        )
        known_facts.append({
            "rid": p["rid"],
            "visit_dates": [adm.isoformat()],
            "hospital": p["hosp"][0],
            "stay_days": stay,
            **({"condition_hint": dx[1]} if fi in (4, 0, 1) else {}),
        })

    # Add decoy known_facts
    for drid in decoy_rids[:4]:
        known_facts.append({
            "rid": drid,
            "visit_dates": [(ref_date - dt.timedelta(days=rng.randint(10, 90))).isoformat()],
            "hospital": hospitals[0][0],
        })

    # 5. Free-text notes: Hinglish meaning traps, Devanagari language trap, fragmented note, canary filename & dir, WhatsApp forward
    # 5a. Meaning traps + Hinglish
    p_m = patients[min(4, len(patients) - 1)]
    doc_m = DOCTORS[0]
    note_meaning = (
        f"NURSING NOTE - Ward 5 (Medicine), Bed 12, Room 101\n"
        f"{p_m['first']} sahab ka BP 150/90, SpO2 97%, Hb 11.2 g/dL.\n"
        f"{doc_m[0]} advised Tab Pan-D 40 OD, Dolo 650 BD x 5 days, Inj Insulin 10 IU.\n"
        f"C/O fever x 3 days. K/C/O Parkinson's disease. H/o DM. R/o dengue.\n"
        f"Attendant C/O {p_m['rel_name']} ({p_m['rel_type']} {p_m['rel_name']}).\n"
    )
    write_file(
        "notes/meaning_trap_ward5.txt",
        note_meaning.encode("utf-8"), "text", "utf-8", None, "sanitize",
        {
            "doc": {
                "loc": "doc", "patient": p_m["pt_id"], "cid": f"{p_m['pt_id']}#0", "link": "required",
                "tags": ["meaning_trap"],
                "entities": [
                    _ent("PATIENT_NAME", p_m["first"], p_m["person_id"], script="hinglish", critical=False),
                    _ent("RELATIVE_NAME", p_m["rel_name"], p_m["person_id"], role="relative"),
                ],
                "preserve": [
                    {"text": doc_m[0], "kind": "doctor", "weight": 0.5, "trap": "doctor"},
                    {"text": "C/O fever x 3 days", "kind": "complaint", "weight": 1.0, "trap": "c/o-complaint"},
                    {"text": "K/C/O Parkinson's disease", "kind": "history", "weight": 1.0, "trap": "k/c/o"},
                    {"text": "Parkinson's disease", "kind": "eponym", "weight": 1.0, "trap": "eponym"},
                    {"text": "H/o DM", "kind": "history", "weight": 1.0, "trap": "h/o"},
                    {"text": "Dolo 650 BD x 5 days", "kind": "medication", "weight": 1.0, "trap": "dose"},
                    {"text": "Ward 5 (Medicine)", "kind": "ward", "weight": 1.0, "trap": "hospital-ward"},
                    {"text": "BP 150/90", "kind": "vital", "weight": 1.0},
                    {"text": "Hb 11.2 g/dL", "kind": "lab", "weight": 1.0},
                ],
                "dates": [], "fields": [],
            }
        },
    )

    # 5b. Fragmented identity trap ("<first>, W/o <rel>")
    if len(patients) > 5:
        p_f = patients[5]
        fdate = ref_date - dt.timedelta(days=25)
        frag_txt = (
            f"Discharge note\n"
            f"{p_f['first']}, {p_f['rel_type']} {p_f['rel_name']}, stable.\n"
            f"Visit: {_fmt_date(fdate, 'hindi_month' if shift_axes else 'dmy_text')}\n"
            f"Diagnosis: Essential (primary) hypertension. Tab Amlodipine 5 mg 0-0-1.\n"
        )
        write_file(
            "discharge/frag_note.txt",
            frag_txt.encode("utf-8"), "text", "utf-8", None, "sanitize",
            {
                "doc": {
                    "loc": "doc", "patient": p_f["pt_id"], "cid": f"{p_f['pt_id']}#0", "link": "required",
                    "tags": ["frag_trap"],
                    "entities": [
                        _ent("PATIENT_NAME", p_f["first"], p_f["person_id"], critical=False),
                        _ent("RELATIVE_NAME", p_f["rel_name"], p_f["person_id"], role="relative"),
                    ],
                    "preserve": [{"text": "0-0-1", "kind": "frequency", "weight": 1.0, "trap": "1-0-1"}],
                    "dates": [{"true": fdate.isoformat(), "event": "frag_visit", "patient": p_f["pt_id"], "hint": "dmy", "path": None}],
                    "fields": [],
                }
            },
        )

    # 5c. Devanagari canary inside directory name + filename + CSV header + base64 attachment
    c2_first, c2_dfirst, c2_last, c2_dlast = canaries[2]
    c3_first, c3_dfirst, c3_last, c3_dlast = canaries[3]
    can_dir_rel = f"discharge/{c2_first}_{c2_last}_dir/{c2_first}_{c2_last}_summary.txt"
    write_file(
        can_dir_rel,
        f"Patient: {c2_dfirst} {c2_dlast}\nDiagnosis: Dengue fever\n".encode("utf-8"),
        "text", "utf-8", None, "sanitize",
        {
            "@filename": {
                "loc": "@filename", "patient": None, "cid": None, "link": "none", "tags": ["canary_filename"],
                "entities": [_ent("CANARY", f"{c2_first}_{c2_last}", "CANARY-2", channel="filename", canary=True)],
                "preserve": [], "dates": [], "fields": [],
            },
            "doc": {
                "loc": "doc", "patient": None, "cid": None, "link": "none", "tags": ["canary_deva"],
                "entities": [_ent("CANARY", f"{c2_dfirst} {c2_dlast}", "CANARY-2", script="deva", canary=True)],
                "preserve": [{"text": "Dengue fever", "kind": "diagnosis", "weight": 1.0}],
                "dates": [], "fields": [],
            },
        },
    )

    # Canary inside CSV header & base64 JSON attachment
    hdr_csv = f"time,{c3_first} {c3_last}\n08:00,BP 120/80\n".encode("utf-8")
    write_file(
        "misc/vitals_header_canary.csv", hdr_csv, "csv", "utf-8", ",", "sanitize",
        {
            "@header": {
                "loc": "@header", "patient": None, "cid": None, "link": "none", "tags": ["canary_header"],
                "entities": [_ent("CANARY", f"{c3_first} {c3_last}", "CANARY-3", channel="header", canary=True)],
                "preserve": [], "dates": [], "fields": [],
            },
            "row:0": {"loc": "row:0", "patient": None, "cid": None, "link": "none", "tags": [], "entities": [], "preserve": [{"text": "BP 120/80", "kind": "vital", "weight": 1.0}], "dates": [], "fields": []},
        },
    )

    # Billing CSV (PAN, INSURANCE_ID, AADHAAR_MASKED, EMAIL)
    bill_buf = io.StringIO()
    bw = csv.writer(bill_buf, lineterminator="\n")
    bw.writerow(["bill_no", "uhid", "patient_name", "pmjay_id", "payer_pan", "masked_aadhaar", "email", "procedure", "amount_inr"])
    bill_units: dict[str, dict] = {}
    for bi, p in enumerate(patients[:4]):
        masked_aa = f"XXXX XXXX {p['aadhaar'][-4:]}"
        bw.writerow([f"BILL-{100 + bi}", p["mrn"], p["full_name"], p["ins_id"], p["pan"], masked_aa, p["email"], "Haemodialysis session", "15000"])
        bill_units[f"row:{bi}"] = {
            "loc": f"row:{bi}", "patient": p["pt_id"], "cid": f"{p['pt_id']}#0", "link": "required", "tags": [],
            "entities": [
                _ent("MRN", p["mrn"], p["person_id"]),
                _ent("PATIENT_NAME", p["full_name"], p["person_id"]),
                _ent("INSURANCE_ID", p["ins_id"], p["person_id"]),
                _ent("PAN", p["pan"], p["person_id"]),
                _ent("AADHAAR_MASKED", masked_aa, p["person_id"]),
                _ent("EMAIL", p["email"], p["person_id"]),
            ],
            "preserve": [
                {"text": "Haemodialysis session", "kind": "procedure", "weight": 1.0},
                {"text": "15000", "kind": "amount", "weight": 0.5},
            ],
            "dates": [], "fields": [],
        }
    write_file("billing/claims.csv", bill_buf.getvalue().encode("utf-8"), "csv", "utf-8", ",", "sanitize", bill_units)

    # Non-canary hidden channels: filename (discharge + lab), metadata, key, header
    p_fn = patients[2]
    write_file(
        f"discharge/Discharge_Summary_{p_fn['first']}_{p_fn['last']}_{p_fn['mrn']}.txt",
        f"Summary for {p_fn['full_name']} ({p_fn['mrn']}).\nDiagnosis: Dengue fever.\n".encode("utf-8"),
        "text", "utf-8", None, "sanitize",
        {
            "@filename": {
                "loc": "@filename", "patient": None, "cid": None, "link": "none", "tags": [],
                "entities": [
                    _ent("PATIENT_NAME", f"{p_fn['first']}_{p_fn['last']}", p_fn["person_id"], channel="filename"),
                    _ent("MRN", p_fn["mrn"], p_fn["person_id"], channel="filename"),
                ],
                "preserve": [], "dates": [], "fields": [],
            },
            "doc": {
                "loc": "doc", "patient": p_fn["pt_id"], "cid": f"{p_fn['pt_id']}#0", "link": "required", "tags": [],
                "entities": [
                    _ent("PATIENT_NAME", p_fn["full_name"], p_fn["person_id"]),
                    _ent("MRN", p_fn["mrn"], p_fn["person_id"]),
                ],
                "preserve": [{"text": "Dengue fever", "kind": "diagnosis", "weight": 1.0}],
                "dates": [], "fields": [],
            },
        },
    )
    lab_fn_obj = {"patient": p_fn["full_name"], "test": "Haemoglobin", "result": "11.2 g/dL"}
    write_file(
        f"lab/{p_fn['phone']}_report_001.json",
        (json.dumps(lab_fn_obj, indent=2) + "\n").encode("utf-8"),
        "json", "utf-8", None, "sanitize",
        {
            "@filename": {
                "loc": "@filename", "patient": None, "cid": None, "link": "none", "tags": [],
                "entities": [_ent("PHONE", p_fn["phone"], p_fn["person_id"], channel="filename")],
                "preserve": [], "dates": [], "fields": [],
            },
            "doc": {
                "loc": "doc", "patient": p_fn["pt_id"], "cid": f"{p_fn['pt_id']}#0", "link": "required", "tags": [],
                "entities": [_ent("PATIENT_NAME", p_fn["full_name"], p_fn["person_id"])],
                "preserve": [{"text": "Haemoglobin", "kind": "lab_test", "weight": 1.0}],
                "dates": [], "fields": [],
            },
        },
    )
    p_hd = patients[3]
    write_file(
        "misc/ward_vitals_sheet.csv",
        f"time,{p_hd['mrn']} {p_hd['first']}\n08:00,BP 120/80 mmHg\n".encode("utf-8"),
        "csv", "utf-8", ",", "sanitize",
        {
            "@header": {
                "loc": "@header", "patient": None, "cid": None, "link": "none", "tags": [],
                "entities": [
                    _ent("MRN", p_hd["mrn"], p_hd["person_id"], channel="header"),
                    _ent("PATIENT_NAME", p_hd["first"], p_hd["person_id"], channel="header"),
                ],
                "preserve": [], "dates": [], "fields": [],
            },
            "row:0": {"loc": "row:0", "patient": None, "cid": None, "link": "none", "tags": [], "entities": [], "preserve": [{"text": "BP 120/80 mmHg", "kind": "vital", "weight": 1.0}], "dates": [], "fields": []},
        },
    )
    write_file(
        "misc/patient_lookup_keys.json",
        (json.dumps({"by_uhid": {p_hd["mrn"]: {"visits": 1}}, "by_name": {p_hd["full_name"]: {"visits": 1}}}, indent=2) + "\n").encode("utf-8"),
        "json", "utf-8", None, "sanitize",
        {
            "@file": {
                "loc": "@file", "patient": None, "cid": None, "link": "none", "tags": [],
                "entities": [
                    _ent("MRN", p_hd["mrn"], p_hd["person_id"], channel="key"),
                    _ent("PATIENT_NAME", p_hd["full_name"], p_hd["person_id"], channel="key"),
                ],
                "preserve": [], "dates": [], "fields": [],
            }
        },
    )
    write_file(
        "opd/meta_only_export.json",
        (json.dumps({"_export_meta": {"source_path": f"D:\\HIS\\{p_hd['first']}_{p_hd['last']}_{p_hd['mrn']}.json"}, "visits": [{"visit_id": "V-1", "complaints": "C/O fever"}]}, indent=2) + "\n").encode("utf-8"),
        "json", "utf-8", None, "sanitize",
        {
            "@file": {
                "loc": "@file", "patient": None, "cid": None, "link": "none", "tags": [],
                "entities": [
                    _ent("PATIENT_NAME", f"{p_hd['first']}_{p_hd['last']}", p_hd["person_id"], channel="metadata"),
                    _ent("MRN", p_hd["mrn"], p_hd["person_id"], channel="metadata"),
                ],
                "preserve": [], "dates": [], "fields": [],
            },
            "/visits/0": {"loc": "/visits/0", "patient": p_hd["pt_id"], "cid": f"{p_hd['pt_id']}#0", "link": "required", "tags": [], "entities": [], "preserve": [], "dates": [], "fields": []},
        },
    )

    # Clean ASHA protocol file (no PII; tests asha trap + token_retention)
    clean_txt = (
        "DENGUE PROTOCOL\n"
        "ASHA workers must refer patients with platelet count below 20000 /uL.\n"
        "Use ICD-10 A90 and LOINC 777-3.\n"
    )
    write_file(
        "clean/protocol.txt", clean_txt.encode("utf-8"), "text", "utf-8", None, "sanitize",
        {
            "doc": {
                "loc": "doc", "patient": None, "cid": None, "link": "none", "tags": [],
                "entities": [],
                "preserve": [
                    {"text": "ASHA workers", "kind": "context", "weight": 1.0, "trap": "asha"},
                    {"text": "ICD-10", "kind": "context", "weight": 1.0},
                    {"text": "LOINC", "kind": "context", "weight": 1.0},
                ],
                "dates": [], "fields": [],
            }
        },
    )

    # 6. Malformed / unsupported files (expect="either")
    p_mal = patients[0]
    fuzz_specs = [
        ("misc/empty_export.csv", b"", "csv"),
        ("misc/truncated_opd.json", f'{{"visits": [{{"patient": "{p_mal["full_name"]}"'.encode("utf-8"), "json"),
        ("misc/corrupt_bytes_note.txt", f"Note {p_mal['full_name']}. ".encode("utf-8") + b"\xff\xfe\xc3(" + b" C/O cough.\r\n", "text"),
        ("misc/hl7_cda.xml", f"<ClinicalDocument><name>{p_mal['full_name']}</name></ClinicalDocument>".encode("utf-8"), "xml"),
        ("misc/photo_rx.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + p_mal["full_name"].encode("utf-8"), "binary"),
        ("misc/scanned.pdf", b"%PDF-1.4\n" + p_mal["full_name"].encode("utf-8") + b"\n%%EOF", "pdf"),
        ("misc/mislabeled.csv", json.dumps({"patient": p_mal["full_name"], "aadhaar": p_mal["aadhaar"]}).encode("utf-8"), "json"),
    ]
    for frel, fbytes, ffmt in fuzz_specs:
        ents = [] if not fbytes else [_ent("PATIENT_NAME", p_mal["full_name"], p_mal["person_id"])]
        units = {} if not fbytes else {"@file": {"loc": "@file", "patient": None, "cid": None, "link": "none", "tags": [], "entities": ents, "preserve": [], "dates": [], "fields": []}}
        write_file(frel, fbytes, ffmt, "utf-8", "," if ffmt == "csv" else None, "either", units)

    # Write known_facts.jsonl
    (att_dir / "known_facts.jsonl").write_text(
        "\n".join(json.dumps(k, ensure_ascii=False) for k in known_facts) + "\n",
        encoding="utf-8",
    )

    truth_obj = {
        "schema": "raksha-truth/1",
        "generator_version": "1.0.0",
        "seed": seed,
        "profile": "small",
        "chaos": shift_axes,
        "ref_date": ref_date.isoformat(),
        "files": truth_files,
        "patients": {
            p["pt_id"]: {"rid": p["rid"], "pid": p["person_id"], "hospitals": [p["hosp"][1].lower()], "traps": p["traps"]}
            for p in patients
        },
        "traps": {
            "language": [p["pt_id"] for p in patients if "language" in p["traps"]],
            "fragmented": [p["pt_id"] for p in patients if "fragmented" in p["traps"]],
            "meaning": [p_m["pt_id"]],
            "reidentification": [p["pt_id"] for p in patients if "reidentification" in p["traps"]],
            "homonym_pairs": [[patients[0]["pt_id"], patients[1]["pt_id"]]] if len(patients) > 1 else [],
        },
        "linkability": {
            "required_units": sum(1 for f in truth_files.values() for u in f["units"].values() if u.get("link") == "required"),
            "ambiguous_units": sum(1 for f in truth_files.values() for u in f["units"].values() if u.get("link") == "ambiguous"),
            "components": len(patients),
        },
        "canaries": [f"CANARY-{i}" for i in range(len(canaries))],
    }
    (truth_dir / "truth.json").write_text(json.dumps(truth_obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    manifest = {
        "schema": "raksha-dataset/1",
        "generator_version": "1.0.0",
        "profile": "small",
        "chaos": shift_axes,
        "ref_date": ref_date.isoformat(),
        "counts": {
            "files": len(truth_files),
            "patients": len(patients),
            "population": len(reg_rows),
        },
    }
    (out_root / "dataset_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return truth_obj


def generate_fuzz_suite(out_dir: Path) -> list[Path]:
    """Generate adversarial malformed/fuzz files covering Appendix B & R-69/R-71."""
    out_dir.mkdir(parents=True, exist_ok=True)
    # 1500-level deep JSON
    deep: dict | str = {"leaf": "test"}
    for _ in range(1500):
        deep = {"level": deep}
    files: dict[str, bytes] = {
        "zero_byte.txt": b"",
        "null_binary.bin": b"\x00\x01\x02\x03\x00\xff",
        "truncated.json": b'{"patients": [{"name": "Test"',
        "truncated_fhir.json": b'{"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Patient"',
        "bad_utf8.txt": b"Valid prefix \xff\xfe\xc3( suffix\n",
        "long_line_50k.txt": (b"A" * 50000) + b"\n",
        "unquoted_commas.csv": b"id,name,notes\n1,Alpha,a,b,c\n2,Beta,ok\n",
        "zip_as_csv.csv": b"PK\x03\x04\x14\x00\x00\x00\x08\x00fakezip",
        "deep_1500.json": json.dumps(deep).encode("utf-8"),
        "dup_copy_a.txt": b"Clinical note: BP 120/80.\n",
        "dup_copy_b.txt": b"Clinical note: BP 120/80.\n",
    }
    created: list[Path] = []
    for name, content in sorted(files.items()):
        p = out_dir / name
        p.write_bytes(content)
        created.append(p)
    return created
