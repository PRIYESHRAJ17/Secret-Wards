# Secret Wards — Offline Privacy Firewall (Knight Rebels)

## What Is Secret Wards?

Hospitals generate patient records in many disconnected formats every day — spreadsheets (CSV/TSV), structured clinical bundles (JSON and FHIR R4), and free-text doctor or nursing notes written in a mix of English, Hindi (Devanagari), and Hinglish (Hindi words typed in English letters).

When hospitals share this data for public-health research, **simply deleting patient names is not enough**:
- Names and IDs often hide inside filenames, spreadsheet column headers, JSON keys, or base64 file attachments.
- The same patient can appear across multiple files in different languages or spellings, making it hard to keep their medical timeline together without accidentally merging two different people.
- Even without a name, an attacker with a public voter list can often re-identify someone from quasi-identifiers such as exact visit dates, age, PIN code, hospital stay length, or a rare disease.
- Conversely, overly aggressive redaction destroys medicines, dosages, lab numbers, and clinician names needed for medical research.

**Secret Wards** is an **offline, CPU-only, zero-LLM privacy firewall** that solves all of these problems in one repeatable pass:
- **Removes personal data everywhere:** Strips names, relatives, addresses, phone numbers, Aadhaar, ABHA, PAN, insurance IDs, and hospital MRNs across English, Hindi, and Hinglish — inside file text, JSON keys, metadata, filenames, and attachments.
- **Keeps medical data intact:** Protects medicines, dosages (`1-0-1`), vitals (`BP 150/90`), lab units, diagnoses, hospital wards, and doctor names (`Dr.` / `Prof.`) before redacting identifiers.
- **Links each patient consistently:** Connects records belonging to the same patient across files, hospitals, and scripts under one non-reversible fake ID (`PSN-XXXXXXXXXX`), while leaving uncertain cases unlinked (`null`) rather than merging two different people.
- **Defends against re-identification:** Shifts dates consistently per patient (preserving exact lengths of stay), groups ages into bands, truncates PIN codes, and selectively tightens rare/elderly records.
- **Fails safely:** Broken, truncated, malformed, or unsupported binary files are quarantined cleanly instead of leaking out raw.

---

## Step-by-Step Setup & How to Run

### Prerequisites
- **Python 3.10+** (verified on Python 3.13 / 3.14; runs 100% offline on CPU once packages are installed)
- **Git**

### Step 1 — Clone the Repository

```bash
git clone https://github.com/PRIYESHRAJ17/Secret-Wards.git
cd Secret-Wards
```

### Step 2 — Create & Activate a Virtual Environment

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

This installs only lightweight, offline libraries (`PyYAML`, `cryptography`, and `regex`) — no model weights or internet calls are used during execution.

### Step 4 — Set a Secret Key & Run the Pipeline

`RAKSHA_SECRET` is required to generate cryptographic pseudonyms and date shifts. Using the **same** secret on the **same** input always produces identical output; using a **different** secret produces completely different pseudonyms and date shifts. (If `RAKSHA_SECRET` is missing or empty, the program exits cleanly with code `2` without writing any output.)

**Linux / macOS:**
```bash
RAKSHA_SECRET="replace-with-your-strong-secret-key" python main.py --input /path/to/input_dir --output /path/to/output_dir
```

**Windows (PowerShell):**
```powershell
$env:RAKSHA_SECRET = "replace-with-your-strong-secret-key"
python main.py --input C:\path\to\input_dir --output C:\path\to\output_dir
```

**Windows (Command Prompt):**
```cmd
set RAKSHA_SECRET=replace-with-your-strong-secret-key && python main.py --input C:\path\to\input_dir --output C:\path\to\output_dir
```

Optional flag:
- `--policy path/to/policy.yaml` — overrides the default privacy rules in `config/policy.yaml` (age band width, date-shift range, PIN truncation digits, pseudonym length, file size and nesting caps).

### Step 5 — Check Your Output Folder

After running, `<output_dir>` contains strictly three items:

```text
output/
├── sanitized/      # Cleaned CSV, TSV, JSON, FHIR R4, and TXT files (UTF-8, original folder layout preserved)
├── report.json     # Integrity manifest (SHA-256 input hashes, sanitized/quarantined status, counts, runtime, memory)
└── records.jsonl   # Line-by-line index mapping every record locator (row:N, /visits/3, doc) to its PSN ID or null
```

- Any file whose filename contained personal data is safely HMAC-renamed in `sanitized/` and recorded by its input SHA-256 in `report.json`.
- Any malformed, truncated, oversized (`>50 MB`), deeply nested (`>100` JSON levels), symlink-escaping, or binary file is quarantined rather than copied raw.

> **Interactive Stage 2 Demo & Full Test Suite:** For the 3D/WebGL interactive showcase (`frontend/`, `api_server.py`) and automated pytest suite (`tests/`, `tools/`), switch to the `demo` branch (`git checkout demo`). See [`docs/brief.pdf`](docs/brief.pdf) for the 2-page Project Brief.

---

## System Architecture

```text
input/ ─▶ ingest (encoding sniff, delimiter auto-detect, quarantine)
       ─▶ pass-1 extraction (profiles, _export_meta headers, clinicians, corpus lexicon)
       ─▶ cross-script linkage (Devanagari/Latin/Hinglish Union-Find + hard vetoes + k-risk profiling)
       ─▶ pass-2 detect & surfaces (clinical-first arbitration, paths, headers, JSON keys, base64)
       ─▶ privacy & pseudonymization (PSN-XXXXXXXXXX, per-patient date shifts, age bands, PIN-3/district)
       ─▶ verify (whole-output zero-survivor + schema validation) ─▶ sanitized/ + report.json + records.jsonl
```

### How Each Component Works

- **Ingestion & Quarantine (`src/ingest.py`):** Sorted deterministic file traversal, raw-byte SHA-256 hashing, symlink escape rejection, content-first format sniffing (CSV, TSV, pipe/semicolon tables, JSON, FHIR R4, plain text), and strict encoding decoding (UTF-8, UTF-8-BOM, BOM-driven UTF-16, and narrow `cp1252`).
- **Detection & Clinical Arbitration (`src/detect/`, `src/surfaces.py`):** Protects clinical facts (`Dr.`/`Prof.` clinicians, doses, frequencies `1-0-1`, vitals, labs with units, `H/o`/`R/o`/`K/c/o`/`C/O` symptoms, eponyms, `ASHA` workers, `ICD-10`, `LOINC`, hospital wards) before deterministically resolving overlapping PII spans across English, Devanagari Hindi, Hinglish, JSON keys (`by_name`, `_export_meta`, integer `aadhar_no`), CSV headers, filenames, and base64 payloads.
- **Cross-Script Linkage & Pseudonymization (`src/linkage.py`, `src/textnorm.py`, `src/pseudonym.py`):** Transliterates Devanagari to Latin consonant skeletons, normalizes comma-flipped `Last, First` names, and links patient records across files/scripts using two-stage Union-Find with hard vetoes on sex, age/DOB, conflicting IDs, distinct same-hospital MRNs, and mismatched relatives. Issues keyed `HMAC-SHA256` pseudonyms (`PSN-` + 10 Crockford Base32 chars).
- **Adaptive Privacy Layer (`src/privacy.py`):** Shifts all dates consistently per patient (`±[30, 1460]` days) across numeric formats and English/Hindi month names, converts DOB to birth year (`YYYY`), groups ages into 5-year bands (`85+` open elderly band in `config/policy.yaml`), truncates PINs to 3 digits, and tightens high-risk clusters (20-year age bands, full PIN suppression, and conditional district suppression when age `>= 80` co-occurs with rare diagnoses in `<= 2` clusters).
- **Security Design (`src/secure.py`, `src/verify.py`):** Expands `RAKSHA_SECRET` in memory via `HKDF-SHA256` (`cryptography`) into domain-separated subkeys (`pseudonym`, `dateshift`, `filename`, `scratch`). Fails closed when the secret is absent, scrubs secrets from logs/tracebacks, and verifies outputs before writing.

## Model Declarations

- **No LLMs, no generative models, and no pretrained transformers (0 ML model parameters).**
- All detection, transliteration, linkage, and privacy controls run 100% deterministically on CPU using `PyYAML`, `cryptography`, and `regex`.

## Evaluation & Verification

- **Dev dataset (`dev/input`, 200 files):** **`93.26 / 100`** composite score (`0 / 3,230` personal data leaks across Latin, Devanagari, Hinglish, and all 6 hidden channels; `0 / 4` canaries; `4,853 / 4,855` medical values preserved; `0` wrong patient merges; `CONTRACT OK`; `11.251 s` single-run runtime).
- **Unseen schema-shifted stress dataset (`heldout_shift`):** **`91.85 / 100`** composite score (`0 / 577` leaks; `0 / 5` canaries; `125 / 126` medical values preserved; precision `1.00`, recall `0.943`, `F0.5 0.988`, `0` wrong merges).
- **Automated suite (`demo` branch):** `python -m pytest -v` (`18 passed`).

## Known Limitations

- Unsupported binary files (PDF, JPEG, ZIP/archives) are safely quarantined rather than OCR-extracted.
- Preserving analytically useful coarse quasi-identifiers (sex, district, 5-year age band for standard-risk clusters) leaves bounded demographic re-identification exposure under targeted attacker simulations unless wider bands are set in `config/policy.yaml`.
- Isolated single-token nicknames in unformatted text without surnames, relative cues, or matching identifiers stay conservative (`null` or unmerged) to prevent wrongly merging distinct people.
