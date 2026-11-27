# Secret Wards — Offline Privacy Firewall (Knight Rebels)

An offline, CPU-only, LLM-free privacy firewall for multilingual Indian hospital records (English, Devanagari Hindi, and Hinglish) across CSV, TSV, JSON, FHIR R4 Bundles, and clinical notes.

## Setup & Run

```bash
pip install -r requirements.txt
RAKSHA_SECRET=<your-secret> python main.py --input <input_dir> --output <output_dir>
```

The CLI writes strictly three artifacts into `<output_dir>`:
- `sanitized/` — format-preserving UTF-8 sanitized files (with PII-bearing paths/filenames HMAC-renamed)
- `report.json` — SHA-256 file manifest (`raksha-report/1`), honest counts, timing, and peak RSS
- `records.jsonl` — deterministic per-record locators (`row:N`, JSON pointers, `doc`) and pseudonyms (`PSN-...` or `null`)

### Live Interactive Demo (Stage 2)

```bash
# Terminal 1 — Offline Privacy Firewall API (port 8000)
RAKSHA_SECRET=<your-secret> BACKEND_PORT=8000 python api_server.py

# Terminal 2 — 3D/WebGL Interactive Demo Proxy (port 3000)
PORT=3000 BACKEND_URL=http://127.0.0.1:8000 node frontend/server.mjs
```
Then open `http://localhost:3000` in Chrome/Edge to explore live hospital sanitization, snippet redaction, and downloadable contract bundles.

## Architecture

```
input/ ─▶ ingest (encoding sniff, delimiter auto-detect, quarantine)
       ─▶ pass-1 extraction (profiles, _export_meta headers, clinicians, corpus lexicon)
       ─▶ cross-script linkage (Devanagari/Latin/Hinglish Union-Find + hard vetoes + k-risk profiling)
       ─▶ pass-2 detect & surfaces (clinical-first arbitration, paths, headers, JSON keys, base64)
       ─▶ privacy & pseudonymization (PSN-XXXXXXXXXX, per-patient date shifts, age bands, PIN-3/district)
       ─▶ verify (whole-output zero-survivor + schema validation) ─▶ sanitized/ + report.json + records.jsonl
```

## How Each Component Works

- **Ingestion & Quarantine (`src/ingest.py`):** Deterministic sorted traversal, raw-byte SHA-256 hashing, symlink escape rejection, content-first format sniffing (CSV, TSV, pipe/semicolon tables, JSON, FHIR R4, plain text), and strict encoding validation (UTF-8, UTF-8-BOM, BOM-driven UTF-16, and narrow `cp1252`). Malformed JSON, excessive nesting depth (`>100`), corrupt bytes, mislabeled formats, and unsupported binaries/archives are quarantined rather than copied raw.
- **Detection & Clinical Arbitration (`src/detect/`, `src/surfaces.py`):** Protects clinical probes (`Dr.`/`Prof.` clinicians, doses, frequencies `1-0-1`, vitals, lab values/units, `H/o`/`R/o`/`K/c/o`/`C/O` clinical symptoms, eponyms, `ASHA` workers, `ICD-10`, `LOINC`, hospital wards) before deterministically arbitraging overlapping PII candidates. Handles English, Devanagari, and Romanized Hinglish identifiers (Aadhaar, ABHA, PAN, insurance IDs, global/local MRNs, kinship patterns, addresses) plus hidden surfaces (Filenames/directories, headers, JSON keys like `by_name`, `_export_meta`, integer `aadhar_no`, and base64 attachments).
- **Cross-Script Linkage & Pseudonymization (`src/linkage.py`, `src/textnorm.py`, `src/pseudonym.py`):** Transliterates Devanagari to Latin consonant skeletons, normalizes comma-flipped `Last, First` names, and links records across formats/scripts via deterministic two-stage Union-Find with hard vetoes on sex, age/DOB, conflicting IDs, distinct same-hospital MRNs, and mismatched relatives. Assigns domain-separated `HMAC-SHA256` pseudonyms (`PSN-` + 10 Crockford Base32 chars) in both `records.jsonl` and sanitized files.
- **Adaptive Privacy Layer (`src/privacy.py`):** Applies per-patient constant HMAC date shifts (`±[30, 1460]` days) across numeric dates and English/Hindi month names while preserving clinical intervals/lengths of stay, year-only DOB cohorts, 5-year age bands (`85+` open elderly band in `config/policy.yaml`), and adaptive k-risk hardening (20-year age bands, full PIN suppression, and selective district suppression when elderly age `>= 80` co-occurs with rare diagnoses in `<= 2` clusters).
- **Security Design (`src/secure.py`, `src/verify.py`):** `RAKSHA_SECRET` is read once into memory and expanded via `HKDF-SHA256` (`cryptography`) into domain-separated subkeys (`pseudonym`, `dateshift`, `filename`, `scratch`). Processing is memory-only by default with fail-closed secret checks, non-leaky tracebacks, and post-sanitization verification prior to export.

## Model Declarations

- **No LLMs, no generative models, and no pretrained transformers (0 ML model parameters).**
- All detection, transliteration, clustering, and privacy transformations use deterministic Python rules (`PyYAML`, `cryptography`, `regex`) running 100% offline on CPU.

## Evaluation & Verification

- Observed dev suite (`dev/input`): **`93.26 / 100`** total (`0 / 3,230` personal data leaks across Latin, Devanagari, Hinglish, and all 6 hiding channels; `0 / 4` canaries; `4,853 / 4,855` medical values preserved; `0` wrong patient merges; `CONTRACT OK`; single-run runtime `11.251 s`).
- Observed unseen domain-shifted benchmark (`heldout_shift`): **`91.85 / 100`** total (`0 / 577` leaks; `0 / 5` canaries; `125 / 126` medical values preserved; precision `1.00`, recall `0.943`, `F0.5 0.988`, `0` wrong merges).
- Run test suite: `python -m pytest -v` (`18 passed`).

## Known Limitations

- Files in unsupported binary formats (PDF, JPEG, ZIP/archives) are safely quarantined rather than OCR-extracted.
- In small epidemiological tables, preserving analytically useful coarse quasi-identifiers (sex, district, 5-year band for non-high-risk records) permits bounded cohort-level re-identification exposure under targeted attacker models unless wider bands are configured in `config/policy.yaml`.
- Isolated single-token nicknames in unformatted text without surnames, relative cues, or corroborating identifiers are kept conservative (`null` or unmerged) when ambiguous to prevent false patient merges.
