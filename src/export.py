"""Contract output writer for sanitized/, records.jsonl, and report.json (R-140..R-144)."""
from __future__ import annotations

import json
from pathlib import Path


def write_outputs(
    out_dir: Path,
    sanitized_blobs: dict[str, str],
    file_entries: list[dict],
    records: list[dict],
    counts: dict[str, int],
    seconds: float,
    rss_mb: float,
) -> None:
    """Write strictly sanitized/, report.json, and records.jsonl into out_dir."""
    san_root = out_dir / "sanitized"
    san_root.mkdir(parents=True, exist_ok=True)

    for rel_out in sorted(sanitized_blobs):
        dest = san_root / rel_out
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(sanitized_blobs[rel_out], encoding="utf-8", newline="")

    exported_set = {f"sanitized/{rel}" for rel in sanitized_blobs}
    filtered_records = [r for r in records if r["file"] in exported_set]
    filtered_records.sort(key=lambda r: (r["file"], r["loc"]))

    with open(out_dir / "records.jsonl", "w", encoding="utf-8", newline="\n") as fj:
        for r in filtered_records:
            fj.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    n_san = sum(1 for e in file_entries if e["status"] == "sanitized")
    n_quar = sum(1 for e in file_entries if e["status"] == "quarantined")
    assert len(file_entries) == n_san + n_quar
    counts["files_total"] = len(file_entries)
    counts["files_sanitized"] = n_san
    counts["files_quarantined"] = n_quar
    counts["records_processed"] = len(filtered_records)
    counts["records_linked"] = sum(1 for r in filtered_records if r["patient"] is not None)

    report = {
        "schema": "raksha-report/1",
        "files": file_entries,
        "counts": counts,
        "timing": {"seconds": round(seconds, 3)},
        "resources": {"peak_rss_mb": rss_mb},
    }
    (out_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
