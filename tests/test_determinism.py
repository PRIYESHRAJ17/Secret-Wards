"""Gate G3 determinism & secret-sensitivity suite."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kit"


def _tree_digest(out_dir: Path) -> str:
    h = hashlib.sha256()
    for name in ("sanitized", "records.jsonl"):
        p = out_dir / name
        items = sorted(p.rglob("*")) if p.is_dir() else ([p] if p.exists() else [])
        for f in items:
            if f.is_file():
                h.update(f.relative_to(out_dir).as_posix().encode("utf-8") + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()


def _run_main(inp: Path, out: Path, secret: str, cwd: Path | None = None, extra_env: dict | None = None) -> None:
    env = dict(os.environ, RAKSHA_SECRET=secret, PYTHONUTF8="1")
    if extra_env:
        env.update(extra_env)
    subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
        cwd=str(cwd or ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


def test_determinism_repeat_cwd_hashseed_locale_clock_and_secret(tmp_path: Path):
    inp = (KIT / "dev/input").resolve()
    out_a = tmp_path / "out_a"
    out_b = tmp_path / "out_b"
    out_c = tmp_path / "out_c"
    out_clock = tmp_path / "out_clock"
    out_alt = tmp_path / "out_alt"

    _run_main(inp, out_a, "det-secret-1", cwd=ROOT, extra_env={"PYTHONHASHSEED": "1", "TZ": "UTC", "LC_ALL": "C"})
    _run_main(inp, out_b, "det-secret-1", cwd=tmp_path, extra_env={"PYTHONHASHSEED": "42", "TZ": "Asia/Kolkata", "LC_ALL": "en_US.UTF-8"})
    _run_main(inp, out_c, "det-secret-1", cwd=ROOT, extra_env={"PYTHONHASHSEED": "999"})

    dig_a = _tree_digest(out_a)
    assert dig_a == _tree_digest(out_b)
    assert dig_a == _tree_digest(out_c)

    # Report non-timing fields match byte-for-byte
    rep_a = json.loads((out_a / "report.json").read_text(encoding="utf-8"))
    rep_b = json.loads((out_b / "report.json").read_text(encoding="utf-8"))
    for r in (rep_a, rep_b):
        r.pop("timing", None)
        r.pop("resources", None)
    assert rep_a == rep_b

    # Faked-clock wrapper (patches datetime.date & datetime.datetime in-process before calling run_pipeline)
    fake_runner = tmp_path / "fake_clock_run.py"
    fake_runner.write_text(
        "import datetime as dt, sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "class FakeDate(dt.date):\n"
        "    @classmethod\n"
        "    def today(cls): return cls(2031, 8, 15)\n"
        "class FakeDatetime(dt.datetime):\n"
        "    @classmethod\n"
        "    def now(cls, tz=None): return cls(2031, 8, 15, 12, 0, 0)\n"
        "    @classmethod\n"
        "    def utcnow(cls): return cls(2031, 8, 15, 12, 0, 0)\n"
        "dt.date = FakeDate\n"
        "dt.datetime = FakeDatetime\n"
        "from pathlib import Path\n"
        "from main import run_pipeline\n"
        f"sys.exit(run_pipeline(Path({str(inp)!r}), Path({str(out_clock)!r})))\n",
        encoding="utf-8",
    )
    subprocess.run([sys.executable, str(fake_runner)], env=dict(os.environ, RAKSHA_SECRET="det-secret-1", PYTHONUTF8="1"), check=True)
    assert dig_a == _tree_digest(out_clock)

    # Different secret changes PSNs and shifted dates
    _run_main(inp, out_alt, "det-secret-DIFFERENT", cwd=ROOT)
    assert dig_a != _tree_digest(out_alt)
    recs_a = [json.loads(l)["patient"] for l in (out_a / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    recs_alt = [json.loads(l)["patient"] for l in (out_alt / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    psns_a = {p for p in recs_a if p}
    psns_alt = {p for p in recs_alt if p}
    assert psns_a and psns_alt and not (psns_a & psns_alt)
