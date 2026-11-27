"""Security foundations: HKDF key separation, PII-free counters, safe error handling, AES-GCM spill."""
from __future__ import annotations

import os
import sys
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class MissingSecretError(RuntimeError):
    """Raised when RAKSHA_SECRET is absent or empty."""


@dataclass(frozen=True)
class DerivedKeys:
    pseudonym: bytes
    dateshift: bytes
    filename: bytes
    scratch: bytes


def derive_keys(secret: bytes) -> DerivedKeys:
    """Derive 4 domain-separated 256-bit subkeys from RAKSHA_SECRET using HKDF-SHA256."""
    if not secret:
        raise MissingSecretError("missing_secret")

    def _hkdf(info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        ).derive(secret)

    return DerivedKeys(
        pseudonym=_hkdf(b"raksha:pseudonym:v1"),
        dateshift=_hkdf(b"raksha:dateshift:v1"),
        filename=_hkdf(b"raksha:filename:v1"),
        scratch=_hkdf(b"raksha:scratch:v1"),
    )


@dataclass
class CounterLogger:
    """PII-free counter accumulator (never records paths, cell values, or exception text)."""

    stages: dict[str, dict[str, int]] = field(default_factory=dict)

    def inc(self, stage: str, counter: str, delta: int = 1) -> None:
        bucket = self.stages.setdefault(stage, {})
        bucket[counter] = bucket.get(counter, 0) + delta


def install_safe_error_handlers() -> None:
    """Suppress library warnings and prevent raw traceback/exception-message leaks."""
    warnings.filterwarnings("ignore")

    def _safe_hook(exc_type, _exc_value, _tb) -> None:
        sys.stderr.write(f"ERROR: {exc_type.__name__}\n")

    sys.excepthook = _safe_hook


class EncryptedScratchSpill:
    """Optional AES-256-GCM encrypted temporary spill store (RAM-only is default)."""

    def __init__(self, scratch_key: bytes) -> None:
        if len(scratch_key) != 32:
            raise ValueError("invalid_scratch_key")
        self._aes = AESGCM(scratch_key)
        self._dir: Path | None = None
        self._files: dict[str, tuple[Path, bytes]] = {}
        self._counter = 0

    def put(self, payload: bytes) -> str:
        if self._dir is None:
            self._dir = Path(tempfile.mkdtemp(prefix="raksha_spill_"))
        self._counter += 1
        token = f"chunk_{self._counter}"
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, payload, token.encode("ascii"))
        fp = self._dir / f"{token}.bin"
        fp.write_bytes(ct)
        self._files[token] = (fp, nonce)
        return token

    def get(self, token: str) -> bytes:
        fp, nonce = self._files[token]
        ct = fp.read_bytes()
        return self._aes.decrypt(nonce, ct, token.encode("ascii"))

    def cleanup(self) -> None:
        for fp, _ in self._files.values():
            try:
                if fp.exists():
                    fp.unlink()
            except OSError:
                pass
        self._files.clear()
        if self._dir is not None:
            try:
                if self._dir.exists():
                    self._dir.rmdir()
            except OSError:
                pass
            self._dir = None


def peak_rss_mb() -> float:
    """Measure process peak RSS in MB across Linux, macOS, and Windows."""
    try:
        import resource  # type: ignore[import-not-found]
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1024.0 if sys.platform != "darwin" else r / 1048576.0, 1)
    except ImportError:
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class _PMC(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            pmc = _PMC()
            pmc.cb = ctypes.sizeof(_PMC)
            kernel32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PMC), wintypes.DWORD]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            handle = kernel32.GetCurrentProcess()
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
                return round(pmc.PeakWorkingSetSize / (1024.0 * 1024.0), 1)
        except Exception:
            return 0.0
    return 0.0
