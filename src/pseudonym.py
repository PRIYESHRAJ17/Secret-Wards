"""HMAC-SHA256 Crockford Base32 pseudonym generator with deterministic collision handling (D-008)."""
from __future__ import annotations

import hashlib
import hmac

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford Base32 (no I, L, O, U)


def issue_psn(
    psn_key: bytes,
    canonical_anchor: str,
    used_psns: set[str],
    prefix: str = "PSN-",
    n_chars: int = 10,
) -> str:
    """Issue a non-reversible, deterministic PSN with collision detection."""
    counter = 0
    while True:
        msg = f"v1|{canonical_anchor}" if counter == 0 else f"v1|{canonical_anchor}#{counter}"
        digest = hmac.new(psn_key, msg.encode("utf-8"), hashlib.sha256).digest()
        val = int.from_bytes(digest[:8], "big")
        code = "".join(_ALPHABET[(val >> (5 * i)) & 31] for i in range(n_chars))
        psn = f"{prefix}{code}"
        if psn not in used_psns:
            used_psns.add(psn)
            return psn
        counter += 1
