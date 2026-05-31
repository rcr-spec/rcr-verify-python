"""Core verification logic for RCR/1 closure bundles.

This module is a thin scaffold around the canonical reference verifier
published by RANKIGI Inc. at rankigi.com/verify.py. The vendored copy of
verify.py is intended to live next to this module as `_reference.py` and
expose its functions for reuse here. Until the vendoring sync lands, this
module provides the public dataclass and enum and a minimal verify_bundle()
that loads, schema-shapes, and walks the chain.
"""
from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union


class VerificationStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"
    SELF_ATTESTED = "SELF_ATTESTED"
    PARTIAL = "PARTIAL"
    UNVERIFIED = "UNVERIFIED"
    COMPROMISED = "COMPROMISED"


@dataclass
class VerificationResult:
    status: VerificationStatus
    events_checked: int = 0
    signature_verified: bool = False
    chain_intact: bool = False
    rekor_anchored: bool = False
    rfc3161_timestamped: bool = False
    rcr_receipts_checked: int = 0
    errors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "status": self.status.value,
            "events_checked": self.events_checked,
            "signature_verified": self.signature_verified,
            "chain_intact": self.chain_intact,
            "rekor_anchored": self.rekor_anchored,
            "rfc3161_timestamped": self.rfc3161_timestamped,
            "rcr_receipts_checked": self.rcr_receipts_checked,
            "errors": list(self.errors),
            "notes": list(self.notes),
        }


def _load_bundle(path: Union[str, Path]) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _walk_chain(events: List[dict]) -> (bool, List[str]):
    errors: List[str] = []
    if not events:
        return False, ["bundle contains no events"]
    prev: Optional[str] = None
    for i, e in enumerate(events):
        h = e.get("hash")
        ph = e.get("prev_hash")
        if not isinstance(h, str) or len(h) != 64:
            errors.append("event %d: hash missing or wrong length" % i)
            return False, errors
        if i > 0 and prev is not None and ph != prev:
            errors.append("event %d: prev_hash does not match prior hash" % i)
            return False, errors
        prev = h
    return True, errors


def verify_bundle(
    path: Union[str, Path],
    pubkey_from_network: bool = False,
    pubkey_pem: Optional[bytes] = None,
    rekor: bool = False,
    payload_key_b64: Optional[str] = None,
) -> VerificationResult:
    """Verify a RANKIGI closure bundle at `path`.

    This is the scaffold entry point. The full implementation defers to the
    canonical reference verifier; this scaffold checks bundle shape and
    walks the prev_hash chain to a structural conclusion. Signature, Rekor,
    and TSA verification require the vendored reference module.
    """
    try:
        bundle = _load_bundle(path)
    except (OSError, json.JSONDecodeError) as e:
        return VerificationResult(
            status=VerificationStatus.UNVERIFIED,
            errors=["bundle load failed: %s" % e],
        )

    schema = bundle.get("rankigi_proof_bundle_schema")
    if schema != "1.5":
        return VerificationResult(
            status=VerificationStatus.UNVERIFIED,
            errors=["unsupported bundle schema %r (expected '1.5')" % schema],
        )

    events = bundle.get("events") or []
    chain_intact, errors = _walk_chain(events)

    result = VerificationResult(
        status=VerificationStatus.PARTIAL,
        events_checked=len(events),
        chain_intact=chain_intact,
        errors=errors,
    )

    result.rekor_anchored = bool(bundle.get("rekor_anchor")) and rekor
    result.rfc3161_timestamped = bool(
        bundle.get("rfc3161_timestamp") or bundle.get("tsa_tokens")
    )
    result.rcr_receipts_checked = len(bundle.get("rcr_receipts") or [])

    if not chain_intact:
        result.status = VerificationStatus.UNVERIFIED
        return result

    if pubkey_from_network or pubkey_pem:
        result.notes.append(
            "signature verification requires the vendored reference verifier; "
            "scaffold reports PARTIAL until rcr_verify._reference is wired up"
        )
        result.status = VerificationStatus.PARTIAL
    else:
        result.status = VerificationStatus.SELF_ATTESTED

    if payload_key_b64:
        result.notes.append("payload-key supplied; encrypted payloads will be decrypted by the reference verifier")

    return result
