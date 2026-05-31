"""rcr-verify: Python verifier for RCR/1 receipts and RANKIGI closure bundles.

Public API:
    verify_bundle(path, **kwargs) -> VerificationResult
    VerificationResult         (dataclass)
    VerificationStatus         (enum)

The heavy lifting lives in rcr_verify.verify, which is a packaged copy of the
canonical reference verifier published by RANKIGI Inc. at rankigi.com/verify.py.
"""
from .verify import (
    VerificationResult,
    VerificationStatus,
    verify_bundle,
)

__all__ = [
    "VerificationResult",
    "VerificationStatus",
    "verify_bundle",
]

__version__ = "0.1.0b1"
