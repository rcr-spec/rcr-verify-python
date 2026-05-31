"""Command-line entry point for `rcr-verify` and `python -m rcr_verify`."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .verify import VerificationStatus, verify_bundle


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rcr-verify",
        description="Verify a RANKIGI closure bundle (RCR/1).",
    )
    p.add_argument("bundle", help="Path to the closure bundle JSON file.")
    p.add_argument(
        "--pubkey-from-network",
        action="store_true",
        help="Fetch the issuer's signing public key from its well-known endpoint.",
    )
    p.add_argument(
        "--pubkey",
        help="Path to a PEM-encoded Ed25519 public key for offline verification.",
    )
    p.add_argument(
        "--rekor",
        action="store_true",
        help="Cross-check the Rekor anchor against sigstore.dev (requires network).",
    )
    p.add_argument(
        "--payload-key",
        help="Base64-encoded 32-byte master key for decrypting payload_canonical_encrypted fields.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human-readable report.",
    )
    p.add_argument(
        "--version",
        action="version",
        version="rcr-verify %s" % __version__,
    )
    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    pubkey_pem = None
    if args.pubkey:
        with open(args.pubkey, "rb") as f:
            pubkey_pem = f.read()

    result = verify_bundle(
        args.bundle,
        pubkey_from_network=args.pubkey_from_network,
        pubkey_pem=pubkey_pem,
        rekor=args.rekor,
        payload_key_b64=args.payload_key,
    )

    if args.json:
        json.dump(result.as_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("Status:              %s" % result.status.value)
        print("Events checked:      %d" % result.events_checked)
        print("Chain intact:        %s" % result.chain_intact)
        print("Rekor anchored:      %s" % result.rekor_anchored)
        print("RFC 3161 timestamps: %s" % result.rfc3161_timestamped)
        print("RCR/1 receipts:      %d" % result.rcr_receipts_checked)
        for note in result.notes:
            print("Note:  %s" % note)
        for err in result.errors:
            print("Error: %s" % err)

    if result.status in (VerificationStatus.UNVERIFIED, VerificationStatus.COMPROMISED):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
