"""Programmatic verification example.

Run:
    python3 examples/verify_bundle.py path/to/bundle.json
"""
import sys

from rcr_verify import verify_bundle


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_bundle.py <bundle.json>")
        return 2
    result = verify_bundle(sys.argv[1], pubkey_from_network=True)
    print("Status:", result.status.value)
    print("Events checked:", result.events_checked)
    print("Chain intact:", result.chain_intact)
    for err in result.errors:
        print("  error:", err)
    return 0 if result.status.value in ("VERIFIED", "SELF_ATTESTED", "PARTIAL") else 1


if __name__ == "__main__":
    sys.exit(main())
