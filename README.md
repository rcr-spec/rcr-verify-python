# rcr-verify

The official Python verifier for RCR/1 receipts and RANKIGI closure bundles.

```
pip install rcr-verify
```

## Quick start

Verify a closure bundle from the command line:

```
python3 -m rcr_verify bundle.json --pubkey-from-network
```

Or use the library:

```python
from rcr_verify import verify_bundle

result = verify_bundle("bundle.json", pubkey_from_network=True)
print(result.status)
# VERIFIED
```

## What it verifies

For each bundle, the verifier checks every leg independently and reports per-leg status:

- Per-event canonical hash recomputation (hash_version 1, 2, 3, 4).
- Per-event prev_hash chain continuity (per chain_id, falling back to per agent_id).
- Per-event Ed25519 signature against the passport public key (when present).
- Sigstore Rekor anchor (when `--rekor` is supplied and the network is reachable).
- RFC 3161 TSA tokens with offline certificate-chain validation and pinned FreeTSA root.
- RCR/1 receipt integrity and claim-strength reporting.

Overall verdicts: `VERIFIED`, `SELF_ATTESTED`, `PARTIAL`, `UNVERIFIED`, `COMPROMISED`.

Network failure is reported as SKIPPED for that leg. Offline verification of hash chain and signatures remains authoritative.

## Status

Version: `0.1.0b1` (beta)
PyPI: coming soon
Requires: Python 3.8 or newer
Dependencies: none (stdlib only)
Optional: `cryptography>=41.0` for signature verification (Ed25519, ECDSA, RSA, RFC 3161). Without it, the verifier still checks hash continuity and reports signatures as NOT VERIFIED (cryptography library missing).

Install with the optional crypto extra:

```
pip install 'rcr-verify[crypto]'
```

## Specification

This package implements the RCR/1 specification at github.com/rcr-spec/spec. The IETF Internet-Draft is `draft-snow-rcr-receipt-00`.

## License

MIT.

## Origin and authority

This package is a thin wrapper around the canonical reference verifier published by RANKIGI Inc. at rankigi.com/verify.py. RANKIGI is a contributor to the rcr-spec community; the standard itself is independent.
