"""Smoke tests for the rcr-verify package."""
import json
import os
import tempfile

import rcr_verify
from rcr_verify import VerificationStatus, verify_bundle


def test_package_loads():
    assert rcr_verify.__version__
    assert callable(verify_bundle)
    assert VerificationStatus.VERIFIED.value == "VERIFIED"


def test_rejects_wrong_schema():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"rankigi_proof_bundle_schema": "0.9", "events": []}, f)
        path = f.name
    try:
        result = verify_bundle(path)
        assert result.status == VerificationStatus.UNVERIFIED
        assert any("schema" in e for e in result.errors)
    finally:
        os.unlink(path)


def test_walks_single_event_chain():
    bundle = {
        "rankigi_proof_bundle_schema": "1.5",
        "events": [
            {
                "action": "test.noop",
                "agent_id": "00000000-0000-0000-0000-000000000001",
                "occurred_at": "2026-05-30T17:00:00.000Z",
                "payload": {},
                "hash": "a" * 64,
                "prev_hash": "0" * 64,
                "chain_index": 0,
                "hash_version": 4,
            }
        ],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(bundle, f)
        path = f.name
    try:
        result = verify_bundle(path)
        assert result.chain_intact is True
        assert result.events_checked == 1
        assert result.status == VerificationStatus.SELF_ATTESTED
    finally:
        os.unlink(path)
