"""
Unit tests for UPAS Cryptographic Evidence Manifest.
"""

from upas_core.evidence.manifest import (
    EvidenceManifest,
    generate_manifest,
    verify_evidence_against_manifest,
)
from upas_core.evidence.model import to_canonical_bytes


def make_sample_evidence():
    return {
        "operation_id": "op_test_100",
        "correlation_id": "rel_test_100",
        "authoritative_sources": {
            "artifact_provenance": {
                "immutable_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            }
        },
        "final_verdict": {
            "state": "VERIFIED",
            "exit_code": 0,
            "completed_at": "2026-08-28T12:00:00Z",
        },
    }


def test_manifest_generation_and_verification():
    ev_dict = make_sample_evidence()
    ev_bytes = to_canonical_bytes(ev_dict)

    manifest = generate_manifest(ev_dict)

    assert manifest.operation_id == "op_test_100"
    assert manifest.final_state == "VERIFIED"
    assert manifest.final_exit_code == 0
    assert manifest.artifact_digest == "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    # Verify against matching evidence bytes
    assert verify_evidence_against_manifest(manifest, ev_bytes) is True


def test_manifest_tampering_fails_verification():
    ev_dict = make_sample_evidence()
    ev_bytes = to_canonical_bytes(ev_dict)
    manifest = generate_manifest(ev_dict)

    # 1. Modify evidence bytes
    tampered_bytes = ev_bytes.replace(b"VERIFIED", b"ROLLED_BACK")
    assert verify_evidence_against_manifest(manifest, tampered_bytes) is False

    # 2. Modify manifest state
    tampered_manifest = EvidenceManifest(
        manifest_id=manifest.manifest_id,
        operation_id=manifest.operation_id,
        correlation_id=manifest.correlation_id,
        evidence_sha256=manifest.evidence_sha256,
        artifact_digest=manifest.artifact_digest,
        final_state="EMERGENCY_HALT",  # Tampered
        final_exit_code=81,
        generated_at=manifest.generated_at,
    )
    assert verify_evidence_against_manifest(tampered_manifest, ev_bytes) is False
