"""
Unit tests for UPAS Atomic Evidence Writer and persisted tamper detection.
"""

import os
import tempfile
from upas_core.evidence.writer import (
    AtomicEvidenceWriter,
    read_and_verify_persisted_evidence,
)


def sample_evidence_dict():
    return {
        "operation_id": "op_writer_001",
        "correlation_id": "rel_writer_001",
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


def test_atomic_write_and_verify_success():
    with tempfile.TemporaryDirectory() as tmpdir:
        ev_file = os.path.join(tmpdir, "audit.evidence.json")
        man_file = os.path.join(tmpdir, "audit.manifest.json")

        writer = AtomicEvidenceWriter()
        ev_path, man_path, manifest = writer.write_evidence_and_manifest(
            evidence=sample_evidence_dict(),
            output_evidence_path=ev_file,
            output_manifest_path=man_file,
        )

        assert os.path.exists(ev_path)
        assert os.path.exists(man_path)

        # Read and verify
        is_valid, ev_dict, loaded_manifest, err = read_and_verify_persisted_evidence(ev_path, man_path)
        assert is_valid is True
        assert err is None
        assert ev_dict["operation_id"] == "op_writer_001"
        assert loaded_manifest.evidence_sha256 == manifest.evidence_sha256


def test_tampered_evidence_file_fails_verification():
    with tempfile.TemporaryDirectory() as tmpdir:
        ev_file = os.path.join(tmpdir, "tampered.evidence.json")
        man_file = os.path.join(tmpdir, "tampered.manifest.json")

        writer = AtomicEvidenceWriter()
        writer.write_evidence_and_manifest(
            evidence=sample_evidence_dict(),
            output_evidence_path=ev_file,
            output_manifest_path=man_file,
        )

        # Tamper directly with persisted evidence file on disk
        with open(ev_file, "r+", encoding="utf-8") as f:
            content = f.read()
            tampered = content.replace('"exit_code":0', '"exit_code":1')
            f.seek(0)
            f.write(tampered)
            f.truncate()

        is_valid, ev_dict, loaded_manifest, err = read_and_verify_persisted_evidence(ev_file, man_file)
        assert is_valid is False
        assert "tampered" in err.lower()
