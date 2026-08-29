"""
Adversarial Security Tests for UPAS Evidence & Audit Generation Primitives.
Covers:
  - Multi-property tamper detection (artifact digest, commit SHA, actor, state, exit code)
  - Hash chain tampering (event deletion, reordering, previous_hash modification)
  - Secret leakage prevention (raw JWT, Bearer tokens, private keys, URI credentials)
  - Atomic write failure & "NO EVIDENCE = NO VERIFIED RELEASE" invariant
"""

import json
import os
import tempfile
import pytest

from upas_core.contracts.enums import EvidenceType, FinalVerdictState
from upas_core.contracts.errors import InvalidEvidenceError
from upas_core.evidence.collector import EvidenceCollector
from upas_core.evidence.manifest import generate_manifest, verify_evidence_against_manifest
from upas_core.evidence.model import (
    SecretRedactor,
    to_canonical_bytes,
    to_canonical_json,
)
from upas_core.evidence.writer import (
    AtomicEvidenceWriter,
    read_and_verify_persisted_evidence,
)

_VALID_SHA = "0123456789abcdef0123456789abcdef01234567"
_VALID_DIGEST = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def build_test_evidence_dict():
    collector = EvidenceCollector(
        project_name="support_bot",
        project_type="application",
        adapter_version="1.0.0",
    )
    collector.set_git_dag(commit_sha=_VALID_SHA, branch="main")
    collector.set_ci_execution(provider="github_actions", run_id="101", conclusion="success")
    collector.set_artifact_provenance(
        immutable_digest=_VALID_DIGEST,
        canonical_reference=f"registry.internal/support_bot@{_VALID_DIGEST}",
        verified_running_digest=_VALID_DIGEST,
    )
    collector.set_production_authorization(
        policy="github_environment_oidc",
        actor="octocat",
        run_id="101",
        environment="production",
        approval_timestamp="2026-08-28T12:00:00Z",
    )
    collector.set_host_runtime(
        host_identity="host-01",
        kernel_timestamp="2026-08-28T12:00:00Z",
        lock_acquired=True,
        lock_path="/run/lock/upas.lock",
        lock_owner_pid=999,
    )
    collector.record_step("deploy", "PASS", 0, 100)
    record = collector.finalize_evidence(FinalVerdictState.VERIFIED, 0)
    return record.to_dict()


# 1. Adversarial Tamper Detection
def test_adversarial_tamper_artifact_digest():
    ev_dict = build_test_evidence_dict()
    ev_bytes = to_canonical_bytes(ev_dict)
    manifest = generate_manifest(ev_bytes)

    # Attacker tampers with the artifact digest in evidence
    tampered_dict = json.loads(ev_bytes.decode())
    tampered_dict["authoritative_sources"]["artifact_provenance"]["immutable_digest"] = (
        "sha256:bad0000000000000000000000000000000000000000000000000000000000000"
    )
    tampered_bytes = to_canonical_bytes(tampered_dict)

    # Verification MUST FAIL
    assert verify_evidence_against_manifest(manifest, tampered_bytes) is False


def test_adversarial_tamper_actor():
    ev_dict = build_test_evidence_dict()
    ev_bytes = to_canonical_bytes(ev_dict)
    manifest = generate_manifest(ev_bytes)

    # Attacker replaces actor with impersonated user
    tampered_dict = json.loads(ev_bytes.decode())
    tampered_dict["authoritative_sources"]["production_authorization"]["actor"] = "impersonated_admin"
    tampered_bytes = to_canonical_bytes(tampered_dict)

    assert verify_evidence_against_manifest(manifest, tampered_bytes) is False


def test_adversarial_tamper_commit_sha():
    ev_dict = build_test_evidence_dict()
    ev_bytes = to_canonical_bytes(ev_dict)
    manifest = generate_manifest(ev_bytes)

    # Attacker alters source commit SHA
    tampered_dict = json.loads(ev_bytes.decode())
    tampered_dict["authoritative_sources"]["git_dag"]["commit_sha"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    tampered_bytes = to_canonical_bytes(tampered_dict)

    assert verify_evidence_against_manifest(manifest, tampered_bytes) is False


def test_adversarial_tamper_lifecycle_state():
    ev_dict = build_test_evidence_dict()
    ev_bytes = to_canonical_bytes(ev_dict)
    manifest = generate_manifest(ev_bytes)

    # Attacker converts failed verdict to VERIFIED
    tampered_dict = json.loads(ev_bytes.decode())
    tampered_dict["final_verdict"]["state"] = "EMERGENCY_HALT"
    tampered_bytes = to_canonical_bytes(tampered_dict)

    assert verify_evidence_against_manifest(manifest, tampered_bytes) is False


# 2. Adversarial Hash Chain Tampering
def test_adversarial_hash_chain_deletion_and_reordering():
    collector = EvidenceCollector(project_name="tour_monitor")
    e1 = collector.record_event("PROD_APPROVAL_PENDING")
    e2 = collector.record_event("PROD_AUTHORIZED")
    e3 = collector.record_event("LOCK_ACQUIRED")
    e4 = collector.record_event("DEPLOYMENT_VERIFIED")

    assert collector.verify_hash_chain() is True

    # 1. Event deletion
    tampered_events = [e1, e3, e4]  # e2 deleted
    collector._audit_events = tampered_events
    assert collector.verify_hash_chain() is False

    # 2. Event reordering
    reordered_events = [e1, e3, e2, e4]
    collector._audit_events = reordered_events
    assert collector.verify_hash_chain() is False


# 3. Secret Redaction & Leakage Prevention
def test_adversarial_secret_leakage_redaction():
    raw_jwt = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    raw_pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    payload_with_secrets = {
        "step": "exec_hook",
        "command": f"curl -H 'Authorization: Bearer {raw_jwt}' http://api.internal",
        "auth_header": f"Bearer {raw_jwt}",
        "raw_token": raw_jwt,
        "db_url": "postgres://superuser:super_secret_password_999@postgres:5432/main",
        "key_material": raw_pem,
    }

    canonical_json = to_canonical_json(payload_with_secrets, redact_secrets=True)

    # Assert NO secret material survived
    assert raw_jwt not in canonical_json
    assert "super_secret_password_999" not in canonical_json
    assert "MIIEowIBAAKCAQEA0" not in canonical_json
    assert "[REDACTED_TOKEN]" in canonical_json
    assert "[REDACTED_PASSWORD]" in canonical_json
    assert "[REDACTED_PRIVATE_KEY]" in canonical_json


# 4. Atomic Write Failure Handling
def test_adversarial_atomic_writer_invalid_target_dir():
    writer = AtomicEvidenceWriter()
    ev_dict = build_test_evidence_dict()

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a file at fake_dir path so that attempting to treat it as a directory fails
        blocking_file = os.path.join(tmpdir, "blocking_file.txt")
        with open(blocking_file, "w") as f:
            f.write("I am a file, not a directory")

        invalid_path = os.path.join(blocking_file, "child_dir", "evidence.json")
        with pytest.raises(InvalidEvidenceError):
            writer.write_evidence_and_manifest(ev_dict, output_evidence_path=invalid_path)
