"""
Unit tests for UPAS Evidence Collector and Hash Chain.
"""

import json
import pytest
from jsonschema import Draft7Validator

from upas_core.contracts.enums import EvidenceType, FinalVerdictState
from upas_core.contracts.errors import InvalidEvidenceError
from upas_core.evidence.collector import EvidenceCollector

_VALID_SHA = "0123456789abcdef0123456789abcdef01234567"
_VALID_DIGEST = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def evidence_schema():
    with open("schemas/evidence.schema.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_evidence_collector_full_lifecycle_and_schema_validation(evidence_schema):
    collector = EvidenceCollector(
        project_name="tour_monitor",
        project_type="application",
        adapter_version="1.0.0",
        correlation_id="rel_tour_monitor_100",
    )

    # 1. Record events
    collector.record_event("PROD_APPROVAL_PENDING")
    collector.record_event("PROD_AUTHORIZED", {"actor": "release-lead"})
    collector.record_event("LOCK_ACQUIRED", {"lock_path": "/run/lock/upas.lock"})
    collector.record_event("DEPLOYMENT_VERIFIED", {"exit_code": 0})

    # Verify hash chain
    assert collector.verify_hash_chain() is True
    assert len(collector.audit_events) == 4

    # 2. Record steps
    collector.record_step("authorization", "PASS", 0, 150)
    collector.record_step("host_lock", "PASS", 0, 50)
    collector.record_step("verification", "PASS", 0, 300)

    # 3. Set authoritative sources
    collector.set_git_dag(commit_sha=_VALID_SHA, branch="main", dirty_tree=False)
    collector.set_ci_execution(provider="github_actions", run_id="123456", conclusion="success")
    collector.set_artifact_provenance(
        immutable_digest=_VALID_DIGEST,
        canonical_reference=f"registry.internal/tour_monitor@{_VALID_DIGEST}",
        verified_running_digest=_VALID_DIGEST,
    )
    collector.set_production_authorization(
        policy="github_environment_oidc",
        actor="octocat",
        run_id="999",
        environment="production",
        approval_timestamp="2026-08-28T12:00:00Z",
    )
    collector.set_host_runtime(
        host_identity="host-prod-01",
        kernel_timestamp="2026-08-28T12:00:00Z",
        lock_acquired=True,
        lock_path="/run/lock/upas.lock",
        lock_owner_pid=1234,
    )

    # 4. Finalize
    evidence = collector.finalize_evidence(
        final_state=FinalVerdictState.VERIFIED,
        exit_code=0,
        summary="Tour Monitor deploy verified",
    )

    evidence_dict = evidence.to_dict()

    # Validate against strict frozen JSON Schema
    validator = Draft7Validator(evidence_schema)
    errors = list(validator.iter_errors(evidence_dict))
    assert len(errors) == 0, f"Schema validation errors: {errors}"


def test_evidence_collector_missing_source_fails_closed():
    collector = EvidenceCollector(project_name="tour_monitor")
    collector.set_git_dag(commit_sha=_VALID_SHA, branch="main")
    # Missing ci_execution, artifact_provenance, etc.

    with pytest.raises(InvalidEvidenceError) as exc_info:
        collector.finalize_evidence(FinalVerdictState.VERIFIED, 0)
    assert "Missing mandatory authoritative source" in str(exc_info.value)
