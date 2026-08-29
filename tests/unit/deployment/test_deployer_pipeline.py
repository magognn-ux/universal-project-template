"""
Unit and Integration tests for UPAS ProductionDeployer pipeline.
Tests full lifecycle flow from PROD_APPROVAL_PENDING to DEPLOYMENT_VERIFIED.
"""

import os
import sys
import tempfile
import time
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from upas_core.contracts.artifacts import (
    ArtifactDescriptor,
    ArtifactType,
    BuilderMetadata,
)
from upas_core.contracts.enums import (
    ExitCode,
    FinalVerdictState,
    MigrationClassification,
    MigrationPolicy,
)
from upas_core.contracts.lifecycle import DeploymentState
from upas_core.contracts.migrations import MigrationSpec
from upas_core.contracts.security import OIDCExpectedConfig
from upas_core.deployment.deployer import (
    DeploymentContext,
    ProductionDeployer,
)
from upas_core.evidence.writer import read_and_verify_persisted_evidence
from upas_core.locking.host_lock import AtomicHostLock
from upas_core.security.host_guard import ProductionHostGuard
from upas_core.security.jti_store import SQLiteJtiStore
from upas_core.security.oidc_verifier import GitHubOIDCVerifier


@pytest.fixture
def deployer_fixtures():
    with tempfile.TemporaryDirectory() as tmpdir:
        jti_db = os.path.join(tmpdir, "jti.db")
        lock_path = os.path.join(tmpdir, "upas.lock")
        backup_file = os.path.join(tmpdir, "backup.dump")
        evidence_file = os.path.join(tmpdir, "audit.evidence.json")
        manifest_file = os.path.join(tmpdir, "audit.manifest.json")

        # Crypto keys for OIDC
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        verifier = GitHubOIDCVerifier(signing_keys={"key-1": pub})
        host_guard = ProductionHostGuard(verifier=verifier, jti_store=SQLiteJtiStore(jti_db))

        oidc_config = OIDCExpectedConfig(
            expected_issuer="https://token.actions.githubusercontent.com",
            expected_audience="upas-production-gate",
            expected_repository="octocat/hello-world",
            expected_environment="production",
            required_claims=["repository", "environment", "ref", "job_workflow_ref"],
        )

        digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        artifact = ArtifactDescriptor(
            artifact_id="art_support_bot_001",
            project_name="support_bot",
            artifact_type=ArtifactType.CONTAINER_IMAGE,
            canonical_reference=f"registry.internal/support_bot@{digest}",
            immutable_digest=digest,
            source_commit="0123456789abcdef0123456789abcdef01234567",
            source_branch="main",
            build_timestamp="2026-08-28T12:00:00Z",
            builder_metadata=BuilderMetadata(
                ci_run_id="run_1",
                runner_os="ubuntu-22.04",
                toolchain="docker",
            ),
        )

        migration_spec = MigrationSpec(
            classification=MigrationClassification.ADDITIVE_COMPATIBLE,
            policy=MigrationPolicy.EXPLICIT_MANIFEST,
            two_phase_protocol=False,
        )

        deployer = ProductionDeployer(
            host_guard=host_guard,
            host_lock=AtomicHostLock(),
        )

        def make_token(jti="deploy-jti-001"):
            payload = {
                "iss": "https://token.actions.githubusercontent.com",
                "aud": "upas-production-gate",
                "repository": "octocat/hello-world",
                "environment": "production",
                "ref": "refs/heads/main",
                "job_workflow_ref": "octocat/hello-world/.github/workflows/deploy.yml@refs/heads/main",
                "jti": jti,
                "exp": int(time.time()) + 3600,
                "actor": "octocat",
                "run_id": "777",
            }
            return jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "key-1"})

        yield {
            "deployer": deployer,
            "artifact": artifact,
            "migration_spec": migration_spec,
            "oidc_config": oidc_config,
            "make_token": make_token,
            "lock_path": lock_path,
            "backup_file": backup_file,
            "evidence_file": evidence_file,
            "manifest_file": manifest_file,
        }


def test_full_successful_deployment_with_evidence(deployer_fixtures):
    f = deployer_fixtures
    token = f["make_token"]("full-deploy-jti")

    ctx = DeploymentContext(
        service_name="support_bot",
        target_host="prod-server-01",
        artifact=f["artifact"],
        migration_spec=f["migration_spec"],
        oidc_token=token,
        oidc_config=f["oidc_config"],
        lock_path=f["lock_path"],
        backup_hook=f"{sys.executable} -c \"with open(r'{f['backup_file']}', 'w') as f: f.write('BACKUP')\"",
        backup_output_file=f["backup_file"],
        pull_command_fn=lambda ref: f["artifact"].immutable_digest,
        restart_command_fn=lambda: f["artifact"].immutable_digest,
        smoke_test_spec={"command": f"{sys.executable} -c 'pass'"},
        evidence_output_path=f["evidence_file"],
        evidence_manifest_path=f["manifest_file"],
    )

    res = f["deployer"].execute_deployment(ctx)

    assert res.success is True
    assert res.final_state == DeploymentState.DEPLOYMENT_VERIFIED
    assert res.final_verdict == FinalVerdictState.VERIFIED
    assert res.exit_code == ExitCode.SUCCESS
    assert res.backup_record is not None
    assert res.backup_record.verified is True
    assert res.approved_digest == f["artifact"].immutable_digest
    assert res.running_digest == f["artifact"].immutable_digest
    assert res.evidence_record is not None
    assert res.evidence_manifest is not None
    assert res.evidence_path == f["evidence_file"]
    assert res.manifest_path == f["manifest_file"]

    # Verify persisted evidence and manifest on disk
    is_valid, ev_dict, manifest, err = read_and_verify_persisted_evidence(
        f["evidence_file"],
        f["manifest_file"],
    )
    assert is_valid is True
    assert err is None
    assert ev_dict["final_verdict"]["state"] == "VERIFIED"
    assert ev_dict["authoritative_sources"]["artifact_provenance"]["immutable_digest"] == f["artifact"].immutable_digest

    # Verify step sequence history
    assert res.step_history == [
        "PROD_APPROVAL_PENDING",
        "PROD_AUTHORIZED",
        "LOCK_ACQUIRED",
        "PREFLIGHT",
        "PRE_DEPLOY_BACKUP",
        "MIGRATION",
        "PULL_BY_DIGEST",
        "RESTART",
        "POST_DEPLOY_VERIFY",
        "DEPLOYMENT_VERIFIED",
    ]
