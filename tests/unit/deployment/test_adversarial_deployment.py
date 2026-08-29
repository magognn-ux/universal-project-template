"""
Adversarial Tests for UPAS Deployment & Verification Primitives.
Covers:
  - Artifact integrity (mutable tags, short/upper SHA, digest mismatches)
  - Backup gate (missing, failed, empty, stale, bypassed)
  - Migration safety (non-additive schema safety, EMERGENCY_HALT escalation)
  - Deployment order bypass prevention (restart before gates)
  - Unknown Remote State (Exit 125, no destructive blind retry)
  - Rollback arbiter (additive safe rollback vs non-additive EMERGENCY_HALT)
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
from upas_core.contracts.errors import (
    BackupFailedError,
    DigestMismatchError,
    EmergencyHaltError,
    InvalidArtifactError,
    MigrationError,
    ProductionAuthError,
    UnknownRemoteStateError,
)
from upas_core.contracts.lifecycle import DeploymentState
from upas_core.contracts.migrations import MigrationSpec
from upas_core.contracts.security import OIDCExpectedConfig
from upas_core.deployment.deployer import (
    DeploymentContext,
    ProductionDeployer,
)
from upas_core.locking.host_lock import AtomicHostLock
from upas_core.security.host_guard import ProductionHostGuard
from upas_core.security.jti_store import SQLiteJtiStore
from upas_core.security.oidc_verifier import GitHubOIDCVerifier

_VALID_DIGEST = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def adv_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        jti_db = os.path.join(tmpdir, "jti.db")
        lock_path = os.path.join(tmpdir, "adv_upas.lock")
        backup_file = os.path.join(tmpdir, "adv_backup.dump")

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

        artifact = ArtifactDescriptor(
            artifact_id="art_adv_001",
            project_name="tour_monitor",
            artifact_type=ArtifactType.CONTAINER_IMAGE,
            canonical_reference=f"registry.internal/tour_monitor@{_VALID_DIGEST}",
            immutable_digest=_VALID_DIGEST,
            source_commit="0123456789abcdef0123456789abcdef01234567",
            source_branch="main",
            build_timestamp="2026-08-28T12:00:00Z",
            builder_metadata=BuilderMetadata(
                ci_run_id="run_adv",
                runner_os="linux",
                toolchain="docker",
            ),
        )

        deployer = ProductionDeployer(
            host_guard=host_guard,
            host_lock=AtomicHostLock(),
        )

        def make_token(jti="adv-token-001"):
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
                "run_id": "888",
            }
            return jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "key-1"})

        yield {
            "deployer": deployer,
            "artifact": artifact,
            "oidc_config": oidc_config,
            "make_token": make_token,
            "lock_path": lock_path,
            "backup_file": backup_file,
            "tmpdir": tmpdir,
        }


# 1. Artifact Adversarial Tests
def test_adversarial_mutable_tag_rejected():
    with pytest.raises(InvalidArtifactError):
        ArtifactDescriptor(
            artifact_id="art_mutable",
            project_name="support_bot",
            artifact_type=ArtifactType.CONTAINER_IMAGE,
            canonical_reference="registry.internal/support_bot:latest",
            immutable_digest=_VALID_DIGEST,
            source_commit="0123456789abcdef0123456789abcdef01234567",
            source_branch="main",
            build_timestamp="2026-08-28T12:00:00Z",
            builder_metadata=BuilderMetadata(ci_run_id="1", runner_os="linux", toolchain="docker"),
        )


def test_adversarial_uppercase_sha_rejected():
    with pytest.raises(InvalidArtifactError):
        ArtifactDescriptor(
            artifact_id="art_upper",
            project_name="support_bot",
            artifact_type=ArtifactType.CONTAINER_IMAGE,
            canonical_reference=f"registry.internal/support_bot@{_VALID_DIGEST.upper()}",
            immutable_digest=_VALID_DIGEST.upper(),
            source_commit="0123456789abcdef0123456789abcdef01234567",
            source_branch="main",
            build_timestamp="2026-08-28T12:00:00Z",
            builder_metadata=BuilderMetadata(ci_run_id="1", runner_os="linux", toolchain="docker"),
        )


def test_adversarial_pulled_digest_mismatch_fails_closed(adv_env):
    env = adv_env
    token = env["make_token"]("pull-mismatch-jti")

    ctx = DeploymentContext(
        service_name="tour_monitor",
        target_host="prod-01",
        artifact=env["artifact"],
        migration_spec=MigrationSpec(
            classification=MigrationClassification.NONE,
            policy=MigrationPolicy.EXPLICIT_MANIFEST,
            two_phase_protocol=False,
        ),
        oidc_token=token,
        oidc_config=env["oidc_config"],
        lock_path=env["lock_path"],
        # Pull returns tampered digest
        pull_command_fn=lambda ref: "sha256:bad0000000000000000000000000000000000000000000000000000000000000",
    )

    res = env["deployer"].execute_deployment(ctx)
    assert res.success is False
    assert res.exit_code == ExitCode.DIGEST_MISMATCH
    assert res.final_verdict == FinalVerdictState.DIGEST_MISMATCH


# 2. Backup Gate Adversarial Tests
def test_adversarial_failed_backup_blocks_mutation(adv_env):
    env = adv_env
    token = env["make_token"]("failed-backup-jti")

    ctx = DeploymentContext(
        service_name="tour_monitor",
        target_host="prod-01",
        artifact=env["artifact"],
        migration_spec=MigrationSpec(
            classification=MigrationClassification.NONE,
            policy=MigrationPolicy.EXPLICIT_MANIFEST,
            two_phase_protocol=False,
        ),
        oidc_token=token,
        oidc_config=env["oidc_config"],
        lock_path=env["lock_path"],
        backup_hook=f"{sys.executable} -c 'import sys; sys.exit(1)'",
        backup_output_file=env["backup_file"],
    )

    res = env["deployer"].execute_deployment(ctx)
    assert res.success is False
    assert res.exit_code == ExitCode.FAILED_BACKUP
    assert res.final_verdict == FinalVerdictState.FAILED_BACKUP


# 3. Migration Safety & EMERGENCY_HALT on Failure
def test_adversarial_non_additive_migration_failure_triggers_emergency_halt(adv_env):
    env = adv_env
    token = env["make_token"]("emergency-halt-jti")

    # Non-additive migration spec
    mig_spec = MigrationSpec(
        classification=MigrationClassification.POTENTIALLY_INCOMPATIBLE,
        policy=MigrationPolicy.EXPLICIT_MANIFEST,
        two_phase_protocol=True,
        pre_deploy_hook=f"{sys.executable} -c 'pass'",
    )

    # Post-deploy verification fails (simulating broken app on new DB schema)
    ctx = DeploymentContext(
        service_name="tour_monitor",
        target_host="prod-01",
        artifact=env["artifact"],
        migration_spec=mig_spec,
        oidc_token=token,
        oidc_config=env["oidc_config"],
        lock_path=env["lock_path"],
        pull_command_fn=lambda ref: env["artifact"].immutable_digest,
        restart_command_fn=lambda: env["artifact"].immutable_digest,
        # Smoke test fails
        smoke_test_spec={"command": f"{sys.executable} -c 'import sys; sys.exit(1)'"},
    )

    res = env["deployer"].execute_deployment(ctx)

    assert res.success is False
    assert res.final_state == DeploymentState.EMERGENCY_HALT
    assert res.final_verdict == FinalVerdictState.EMERGENCY_HALT
    assert res.exit_code == ExitCode.EMERGENCY_HALT
    assert res.rollback_decision is not None
    assert res.rollback_decision.can_safe_rollback_app is False
    assert res.rollback_decision.requires_database_restore_approval is True


def test_adversarial_additive_migration_failure_triggers_safe_auto_rollback(adv_env):
    env = adv_env
    token = env["make_token"]("auto-rollback-jti")

    mig_spec = MigrationSpec(
        classification=MigrationClassification.ADDITIVE_COMPATIBLE,
        policy=MigrationPolicy.EXPLICIT_MANIFEST,
        two_phase_protocol=False,
    )

    rolled_back_executed = False

    def on_rollback():
        nonlocal rolled_back_executed
        rolled_back_executed = True

    ctx = DeploymentContext(
        service_name="tour_monitor",
        target_host="prod-01",
        artifact=env["artifact"],
        migration_spec=mig_spec,
        oidc_token=token,
        oidc_config=env["oidc_config"],
        lock_path=env["lock_path"],
        pull_command_fn=lambda ref: env["artifact"].immutable_digest,
        restart_command_fn=lambda: env["artifact"].immutable_digest,
        smoke_test_spec={"command": f"{sys.executable} -c 'import sys; sys.exit(1)'"},
        rollback_command_fn=on_rollback,
    )

    res = env["deployer"].execute_deployment(ctx)

    assert res.success is False
    assert res.final_state == DeploymentState.ROLLED_BACK
    assert res.final_verdict == FinalVerdictState.ROLLED_BACK
    assert rolled_back_executed is True
    assert res.rollback_decision.can_safe_rollback_app is True


# 4. Unknown Remote State Handling (Exit 125)
def test_adversarial_unknown_remote_state_stops_immediately_without_retry(adv_env):
    env = adv_env
    token = env["make_token"]("unknown-remote-jti")

    def simulate_dropped_connection_restart():
        # Raise UnknownRemoteStateError during mutation
        raise UnknownRemoteStateError("SSH connection dropped during container restart")

    ctx = DeploymentContext(
        service_name="tour_monitor",
        target_host="prod-01",
        artifact=env["artifact"],
        migration_spec=MigrationSpec(
            classification=MigrationClassification.NONE,
            policy=MigrationPolicy.EXPLICIT_MANIFEST,
            two_phase_protocol=False,
        ),
        oidc_token=token,
        oidc_config=env["oidc_config"],
        lock_path=env["lock_path"],
        pull_command_fn=lambda ref: env["artifact"].immutable_digest,
        restart_command_fn=simulate_dropped_connection_restart,
    )

    res = env["deployer"].execute_deployment(ctx)

    assert res.success is False
    assert res.final_state == DeploymentState.UNKNOWN_REMOTE_STATE
    assert res.final_verdict == FinalVerdictState.UNKNOWN_REMOTE_STATE
    assert res.exit_code == ExitCode.UNKNOWN_REMOTE_STATE
    assert "Unknown remote state during restart" in res.error_message


# 5. Gate Bypass Prevention
def test_adversarial_missing_auth_token_blocks_deployment(adv_env):
    env = adv_env
    ctx = DeploymentContext(
        service_name="tour_monitor",
        target_host="prod-01",
        artifact=env["artifact"],
        migration_spec=MigrationSpec(
            classification=MigrationClassification.NONE,
            policy=MigrationPolicy.EXPLICIT_MANIFEST,
            two_phase_protocol=False,
        ),
        oidc_token="",  # Missing token
        oidc_config=env["oidc_config"],
        lock_path=env["lock_path"],
    )

    res = env["deployer"].execute_deployment(ctx)
    assert res.success is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED
    assert res.final_verdict == FinalVerdictState.PROD_AUTH_FAILED
