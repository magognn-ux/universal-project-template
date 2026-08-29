"""
End-to-End Pilot Integration and Adversarial Verification Suite.
Validates the canonical UPAS lifecycle against Support Bot and verifies zero-bypass security invariants.
"""

import json
import os
from pathlib import Path
import sys
import tempfile
import time
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from upas_core.adapter.validator import load_and_validate_adapter
from upas_core.cli.main import main
from upas_core.contracts.artifacts import ArtifactDescriptor, ArtifactType, BuilderMetadata
from upas_core.contracts.enums import (
    ExitCode,
    FinalVerdictState,
    MigrationClassification,
    MigrationPolicy,
    TestLevel,
)
from upas_core.contracts.errors import (
    ApprovalDeniedError,
    ConcurrencyBlockedError,
    IncompatibleVersionError,
    ProductionAuthError,
)
from upas_core.cli.parser import SecurityViolationError
from upas_core.contracts.lifecycle import DeploymentState
from upas_core.contracts.migrations import MigrationSpec
from upas_core.contracts.security import OIDCExpectedConfig
from upas_core.deployment.deployer import (
    DeploymentContext,
    DeploymentExecutionResult,
    ProductionDeployer,
)
from upas_core.discovery.detector import (
    ProjectCapabilityDetector,
    discover_and_validate_project,
    inspect_git_state,
)
from upas_core.evidence.writer import read_and_verify_persisted_evidence
from upas_core.locking.host_lock import AtomicHostLock
from upas_core.security.host_guard import ProductionHostGuard
from upas_core.security.jti_store import SQLiteJtiStore
from upas_core.security.oidc_verifier import GitHubOIDCVerifier
from upas_core.testing.engine import DefaultTestEscalationEngine

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"


@pytest.fixture
def rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub


def make_signed_token(
    priv_key,
    repository="org/support-bot",
    environment="production",
    actor="release-manager",
    run_id="run_9999",
    ref="refs/heads/main",
    sha="a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
    jti="jti-pilot-1",
    exp_offset=3600,
):
    now = int(time.time())
    payload = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "upas-production-gate",
        "repository": repository,
        "environment": environment,
        "ref": ref,
        "job_workflow_ref": f"{repository}/.github/workflows/deploy.yml@{ref}",
        "sha": sha,
        "actor": actor,
        "run_id": run_id,
        "jti": jti,
        "exp": now + exp_offset,
        "sub": f"repo:{repository}:environment:{environment}",
    }
    return jwt.encode(payload, priv_key, algorithm="RS256", headers={"kid": "key-1"})


@pytest.fixture
def support_bot_adapter():
    adapter_path = FIXTURES_DIR / "valid" / "support_bot_adapter.json"
    return load_and_validate_adapter(str(adapter_path))


@pytest.fixture
def tour_monitor_adapter():
    adapter_path = FIXTURES_DIR / "valid" / "tour_monitor_adapter.json"
    return load_and_validate_adapter(str(adapter_path))


class TestSupportBotPilotLifecycle:
    """
    Authoritative test suite verifying the complete operational model for Support Bot:
    BUG → FIX → TARGETED TESTS → QA → HUMAN APPROVAL → OIDC AUTH → LOCK →
    PREFLIGHT → BACKUP → MIGRATION → IMMUTABLE DIGEST DEPLOY → VERIFY → EVIDENCE → RELEASE
    """

    def test_step1_project_discovery_and_capability_validation(self, support_bot_adapter):
        """Step 1 & 2: Project discovery & capability validation."""
        detector = ProjectCapabilityDetector()
        adapter_path = FIXTURES_DIR / "valid" / "support_bot_adapter.json"
        
        # Test discovery on the actual support_bot project directory if present
        support_bot_dir = Path("c:/Users/user/Projects/support_bot")
        if support_bot_dir.exists():
            val_res = detector.validate_capabilities(
                project_dir=str(support_bot_dir),
                adapter=support_bot_adapter,
                adapter_path=str(adapter_path),
            )
            assert val_res.project_name == "support_bot"
            assert val_res.exit_code == ExitCode.SUCCESS

    def test_step2_targeted_test_selection_for_bugfix(self, support_bot_adapter):
        """Step 3 & 4: Bug fix in utils resolves targeted Level 1 test plan."""
        engine = DefaultTestEscalationEngine()
        # Simulated bugfix in formatting.py
        modified_files = ["app/utils/formatting.py"]
        plan = engine.resolve_test_plan(
            modified_files=modified_files,
            test_engine=support_bot_adapter.test_engine,
            zones=support_bot_adapter.zones,
        )
        assert plan.resolved_level == TestLevel.L1
        assert "tests/test_formatting.py" in plan.target_tests
        assert "pytest" in plan.commands[0]

    def test_step3_production_approval_boundary_rejects_unauthorized_deploy(self, support_bot_adapter):
        """Step 5 & 6: Production approval boundary strictly forbids deployment without valid OIDC token."""
        deployer = ProductionDeployer()
        artifact = ArtifactDescriptor(
            artifact_id="art_support_bot_001",
            project_name="support_bot",
            artifact_type=ArtifactType.CONTAINER_IMAGE,
            canonical_reference="ghcr.io/org/support-bot@sha256:" + "a" * 64,
            immutable_digest="sha256:" + "a" * 64,
            source_commit="0123456789abcdef0123456789abcdef01234567",
            source_branch="main",
            build_timestamp="2026-08-28T12:00:00Z",
            builder_metadata=BuilderMetadata(ci_run_id="ci_1", runner_os="linux", toolchain="docker"),
        )
        ctx = DeploymentContext(
            service_name="support-bot",
            target_host="localhost",
            artifact=artifact,
            migration_spec=support_bot_adapter.to_migration_spec(),
            oidc_token="INVALID_TOKEN_STRING",
            oidc_config=support_bot_adapter.to_oidc_config(repository="org/support-bot"),
        )

        res = deployer.execute_deployment(ctx)
        assert res.success is False
        assert res.final_state == DeploymentState.PROD_APPROVAL_PENDING
        assert res.final_verdict == FinalVerdictState.PROD_AUTH_FAILED
        assert res.exit_code == ExitCode.PROD_AUTH_FAILED

    def test_step4_full_authorized_deployment_lifecycle(self, support_bot_adapter, rsa_keypair):
        """
        Step 7-15: Complete authorized lifecycle with locking, preflight, backup,
        migration, immutable digest pull, restart, verification, and cryptographic evidence.
        """
        priv, pub = rsa_keypair
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_file = os.path.join(tmpdir, "upas.lock")
            evidence_file = os.path.join(tmpdir, "support_bot.evidence.json")
            manifest_file = os.path.join(tmpdir, "support_bot.manifest.json")
            backup_file = os.path.join(tmpdir, "backup_support_bot.dump")
            jti_db = os.path.join(tmpdir, "jti.db")

            approved_digest = "sha256:" + "b" * 64
            commit_sha = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"

            # 1. Generate valid signed OIDC token
            repo = "org/support-bot"
            env = "production"
            valid_token = make_signed_token(
                priv_key=priv,
                repository=repo,
                environment=env,
                actor="release-manager",
                run_id="run_9999",
                ref="refs/heads/main",
                sha=commit_sha,
                jti="jti-pilot-valid-1",
            )

            # 2. Build verified artifact descriptor
            artifact = ArtifactDescriptor(
                artifact_id="art_support_bot_pilot",
                project_name="support_bot",
                artifact_type=ArtifactType.CONTAINER_IMAGE,
                canonical_reference=f"ghcr.io/org/support-bot@{approved_digest}",
                immutable_digest=approved_digest,
                source_commit=commit_sha,
                source_branch="main",
                build_timestamp="2026-08-28T12:00:00Z",
                builder_metadata=BuilderMetadata(ci_run_id="run_9999", runner_os="linux", toolchain="docker_buildx"),
            )

            verifier = GitHubOIDCVerifier(signing_keys={"key-1": pub})
            host_guard = ProductionHostGuard(verifier=verifier, jti_store=SQLiteJtiStore(jti_db))
            deployer = ProductionDeployer(host_guard=host_guard)

            # 3. Create context with simulated staging execution hooks
            ctx = DeploymentContext(
                service_name="support-bot",
                target_host="simulated-staging",
                artifact=artifact,
                migration_spec=MigrationSpec(
                    classification=MigrationClassification.ADDITIVE_COMPATIBLE,
                    policy=MigrationPolicy.EXPLICIT_MANIFEST,
                    two_phase_protocol=True,
                    pre_deploy_hook=f"{sys.executable} -c 'pass'",
                ),
                oidc_token=valid_token,
                oidc_config=support_bot_adapter.to_oidc_config(repository=repo),
                lock_path=lock_file,
                lock_timeout_seconds=10,
                preflight_thresholds={
                    "min_free_ram_mb": 10,
                    "max_swap_usage_pct": 99.0,
                    "max_1m_load_average": 99.0,
                    "min_free_disk_gb": 0.1,
                },
                backup_hook=None,  # triggers verified auto-snapshot
                backup_output_file=backup_file,
                pull_command_fn=lambda ref: approved_digest,
                restart_command_fn=lambda: approved_digest,
                health_check_spec={
                    "type": "custom_command",
                    "command": f"{sys.executable} -c 'pass'",
                    "timeout_seconds": 5,
                    "max_retries": 1,
                    "retry_interval_seconds": 1,
                },
                smoke_test_spec={
                    "type": "custom_command",
                    "command": f"{sys.executable} -c 'pass'",
                    "timeout_seconds": 5,
                },
                expected_container_name="support-bot",
                evidence_output_path=evidence_file,
                evidence_manifest_path=manifest_file,
            )

            res = deployer.execute_deployment(ctx)

            # Assert complete successful deployment state
            assert res.success is True
            assert res.final_state == DeploymentState.DEPLOYMENT_VERIFIED
            assert res.final_verdict == FinalVerdictState.VERIFIED
            assert res.exit_code == ExitCode.SUCCESS
            assert res.running_digest == approved_digest
            assert res.backup_record is not None
            assert res.backup_record.verified is True
            assert os.path.exists(evidence_file)
            assert os.path.exists(manifest_file)

            # Step 15: Cryptographic Audit Verification
            is_valid, ev_dict, manifest, err = read_and_verify_persisted_evidence(
                evidence_path=evidence_file,
                manifest_path=manifest_file,
            )
            assert is_valid is True
            assert err is None
            assert manifest.operation_id == ev_dict["operation_id"]
            assert manifest.final_state == "VERIFIED"


class TestAdversarialSecurityAndGateEnforcement:
    """
    Adversarial verification testing all attack vectors and gate bypass attempts.
    """

    def test_forbidden_bypass_flags_rejected(self):
        """Bypass flags (--force, --approve, --skip-auth) are strictly blocked with ExitCode 43."""
        for flag in ["--force", "-f", "--approve", "--skip-auth", "--insecure"]:
            code = main(["deploy", flag])
            assert code == ExitCode.PROD_AUTH_FAILED.value

    def test_forged_oidc_claims_rejected(self, support_bot_adapter, rsa_keypair):
        """Token with mismatched repository claim fails authorization gate."""
        priv, pub = rsa_keypair
        forged_token = make_signed_token(
            priv_key=priv,
            repository="attacker/malicious-repo",
            environment="production",
            actor="attacker",
            run_id="run_666",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            verifier = GitHubOIDCVerifier(signing_keys={"key-1": pub})
            host_guard = ProductionHostGuard(verifier=verifier, jti_store=SQLiteJtiStore(os.path.join(tmpdir, "jti.db")))
            deployer = ProductionDeployer(host_guard=host_guard)

            artifact = ArtifactDescriptor(
                artifact_id="art_adv",
                project_name="support_bot",
                artifact_type=ArtifactType.CONTAINER_IMAGE,
                canonical_reference="ghcr.io/org/support-bot@sha256:" + "c" * 64,
                immutable_digest="sha256:" + "c" * 64,
                source_commit="0000000000000000000000000000000000000000",
                source_branch="main",
                build_timestamp="2026-08-28T12:00:00Z",
                builder_metadata=BuilderMetadata(ci_run_id="ci_adv", runner_os="linux", toolchain="docker"),
            )
            ctx = DeploymentContext(
                service_name="support-bot",
                target_host="localhost",
                artifact=artifact,
                migration_spec=support_bot_adapter.to_migration_spec(),
                oidc_token=forged_token,
                oidc_config=support_bot_adapter.to_oidc_config(repository="org/support-bot"),
            )
            res = deployer.execute_deployment(ctx)
            assert res.success is False
            assert res.exit_code == ExitCode.PROD_AUTH_FAILED

    def test_tampered_evidence_audit_failure(self):
        """Tampering with evidence payload triggers immediate audit integrity failure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_file = os.path.join(tmpdir, "tampered.evidence.json")
            man_file = os.path.join(tmpdir, "tampered.manifest.json")

            from upas_core.evidence.writer import AtomicEvidenceWriter
            writer = AtomicEvidenceWriter()
            ev_data = {
                "operation_id": "op_audit_test",
                "correlation_id": "rel_audit_test",
                "authoritative_sources": {"artifact_provenance": {"immutable_digest": "sha256:" + "0" * 64}},
                "final_verdict": {"state": "VERIFIED", "exit_code": 0, "completed_at": "2026-08-28T12:00:00Z"},
            }
            writer.write_evidence_and_manifest(ev_data, ev_file, man_file)

            # Maliciously modify evidence after signing
            with open(ev_file, "r+", encoding="utf-8") as f:
                tampered = json.load(f)
                tampered["authoritative_sources"]["artifact_provenance"]["immutable_digest"] = "sha256:" + "f" * 64
                f.seek(0)
                json.dump(tampered, f)
                f.truncate()

            code = main(["audit", "--evidence", ev_file, "--manifest", man_file])
            assert code == ExitCode.TESTS_FAILED.value

    def test_non_additive_migration_failure_triggers_emergency_halt(self, support_bot_adapter, rsa_keypair):
        """Verification failure after POTENTIALLY_INCOMPATIBLE migration triggers EMERGENCY_HALT (Exit 81)."""
        priv, pub = rsa_keypair
        commit_sha = "1234567890abcdef1234567890abcdef12345678"
        digest = "sha256:" + "d" * 64

        valid_token = make_signed_token(
            priv_key=priv,
            repository="org/support-bot",
            environment="production",
            actor="admin",
            run_id="run_1",
            sha=commit_sha,
            jti="jti-halt-1",
        )
        artifact = ArtifactDescriptor(
            artifact_id="art_halt",
            project_name="support_bot",
            artifact_type=ArtifactType.CONTAINER_IMAGE,
            canonical_reference=f"ghcr.io/org/support-bot@{digest}",
            immutable_digest=digest,
            source_commit=commit_sha,
            source_branch="main",
            build_timestamp="2026-08-28T12:00:00Z",
            builder_metadata=BuilderMetadata(ci_run_id="run_1", runner_os="linux", toolchain="docker"),
        )
        # Non-additive migration spec
        mig_spec = MigrationSpec(
            classification=MigrationClassification.POTENTIALLY_INCOMPATIBLE,
            policy=MigrationPolicy.EXPLICIT_MANIFEST,
            two_phase_protocol=True,
            pre_deploy_hook=f"{sys.executable} -c 'pass'",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            verifier = GitHubOIDCVerifier(signing_keys={"key-1": pub})
            host_guard = ProductionHostGuard(verifier=verifier, jti_store=SQLiteJtiStore(os.path.join(tmpdir, "jti.db")))
            deployer = ProductionDeployer(host_guard=host_guard)

            ctx = DeploymentContext(
                service_name="support-bot",
                target_host="localhost",
                artifact=artifact,
                migration_spec=mig_spec,
                oidc_token=valid_token,
                oidc_config=support_bot_adapter.to_oidc_config(repository="org/support-bot"),
                lock_path=os.path.join(tmpdir, "lock.file"),
                health_check_spec={
                    "type": "custom_command",
                    "command": f"{sys.executable} -c 'import sys; sys.exit(1)'",  # Intentional fail
                    "timeout_seconds": 1,
                    "max_retries": 1,
                    "retry_interval_seconds": 1,
                },
            )
            res = deployer.execute_deployment(ctx)
            assert res.success is False
            assert res.final_state == DeploymentState.EMERGENCY_HALT
            assert res.final_verdict == FinalVerdictState.EMERGENCY_HALT
            assert res.exit_code == ExitCode.EMERGENCY_HALT


class TestProjectIsolation:
    """
    Verifies that UPAS remains 100% universal across projects without project-specific branching.
    """

    def test_support_bot_and_tour_monitor_adapters_run_on_same_universal_engine(
        self, support_bot_adapter, tour_monitor_adapter
    ):
        """Both project adapters are parsed and validated by the exact same engine without branching."""
        assert support_bot_adapter.project.name == "support_bot"
        assert tour_monitor_adapter.project.name == "tour_monitor"

        engine = DefaultTestEscalationEngine()

        # Support Bot test plan resolution
        sb_plan = engine.resolve_test_plan(
            modified_files=["app/db/migrations.py"],
            test_engine=support_bot_adapter.test_engine,
            zones=support_bot_adapter.zones,
        )
        assert sb_plan.resolved_level == TestLevel.L5

        # Tour Monitor test plan resolution
        tm_plan = engine.resolve_test_plan(
            modified_files=["core/notification_service.py"],
            test_engine=tour_monitor_adapter.test_engine,
            zones=tour_monitor_adapter.zones,
        )
        assert tm_plan.resolved_level == TestLevel.L2
