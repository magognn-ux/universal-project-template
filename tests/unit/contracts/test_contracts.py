"""
Unit tests for UPAS Phase 2B Core Contracts.
Verifies all contract enums, errors, data classes, state machines, and evidence schemas.
"""

import json
from pathlib import Path
import pytest
import jsonschema

from upas_core.contracts import (
    ApprovalDeniedError,
    ArtifactDescriptor,
    ArtifactProvenanceRecord,
    ArtifactType,
    ArtifactVerificationResult,
    AuthoritativeSourcesRecord,
    AuthPolicy,
    AuthResult,
    BuilderMetadata,
    ChangeLifecycleStateMachine,
    ChangeState,
    CiExecutionRecord,
    CommandSpec,
    CompatibilityResult,
    ConcurrencyBlockedError,
    DeploymentLifecycleStateMachine,
    DeploymentState,
    DigestMismatchError,
    EmergencyHaltError,
    EscalationTriggers,
    EscalationViolationError,
    EvidenceRecord,
    EvidenceType,
    ExecutionResult,
    ExecutionStatus,
    ExitCode,
    FinalVerdictRecord,
    FinalVerdictState,
    GitDagRecord,
    GuardResult,
    HostLockStateRecord,
    HostRuntimeRecord,
    IncompatibleVersionError,
    InfraAccess,
    InfraType,
    InvalidArtifactError,
    InvalidEvidenceError,
    InvalidStateTransitionError,
    LockHandle,
    LockResult,
    MigrationClassification,
    MigrationError,
    MigrationPolicy,
    MigrationResult,
    MigrationSpec,
    OIDCClaims,
    OIDCExpectedConfig,
    PreflightFailedError,
    PreflightResult,
    ProductionAuthorizationRecord,
    ProductionAuthError,
    ProjectRecord,
    ReleaseLifecycleStateMachine,
    ReleaseState,
    RiskLevel,
    RollbackDecision,
    SharedInfraViolationError,
    StepEvidenceRecord,
    StepResult,
    StepStatus,
    TestLevel,
    TestMapEntry,
    TestPlan,
    UPASError,
    ZoneSpec,
    # Protocols
    ArtifactVerifier,
    CapabilityValidator,
    CommandRunner,
    CompatibilityChecker,
    EvidenceGenerator,
    HostGuard,
    HostLock,
    InfrastructureGuard,
    JtiStore,
    MigrationOrchestrator,
    OIDCVerifier,
    ResourcePreflight,
    RollbackSafetyArbiter,
    TestEscalationEngine,
)


class TestExitCodesAndEnums:
    def test_exit_codes_are_unique(self):
        codes = [e.value for e in ExitCode]
        assert len(codes) == len(set(codes)), "All UPAS ExitCode values must be distinct"

    def test_canonical_exit_code_values(self):
        assert ExitCode.SUCCESS == 0
        assert ExitCode.TESTS_FAILED == 1
        assert ExitCode.CAPABILITY_MISMATCH == 2
        assert ExitCode.INVALID_EVIDENCE_STATE == 3
        assert ExitCode.APPROVAL_DENIED == 42
        assert ExitCode.PROD_AUTH_FAILED == 43
        assert ExitCode.DIGEST_MISMATCH == 65
        assert ExitCode.FAILED_PULL == 66
        assert ExitCode.MIGRATION_FAILED == 70
        assert ExitCode.BLOCKED_CONCURRENCY == 75
        assert ExitCode.SHARED_INFRA_VIOLATION == 77
        assert ExitCode.FAILED_BACKUP == 78
        assert ExitCode.FAILED_PREFLIGHT == 79
        assert ExitCode.ESCALATION_VIOLATION == 80
        assert ExitCode.EMERGENCY_HALT == 81
        assert ExitCode.EXECUTION_TIMEOUT == 124
        assert ExitCode.UNKNOWN_REMOTE_STATE == 125
        assert ExitCode.INCOMPATIBLE_VERSION_ERROR == 126

    def test_error_classes_map_to_exit_codes(self):
        assert IncompatibleVersionError("test").exit_code == ExitCode.INCOMPATIBLE_VERSION_ERROR
        assert ProductionAuthError("test").exit_code == ExitCode.PROD_AUTH_FAILED
        assert ApprovalDeniedError("test").exit_code == ExitCode.APPROVAL_DENIED
        assert ConcurrencyBlockedError("test").exit_code == ExitCode.BLOCKED_CONCURRENCY
        assert DigestMismatchError("test").exit_code == ExitCode.DIGEST_MISMATCH
        assert MigrationError("test").exit_code == ExitCode.MIGRATION_FAILED
        assert EmergencyHaltError("test").exit_code == ExitCode.EMERGENCY_HALT
        assert EscalationViolationError("test").exit_code == ExitCode.ESCALATION_VIOLATION
        assert SharedInfraViolationError("test").exit_code == ExitCode.SHARED_INFRA_VIOLATION
        assert PreflightFailedError("test").exit_code == ExitCode.FAILED_PREFLIGHT


class TestLifecycleStateMachines:
    def test_change_lifecycle_valid_transitions(self):
        sm = ChangeLifecycleStateMachine(ChangeState.DRAFT)
        assert sm.current_state == ChangeState.DRAFT
        sm.transition_to(ChangeState.MODIFIED)
        sm.transition_to(ChangeState.TESTED)
        sm.transition_to(ChangeState.PRECHECK_OK)
        sm.transition_to(ChangeState.COMMITTED)
        assert sm.current_state == ChangeState.COMMITTED

    def test_change_lifecycle_illegal_transition_fails(self):
        sm = ChangeLifecycleStateMachine(ChangeState.DRAFT)
        with pytest.raises(InvalidStateTransitionError):
            sm.transition_to(ChangeState.COMMITTED)

    def test_release_lifecycle_valid_transitions(self):
        sm = ReleaseLifecycleStateMachine(ReleaseState.CI_TRIGGERED)
        sm.transition_to(ReleaseState.CI_TESTING)
        sm.transition_to(ReleaseState.ARTIFACT_BUILDING)
        sm.transition_to(ReleaseState.DIGEST_PINNED)
        sm.transition_to(ReleaseState.RELEASE_CANDIDATE_READY)
        assert sm.current_state == ReleaseState.RELEASE_CANDIDATE_READY

    def test_release_lifecycle_illegal_transition_fails(self):
        sm = ReleaseLifecycleStateMachine(ReleaseState.CI_TRIGGERED)
        with pytest.raises(InvalidStateTransitionError):
            sm.transition_to(ReleaseState.RELEASE_CANDIDATE_READY)

    def test_deployment_lifecycle_valid_path(self):
        sm = DeploymentLifecycleStateMachine(DeploymentState.PROD_APPROVAL_PENDING)
        sm.transition_to(DeploymentState.PROD_AUTHORIZED)
        sm.transition_to(DeploymentState.LOCK_ACQUIRED)
        sm.transition_to(DeploymentState.PREFLIGHT)
        sm.transition_to(DeploymentState.PRE_DEPLOY_BACKUP)
        sm.transition_to(DeploymentState.MIGRATION)
        sm.transition_to(DeploymentState.PULL_BY_DIGEST)
        sm.transition_to(DeploymentState.RESTART)
        sm.transition_to(DeploymentState.POST_DEPLOY_VERIFY)
        sm.transition_to(DeploymentState.DEPLOYMENT_VERIFIED)
        assert sm.current_state == DeploymentState.DEPLOYMENT_VERIFIED

    def test_deployment_lifecycle_illegal_bypass_fails(self):
        sm = DeploymentLifecycleStateMachine(DeploymentState.PROD_APPROVAL_PENDING)
        # Attempting direct deploy without approval
        with pytest.raises(InvalidStateTransitionError):
            sm.transition_to(DeploymentState.DEPLOYMENT_VERIFIED)


class TestExecutionContracts:
    def test_valid_command_spec(self):
        spec = CommandSpec(argv=["pytest", "-v"], timeout_seconds=60)
        assert spec.argv == ["pytest", "-v"]
        assert spec.timeout_seconds == 60

    def test_command_spec_forbids_raw_string(self):
        with pytest.raises(TypeError):
            CommandSpec(argv="pytest -v", timeout_seconds=60)  # type: ignore

    def test_command_spec_forbids_empty_argv(self):
        with pytest.raises(ValueError):
            CommandSpec(argv=[], timeout_seconds=60)

    def test_command_spec_forbids_non_positive_timeout(self):
        with pytest.raises(ValueError):
            CommandSpec(argv=["echo", "hello"], timeout_seconds=0)

    def test_execution_result_properties(self):
        res = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            stdout="ok",
            stderr="",
            duration_ms=150,
            command=["pytest"],
        )
        assert res.is_success is True
        assert res.is_timeout is False

        res_timeout = ExecutionResult(
            status=ExecutionStatus.TIMEOUT,
            exit_code=124,
            stdout="",
            stderr="timed out",
            duration_ms=60000,
            command=["pytest"],
        )
        assert res_timeout.is_success is False
        assert res_timeout.is_timeout is True


class TestSecurityContracts:
    def test_valid_oidc_claims(self):
        claims = OIDCClaims(
            iss="https://token.actions.githubusercontent.com",
            aud="upas-production-gate",
            repository="org/repo",
            environment="production",
            ref="refs/heads/main",
            job_workflow_ref="org/repo/.github/workflows/deploy.yml@refs/heads/main",
            jti="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            exp=1800000000,
            actor="octocat",
            run_id="123456",
        )
        assert claims.iss == "https://token.actions.githubusercontent.com"
        d = claims.to_dict()
        assert d["repository"] == "org/repo"
        assert d["environment"] == "production"

    def test_oidc_claims_missing_mandatory_fails(self):
        with pytest.raises(ValueError):
            OIDCClaims(
                iss="",
                aud="aud",
                repository="repo",
                environment="prod",
                ref="ref",
                job_workflow_ref="job",
                jti="jti",
                exp=1000,
            )

    def test_auth_result_consistency(self):
        # Valid success
        res = AuthResult(
            authenticated=True,
            policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
            actor="octocat",
            run_id="123",
            environment="production",
            approval_timestamp="2026-08-28T12:00:00Z",
            exit_code=ExitCode.SUCCESS,
        )
        assert res.authenticated is True

        # Inconsistent: authenticated=True with non-zero exit code
        with pytest.raises(ValueError):
            AuthResult(
                authenticated=True,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="octocat",
                run_id="123",
                environment="production",
                approval_timestamp="2026-08-28T12:00:00Z",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )


class TestArtifactContracts:
    def test_valid_artifact_descriptor(self):
        sha = "a" * 64
        art = ArtifactDescriptor(
            artifact_id="art_tour_monitor_build_42",
            project_name="tour_monitor",
            artifact_type=ArtifactType.CONTAINER_IMAGE,
            canonical_reference=f"ghcr.io/org/tour-monitor@sha256:{sha}",
            immutable_digest=f"sha256:{sha}",
            source_commit="b" * 40,
            source_branch="main",
            build_timestamp="2026-08-28T12:00:00Z",
            builder_metadata=BuilderMetadata(ci_run_id="123", runner_os="ubuntu-latest", toolchain="docker-24.0"),
        )
        assert art.immutable_digest == f"sha256:{sha}"

    def test_artifact_descriptor_tag_only_fails(self):
        with pytest.raises(InvalidArtifactError):
            ArtifactDescriptor(
                artifact_id="art_1",
                project_name="proj",
                artifact_type=ArtifactType.CONTAINER_IMAGE,
                canonical_reference="ghcr.io/org/proj:latest",
                immutable_digest="sha256:latest",
                source_commit="b" * 40,
                source_branch="main",
                build_timestamp="2026-08-28T12:00:00Z",
                builder_metadata=BuilderMetadata(ci_run_id="1", runner_os="linux", toolchain="docker"),
            )

    def test_artifact_descriptor_mismatched_digest_fails(self):
        sha1 = "a" * 64
        sha2 = "b" * 64
        with pytest.raises(InvalidArtifactError):
            ArtifactDescriptor(
                artifact_id="art_1",
                project_name="proj",
                artifact_type=ArtifactType.CONTAINER_IMAGE,
                canonical_reference=f"ghcr.io/org/proj@sha256:{sha1}",
                immutable_digest=f"sha256:{sha2}",
                source_commit="c" * 40,
                source_branch="main",
                build_timestamp="2026-08-28T12:00:00Z",
                builder_metadata=BuilderMetadata(ci_run_id="1", runner_os="linux", toolchain="docker"),
            )


class TestMigrationContracts:
    def test_incompatible_migration_requires_two_phase_protocol(self):
        # Valid: two_phase_protocol=True
        spec = MigrationSpec(
            classification=MigrationClassification.POTENTIALLY_INCOMPATIBLE,
            policy=MigrationPolicy.EXPLICIT_MANIFEST,
            two_phase_protocol=True,
            pre_deploy_hook="alembic upgrade +1",
        )
        assert spec.two_phase_protocol is True

        # Invalid: two_phase_protocol=False with POTENTIALLY_INCOMPATIBLE
        with pytest.raises(MigrationError):
            MigrationSpec(
                classification=MigrationClassification.POTENTIALLY_INCOMPATIBLE,
                policy=MigrationPolicy.EXPLICIT_MANIFEST,
                two_phase_protocol=False,
            )

    def test_rollback_safety_arbiter_decisions(self):
        # Additive migration -> auto rollback allowed
        dec_additive = RollbackDecision.for_classification(
            MigrationClassification.ADDITIVE_COMPATIBLE, "App container failed smoke check"
        )
        assert dec_additive.can_safe_rollback_app is True
        assert dec_additive.target_state == FinalVerdictState.ROLLED_BACK

        # Incompatible migration -> auto rollback FORBIDDEN, triggers EMERGENCY_HALT
        dec_incomp = RollbackDecision.for_classification(
            MigrationClassification.POTENTIALLY_INCOMPATIBLE, "App container crashed on startup"
        )
        assert dec_incomp.can_safe_rollback_app is False
        assert dec_incomp.requires_database_restore_approval is True
        assert dec_incomp.target_state == FinalVerdictState.EMERGENCY_HALT


class TestTestingBudgetContracts:
    def test_test_level_ordering(self):
        assert TestLevel.L0 < TestLevel.L1 < TestLevel.L2 < TestLevel.L3 < TestLevel.L4 < TestLevel.L5

    def test_escalation_triggers_database_migrations_enforced(self):
        # Valid: level 4 or 5
        triggers = EscalationTriggers(
            database_migrations=5,
            database_schemas=4,
            api_contracts=3,
            runtime_configuration=3,
            dependency_manifests=4,
            infrastructure_manifests=4,
            security_sensitive_files=5,
        )
        assert triggers.database_migrations == 5

        # Invalid: level 3 for DB migrations
        with pytest.raises(ValueError):
            EscalationTriggers(
                database_migrations=3,
                database_schemas=4,
                api_contracts=3,
                runtime_configuration=3,
                dependency_manifests=4,
                infrastructure_manifests=4,
                security_sensitive_files=5,
            )

    def test_test_plan_no_downgrade(self):
        plan = TestPlan(
            resolved_level=TestLevel.L4,
            commands=["pytest tests/l4_arch"],
            target_tests=["tests/l4_arch"],
            reason="Database migration changed",
        )
        # Cannot downgrade to L1
        with pytest.raises(EscalationViolationError):
            plan.escalate_to(TestLevel.L1, "Attempting downgrade")

        # Can escalate to L5
        escalated = plan.escalate_to(TestLevel.L5, "Full release gate requested")
        assert escalated.resolved_level == TestLevel.L5


class TestEvidenceRecordContract:
    def test_evidence_record_matches_schema(self):
        sha = "a" * 64
        commit = "c" * 40
        record = EvidenceRecord(
            evidence_type=EvidenceType.DEPLOYMENT_AUDIT_RECORD,
            operation_id="op_deploy_prod_12345",
            correlation_id="rel_2026_08_28_001",
            project=ProjectRecord(
                name="tour_monitor",
                type="application",
                adapter_version="1.0.0",
            ),
            authoritative_sources=AuthoritativeSourcesRecord(
                git_dag=GitDagRecord(
                    commit_sha=commit,
                    branch="main",
                    dirty_tree=False,
                ),
                ci_execution=CiExecutionRecord(
                    provider="github_actions",
                    run_id="987654321",
                    workflow_ref="org/repo/.github/workflows/deploy.yml@refs/heads/main",
                    conclusion="success",
                ),
                artifact_provenance=ArtifactProvenanceRecord(
                    immutable_digest=f"sha256:{sha}",
                    canonical_reference=f"ghcr.io/org/tour-monitor@sha256:{sha}",
                    verified_running_digest=f"sha256:{sha}",
                ),
                production_authorization=ProductionAuthorizationRecord(
                    policy="github_environment_oidc",
                    actor="release-manager",
                    run_id="987654321",
                    environment="production",
                    approval_timestamp="2026-08-28T12:00:00Z",
                    oidc_claims={"aud": "upas-production-gate", "iss": "https://token.actions.githubusercontent.com"},
                ),
                host_runtime=HostRuntimeRecord(
                    host_identity="srv-prod-node-01",
                    kernel_timestamp="2026-08-28T12:01:00Z",
                    lock_state=HostLockStateRecord(
                        lock_acquired=True,
                        lock_path="/run/lock/upas-deploy.lock",
                        lock_owner_pid=1234,
                    ),
                ),
            ),
            steps=[
                StepEvidenceRecord(
                    name="preflight_check",
                    status="PASS",
                    exit_code=0,
                    duration_ms=45,
                    details={"ram_free_mb": 4096},
                )
            ],
            final_verdict=FinalVerdictRecord(
                state=FinalVerdictState.VERIFIED,
                exit_code=0,
                completed_at="2026-08-28T12:05:00Z",
                total_duration_ms=240000,
                summary="Deployment successfully verified.",
            ),
        )

        d = record.to_dict()
        schema_path = Path(__file__).parents[3] / "schemas" / "evidence.schema.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        # Validate against authoritative frozen evidence.schema.json
        jsonschema.validate(instance=d, schema=schema)


class TestRuntimeProtocols:
    def test_protocol_implementations(self):
        class DummyRunner:
            def run(self, spec: CommandSpec) -> ExecutionResult:
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    stdout="",
                    stderr="",
                    duration_ms=10,
                    command=spec.argv,
                )

        assert isinstance(DummyRunner(), CommandRunner)
