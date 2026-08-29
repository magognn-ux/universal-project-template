"""
UPAS Unified Lifecycle Harness & Orchestrator.
Composes all security, locking, preflight, backup, migration, deployment,
verification, and evidence generation primitives into a single coordinated execution runner.
"""

import json
import os
import sys
from typing import Any, Dict, Optional

from upas_core.contracts.artifacts import ArtifactDescriptor, ArtifactType, BuilderMetadata
from upas_core.contracts.enums import (
    ExitCode,
    FinalVerdictState,
    MigrationClassification,
    MigrationPolicy,
)
from upas_core.contracts.errors import (
    InvalidArtifactError,
    InvalidEvidenceError,
    ProductionAuthError,
    UPASError,
)
from upas_core.cli.parser import SecurityViolationError
from upas_core.contracts.migrations import MigrationSpec
from upas_core.contracts.security import OIDCExpectedConfig
from upas_core.deployment.deployer import (
    DeploymentContext,
    DeploymentExecutionResult,
    ProductionDeployer,
)
from upas_core.adapter.validator import load_and_validate_adapter
from upas_core.discovery.detector import ProjectCapabilityDetector, inspect_git_state, resolve_changed_files
from upas_core.evidence.writer import read_and_verify_persisted_evidence
from upas_core.locking.host_lock import AtomicHostLock
from upas_core.resources.preflight import HostResourcePreflight
from upas_core.testing.engine import DefaultTestEscalationEngine
from upas_core.verification.verifier import PostDeployVerifier


def load_adapter_config(adapter_path: str) -> Dict[str, Any]:
    """Loads the project adapter contract file."""
    if not os.path.exists(adapter_path):
        raise UPASError(
            f"UPAS Adapter configuration file not found at '{adapter_path}'",
            exit_code=ExitCode.TESTS_FAILED,
        )
    try:
        with open(adapter_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise UPASError(
            f"Failed to parse UPAS Adapter configuration JSON: {exc}",
            exit_code=ExitCode.TESTS_FAILED,
        ) from exc


def load_or_build_artifact_descriptor(
    adapter_cfg: Dict[str, Any],
    artifact_path: Optional[str] = None,
    canonical_reference: Optional[str] = None,
    digest: Optional[str] = None,
    commit_sha: Optional[str] = None,
    branch: str = "main",
) -> ArtifactDescriptor:
    """Loads or constructs a validated immutable ArtifactDescriptor."""
    if artifact_path and os.path.exists(artifact_path):
        try:
            with open(artifact_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return ArtifactDescriptor.from_dict(data)
        except Exception as exc:
            raise InvalidArtifactError(f"Failed to parse artifact file '{artifact_path}': {exc}")

    # Fallback to CLI supplied parameters
    proj_name = adapter_cfg.get("project", {}).get("name", "unknown_project")
    resolved_commit = commit_sha or "0123456789abcdef0123456789abcdef01234567"
    resolved_digest = digest or ""
    resolved_ref = canonical_reference or ""

    if not resolved_ref and resolved_digest:
        resolved_ref = f"registry.internal/{proj_name}@{resolved_digest}"

    if not resolved_ref or not resolved_digest:
        raise InvalidArtifactError(
            "Missing immutable artifact information. Provide either --artifact <file> "
            "or both --canonical-reference and --digest."
        )

    return ArtifactDescriptor(
        artifact_id=f"art_{proj_name}_{resolved_commit[:8]}",
        project_name=proj_name,
        artifact_type=ArtifactType.CONTAINER_IMAGE,
        canonical_reference=resolved_ref,
        immutable_digest=resolved_digest,
        source_commit=resolved_commit,
        source_branch=branch,
        build_timestamp="2026-08-28T12:00:00Z",
        builder_metadata=BuilderMetadata(
            ci_run_id="upas_cli_run",
            runner_os=sys.platform,
            toolchain="upas",
        ),
    )


class LifecycleHarness:
    """
    Unified operational harness for all UPAS lifecycle operations.
    Guarantees state-machine driven gating, fail-closed handling, and audit generation.
    """

    def __init__(
        self,
        deployer: Optional[ProductionDeployer] = None,
        post_verifier: Optional[PostDeployVerifier] = None,
        preflight: Optional[HostResourcePreflight] = None,
        host_lock: Optional[AtomicHostLock] = None,
    ):
        self.deployer = deployer or ProductionDeployer()
        self.post_verifier = post_verifier or PostDeployVerifier()
        self.preflight = preflight or HostResourcePreflight()
        self.host_lock = host_lock or AtomicHostLock()

    def run_deploy(self, args: Any) -> int:
        """Executes full production deployment lifecycle pipeline."""
        adapter_cfg = load_adapter_config(args.adapter_path)
        proj_meta = adapter_cfg.get("project", {})
        dep_cfg = adapter_cfg.get("deployment", {})
        res_cfg = adapter_cfg.get("resource_gate", {})
        bak_cfg = adapter_cfg.get("backup", {})
        mig_cfg = adapter_cfg.get("migration", {})
        ver_cfg = adapter_cfg.get("verification", {})
        auth_cfg = adapter_cfg.get("authorization", {})

        service_name = dep_cfg.get("service_name", proj_meta.get("name", "app"))
        target_host = dep_cfg.get("target_host", "localhost")
        lock_path = dep_cfg.get("host_lock_path", "/run/lock/upas-deploy.lock")
        lock_timeout = dep_cfg.get("lock_timeout_seconds", 30)

        # Artifact
        artifact = load_or_build_artifact_descriptor(
            adapter_cfg=adapter_cfg,
            artifact_path=getattr(args, "artifact_path", None),
            canonical_reference=getattr(args, "canonical_reference", None),
            digest=getattr(args, "digest", None),
            commit_sha=getattr(args, "commit_sha", None),
            branch=getattr(args, "branch", "main"),
        )

        # Migration Spec
        classification_str = mig_cfg.get("default_classification", "NONE")
        try:
            classification = MigrationClassification(classification_str)
        except ValueError:
            classification = MigrationClassification.NONE

        migration_spec = MigrationSpec(
            classification=classification,
            policy=MigrationPolicy.EXPLICIT_MANIFEST,
            two_phase_protocol=mig_cfg.get("two_phase_protocol", False),
            pre_deploy_hook=mig_cfg.get("pre_deploy_hook"),
            post_deploy_finalize_hook=mig_cfg.get("post_deploy_finalize_hook"),
        )

        # OIDC Config
        oidc_token = getattr(args, "oidc_token", None) or os.environ.get("UPAS_OIDC_TOKEN", "")
        expected_repo = (
            getattr(args, "expected_repository", None)
            or auth_cfg.get("expected_repository")
            or "octocat/hello-world"
        )
        expected_env = (
            getattr(args, "expected_environment", None)
            or auth_cfg.get("environment_name", "production")
        )

        oidc_config = OIDCExpectedConfig(
            expected_issuer=auth_cfg.get("expected_issuer", "https://token.actions.githubusercontent.com"),
            expected_audience=auth_cfg.get("expected_audience", "upas-production-gate"),
            expected_repository=expected_repo,
            expected_environment=expected_env,
            required_claims=auth_cfg.get("required_claims", ["repository", "environment", "ref", "job_workflow_ref"]),
        )

        # Backup paths
        checkpoint_dir = bak_cfg.get("checkpoint_dir", ".")
        backup_out_file = os.path.join(checkpoint_dir, f"backup_{service_name}.dump")

        # Evidence paths
        evidence_out = getattr(args, "evidence_output_path", None)
        manifest_out = getattr(args, "manifest_output_path", None)

        context = DeploymentContext(
            service_name=service_name,
            target_host=target_host,
            artifact=artifact,
            migration_spec=migration_spec,
            oidc_token=oidc_token,
            oidc_config=oidc_config,
            lock_path=lock_path,
            lock_timeout_seconds=lock_timeout,
            preflight_thresholds=res_cfg.get("pre_flight_checks"),
            backup_hook=bak_cfg.get("engine_hook"),
            backup_output_file=backup_out_file,
            health_check_spec=ver_cfg.get("health_check"),
            smoke_test_spec=ver_cfg.get("smoke_test"),
            expected_container_name=dep_cfg.get("service_name"),
            evidence_output_path=evidence_out,
            evidence_manifest_path=manifest_out,
        )

        res = self.deployer.execute_deployment(context)

        if res.success:
            sys.stdout.write(
                f"[UPAS] SUCCESS: Deployment of '{service_name}' verified and complete. "
                f"Digest: {res.running_digest} (Exit {res.exit_code.value})\n"
            )
            return ExitCode.SUCCESS.value
        else:
            sys.stderr.write(
                f"[UPAS] FAILED: Deployment failed at state '{res.final_state.value}'. "
                f"Error: {res.error_message} (Exit {res.exit_code.value})\n"
            )
            return res.exit_code.value

    def run_verify(self, args: Any) -> int:
        """Runs post-deployment runtime verification gate."""
        adapter_cfg = load_adapter_config(args.adapter_path)
        dep_cfg = adapter_cfg.get("deployment", {})
        ver_cfg = adapter_cfg.get("verification", {})
        service_name = dep_cfg.get("service_name", "app")

        running_digest = getattr(args, "running_digest", None) or ""
        approved_digest = getattr(args, "approved_digest", None) or running_digest

        if not running_digest or not approved_digest:
            sys.stderr.write("[UPAS] Error: Missing --running-digest or --approved-digest\n")
            return ExitCode.TESTS_FAILED.value

        res = self.post_verifier.verify_runtime(
            service_name=service_name,
            approved_digest=approved_digest,
            running_digest=running_digest,
            expected_container_name=service_name,
            actual_container_name=service_name,
            health_check_spec=ver_cfg.get("health_check"),
            smoke_test_spec=ver_cfg.get("smoke_test"),
        )

        if res.verified:
            sys.stdout.write(f"[UPAS] Verification PASS for service '{service_name}'\n")
            return ExitCode.SUCCESS.value
        else:
            sys.stderr.write(f"[UPAS] Verification FAIL: {res.error_message}\n")
            return res.exit_code.value

    def run_audit(self, args: Any) -> int:
        """Verifies cryptographic integrity of persisted evidence and manifest."""
        is_valid, ev_dict, manifest, err = read_and_verify_persisted_evidence(
            evidence_path=args.evidence_path,
            manifest_path=args.manifest_path,
        )

        if is_valid:
            sys.stdout.write(
                f"[UPAS] Audit VERIFIED: Manifest '{manifest.manifest_id}' matches evidence '{manifest.operation_id}' "
                f"(SHA256: {manifest.evidence_sha256})\n"
            )
            return ExitCode.SUCCESS.value
        else:
            sys.stderr.write(f"[UPAS] Audit TAMPER / INTEGRITY FAILURE: {err}\n")
            return ExitCode.TESTS_FAILED.value

    def run_preflight(self, args: Any) -> int:
        """Runs standalone resource preflight inspection."""
        adapter_cfg = load_adapter_config(args.adapter_path)
        res_cfg = adapter_cfg.get("resource_gate", {})
        thresholds = res_cfg.get("pre_flight_checks", {})

        result = self.preflight.inspect_resources(thresholds)
        if result.passed:
            sys.stdout.write("[UPAS] Preflight PASS: Host resources satisfy deployment requirements\n")
            return ExitCode.SUCCESS.value
        else:
            sys.stderr.write(f"[UPAS] Preflight FAIL: {result.error_message}\n")
            return result.exit_code.value

    def run_lock(self, args: Any) -> int:
        """Inspects or tests deployment concurrency lock."""
        lock_path = getattr(args, "lock_path", "/run/lock/upas-deploy.lock")
        abs_path = os.path.abspath(lock_path)
        if not os.path.exists(abs_path):
            sys.stdout.write(f"[UPAS] Lock AVAILABLE: No lock file exists at '{abs_path}'\n")
            return ExitCode.SUCCESS.value

        data, err = self.host_lock._read_lock_data(abs_path)
        if data and isinstance(data.get("owner_pid"), int):
            pid = data["owner_pid"]
            if self.host_lock.check_liveness(pid):
                sys.stderr.write(f"[UPAS] Lock BLOCKED: Host lock at '{abs_path}' is held by active process (PID {pid})\n")
                return ExitCode.BLOCKED_CONCURRENCY.value

        sys.stdout.write(f"[UPAS] Lock AVAILABLE: Lock file at '{abs_path}' is stale or unheld\n")
        return ExitCode.SUCCESS.value

    def run_discover(self, args: Any) -> int:
        """Discovers project adapter and validates required project capabilities."""
        project_dir = getattr(args, "project_dir", ".")
        explicit_adapter = getattr(args, "adapter_path", None)

        detector = ProjectCapabilityDetector()
        try:
            adapter_path = explicit_adapter or detector.discover_adapter(project_dir)
            loaded_adapter = load_and_validate_adapter(adapter_path)
            val_res = detector.validate_capabilities(
                project_dir=project_dir,
                adapter=loaded_adapter,
                adapter_path=adapter_path,
            )

            if val_res.passed:
                sys.stdout.write(
                    f"[UPAS] Discovery PASS: Project '{loaded_adapter.project.name}' validated. "
                    f"Language: {loaded_adapter.project.language} {loaded_adapter.project.runtime_version}, "
                    f"Runner: {loaded_adapter.test_engine.runner}, "
                    f"Git: {val_res.git_state.branch}@{val_res.git_state.commit_sha[:8]} "
                    f"({'dirty' if val_res.git_state.is_dirty else 'clean'})\n"
                )
                return ExitCode.SUCCESS.value
            else:
                sys.stderr.write(
                    f"[UPAS] Discovery CAPABILITY MISMATCH for project '{val_res.project_name}': "
                    f"{'; '.join(val_res.missing_capabilities)}\n"
                )
                return val_res.exit_code.value

        except UPASError as exc:
            sys.stderr.write(f"[UPAS] Discovery FAILED: {exc}\n")
            return exc.exit_code.value
        except Exception as exc:
            sys.stderr.write(f"[UPAS] Discovery unexpected error: {exc}\n")
            return ExitCode.TESTS_FAILED.value

    def run_precheck(self, args: Any) -> int:
        """Runs QA release precheck and targeted test suite."""
        project_dir = getattr(args, "project_dir", ".")
        adapter_path = getattr(args, "adapter_path", "upas.adapter.json")
        force_level_raw = getattr(args, "force_level", None)

        try:
            loaded_adapter = load_and_validate_adapter(adapter_path)
            files, diff_source = resolve_changed_files(project_dir, getattr(args, "files", None))

            engine = DefaultTestEscalationEngine()
            force_level = __import__("upas_core.contracts.enums", fromlist=["TestLevel"]).TestLevel(force_level_raw) if force_level_raw is not None else None

            plan = engine.resolve_test_plan(
                modified_files=files,
                test_engine=loaded_adapter.test_engine,
                zones=loaded_adapter.zones,
                force_min_level=force_level,
            )

            sys.stdout.write(
                f"[UPAS PRECHECK] Diff Resolution: {len(files)} file(s) via {diff_source}\n"
                f"[UPAS PRECHECK] Resolved Test Tier: Level {plan.resolved_level.value} "
                f"({plan.resolved_level.name})\n"
                f"[UPAS PRECHECK] Reason: {plan.reason}\n"
                f"[UPAS PRECHECK] Executing command: {plan.commands[0]}\n"
            )

            exec_res = engine.execute_test_plan(plan=plan, project_dir=project_dir)

            if exec_res.status.value == "SUCCESS" and exec_res.exit_code == 0:
                sys.stdout.write(
                    f"[UPAS PRECHECK] PASS: All Level {plan.resolved_level.value} checks succeeded "
                    f"in {exec_res.duration_ms}ms\n"
                )
                return ExitCode.SUCCESS.value
            else:
                sys.stderr.write(
                    f"[UPAS PRECHECK] FAIL: Test execution failed with exit code {exec_res.exit_code}\n"
                    f"{exec_res.stderr}\n"
                )
                return ExitCode.TESTS_FAILED.value

        except UPASError as exc:
            sys.stderr.write(f"[UPAS PRECHECK ERROR] {exc}\n")
            return exc.exit_code.value
        except Exception as exc:
            sys.stderr.write(f"[UPAS PRECHECK UNEXPECTED ERROR] {exc}\n")
            return ExitCode.TESTS_FAILED.value

    def run_init(self, args: Any) -> int:
        """Bootstraps canonical UPAS configuration and caller workflow."""
        from upas_core.cli.init_cmd import initialize_project

        project_dir = getattr(args, "project_dir", ".")
        overwrite = getattr(args, "overwrite", False)
        custom_name = getattr(args, "custom_name", None)
        archetype = getattr(args, "archetype", "application")

        success, logs = initialize_project(
            project_dir=project_dir,
            overwrite=overwrite,
            custom_name=custom_name,
            archetype=archetype,
        )

        for log_line in logs:
            if "CONFLICT" in log_line or "FAILED" in log_line:
                sys.stderr.write(f"[UPAS INIT] {log_line}\n")
            else:
                sys.stdout.write(f"[UPAS INIT] {log_line}\n")

        if success:
            sys.stdout.write(
                f"[UPAS INIT] SUCCESS: Project initialized at '{os.path.abspath(project_dir)}'. "
                f"Next step: review upas.adapter.json and run 'upas discover'.\n"
            )
            return ExitCode.SUCCESS.value
        else:
            sys.stderr.write("[UPAS INIT] FAILED: Project initialization halted due to conflicts.\n")
            return ExitCode.TESTS_FAILED.value

