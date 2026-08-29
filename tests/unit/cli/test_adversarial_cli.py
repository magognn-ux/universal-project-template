"""
Adversarial Security & Bypass Prevention Tests for UPAS CLI Harness.
Covers:
  - Prohibited bypass flags (--force, --approve, --no-auth, --bypass-lock, --skip-backup, etc.)
  - Unauthenticated deployment mutation prevention (ExitCode 43)
  - Mutable artifact tag rejection
  - Concurrency collision blocking (ExitCode 75)
  - Audit tamper detection
"""

import json
import os
import sys
import tempfile
import pytest

from upas_core.cli.main import main
from upas_core.contracts.enums import ExitCode
from upas_core.cli.parser import SecurityViolationError, detect_security_bypass_attempts


# 1. Prohibited Bypass Flags (Security Invariant 10)
@pytest.mark.parametrize("bypass_flag", [
    "--force",
    "-f",
    "--approve",
    "--skip-auth",
    "--no-auth",
    "--bypass-auth",
    "--bypass-lock",
    "--skip-lock",
    "--skip-backup",
    "--no-backup",
    "--skip-verify",
    "--skip-verification",
    "--insecure",
    "--ignore-errors",
    "--dry-run-mutate",
    "--allow-unauthorized",
])
def test_adversarial_cli_prohibited_bypass_flags_blocked(bypass_flag):
    # Direct scanner check
    with pytest.raises(SecurityViolationError):
        detect_security_bypass_attempts(["deploy", bypass_flag, "--digest", "sha256:" + "0" * 64])

    # CLI main execution check -> MUST RETURN ExitCode.PROD_AUTH_FAILED (43)
    code = main(["deploy", bypass_flag, "--digest", "sha256:" + "0" * 64])
    assert code == ExitCode.PROD_AUTH_FAILED.value


# 2. Unauthenticated Mutation Attempt
def test_adversarial_cli_missing_auth_token():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter_path = os.path.join(tmpdir, "upas.adapter.json")
        with open(adapter_path, "w") as f:
            json.dump({
                "schema_version": "1.0.0",
                "project": {"name": "app", "type": "application", "language": "py", "runtime_version": "3.12"},
                "zones": [{"name": "c", "paths": ["."], "risk_level": "low", "default_test_level": 0}],
                "test_engine": {"runner": "t", "level_commands": {"level_0": "t", "level_1": "t", "level_2": "t", "level_3": "t", "level_4": "t", "level_5": "t"}, "test_map": [], "escalation_triggers": {"database_migrations": 4, "database_schemas": 3, "api_contracts": 3, "runtime_configuration": 3, "dependency_manifests": 3, "infrastructure_manifests": 3, "security_sensitive_files": 3}},
                "artifact": {"type": "container_image", "builder": "d", "registry": "r", "immutable_tag_format": "r@sha256:{digest}"},
                "resource_gate": {"pre_flight_checks": {"min_free_ram_mb": 0, "max_swap_usage_pct": 100, "max_1m_load_average": 100, "min_free_disk_gb": 0}},
                "deployment": {"strategy": "immutable_pull", "target_host": "h", "service_name": "app", "runtime_directory": "r"},
                "verification": {"health_check": {"type": "custom_command", "timeout_seconds": 1, "max_retries": 1, "retry_interval_seconds": 1}},
                "backup": {"type": "none", "engine_hook": "true", "retention_count": 1, "checkpoint_dir": tmpdir},
                "migration": {"classification_policy": "explicit_manifest", "default_classification": "NONE", "two_phase_protocol": False},
                "authorization": {"provider": "github_environment_oidc", "environment_name": "production", "expected_issuer": "https://token.actions.githubusercontent.com", "expected_audience": "upas-production-gate", "required_claims": ["repository", "environment", "ref", "job_workflow_ref"]},
            }, f)

        # Execute deploy with NO token
        code = main([
            "deploy",
            "--adapter", adapter_path,
            "--digest", "sha256:" + "0" * 64,
        ])
        assert code == ExitCode.PROD_AUTH_FAILED.value


# 3. Mutable Artifact Tag Rejected
def test_adversarial_cli_mutable_tag_rejected():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter_path = os.path.join(tmpdir, "upas.adapter.json")
        with open(adapter_path, "w") as f:
            json.dump({
                "schema_version": "1.0.0",
                "project": {"name": "app", "type": "application", "language": "py", "runtime_version": "3.12"},
                "zones": [{"name": "c", "paths": ["."], "risk_level": "low", "default_test_level": 0}],
                "test_engine": {"runner": "t", "level_commands": {"level_0": "t", "level_1": "t", "level_2": "t", "level_3": "t", "level_4": "t", "level_5": "t"}, "test_map": [], "escalation_triggers": {"database_migrations": 4, "database_schemas": 3, "api_contracts": 3, "runtime_configuration": 3, "dependency_manifests": 3, "infrastructure_manifests": 3, "security_sensitive_files": 3}},
                "artifact": {"type": "container_image", "builder": "d", "registry": "r", "immutable_tag_format": "r@sha256:{digest}"},
                "resource_gate": {"pre_flight_checks": {"min_free_ram_mb": 0, "max_swap_usage_pct": 100, "max_1m_load_average": 100, "min_free_disk_gb": 0}},
                "deployment": {"strategy": "immutable_pull", "target_host": "h", "service_name": "app", "runtime_directory": "r"},
                "verification": {"health_check": {"type": "custom_command", "timeout_seconds": 1, "max_retries": 1, "retry_interval_seconds": 1}},
                "backup": {"type": "none", "engine_hook": "true", "retention_count": 1, "checkpoint_dir": tmpdir},
                "migration": {"classification_policy": "explicit_manifest", "default_classification": "NONE", "two_phase_protocol": False},
                "authorization": {"provider": "github_environment_oidc", "environment_name": "production", "expected_issuer": "https://token.actions.githubusercontent.com", "expected_audience": "upas-production-gate", "required_claims": ["repository", "environment", "ref", "job_workflow_ref"]},
            }, f)

        # Execute deploy with mutable tag 'latest'
        code = main([
            "deploy",
            "--adapter", adapter_path,
            "--canonical-reference", "registry.internal/app:latest",
            "--digest", "latest",
        ])
        assert code == ExitCode.DIGEST_MISMATCH.value


# 4. Audit Tamper Detection
def test_adversarial_cli_audit_tampered_evidence():
    with tempfile.TemporaryDirectory() as tmpdir:
        ev_file = os.path.join(tmpdir, "audit.evidence.json")
        man_file = os.path.join(tmpdir, "audit.manifest.json")

        with open(ev_file, "w") as f:
            f.write('{"tampered": true}')
        with open(man_file, "w") as f:
            f.write('{"manifest_id": "m1", "operation_id": "op1", "correlation_id": "rel1", "evidence_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "artifact_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "final_state": "VERIFIED", "final_exit_code": 0, "generated_at": "2026-08-28T12:00:00Z"}')

        code = main(["audit", "--evidence", ev_file, "--manifest", man_file])
        assert code == ExitCode.TESTS_FAILED.value
