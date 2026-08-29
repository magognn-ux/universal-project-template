"""
Unit tests for UPAS CLI subcommands (preflight, lock, audit, verify).
"""

import json
import os
import sys
import tempfile
import pytest

from upas_core.cli.main import main
from upas_core.contracts.enums import ExitCode
from upas_core.evidence.writer import AtomicEvidenceWriter


@pytest.fixture
def sample_adapter_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter_path = os.path.join(tmpdir, "upas.adapter.json")
        adapter_data = {
            "schema_version": "1.0.0",
            "upas_target_version": ">=1.0.0,<2.0.0",
            "project": {
                "name": "support_bot",
                "type": "application",
                "language": "python",
                "runtime_version": "3.12",
            },
            "zones": [
                {
                    "name": "core",
                    "paths": ["src/"],
                    "risk_level": "medium",
                    "default_test_level": 1,
                }
            ],
            "test_engine": {
                "runner": "pytest",
                "level_commands": {
                    "level_0": f"{sys.executable} -c 'pass'",
                    "level_1": f"{sys.executable} -c 'pass'",
                    "level_2": f"{sys.executable} -c 'pass'",
                    "level_3": f"{sys.executable} -c 'pass'",
                    "level_4": f"{sys.executable} -c 'pass'",
                    "level_5": f"{sys.executable} -c 'pass'",
                },
                "test_map": [],
                "escalation_triggers": {
                    "database_migrations": 4,
                    "database_schemas": 3,
                    "api_contracts": 3,
                    "runtime_configuration": 3,
                    "dependency_manifests": 3,
                    "infrastructure_manifests": 3,
                    "security_sensitive_files": 3,
                },
            },
            "artifact": {
                "type": "container_image",
                "builder": "docker",
                "registry": "registry.internal/support_bot",
                "immutable_tag_format": "registry.internal/support_bot@sha256:{digest}",
            },
            "resource_gate": {
                "pre_flight_checks": {
                    "min_free_ram_mb": 10,
                    "max_swap_usage_pct": 99.0,
                    "max_1m_load_average": 99.0,
                    "min_free_disk_gb": 0.1,
                }
            },
            "deployment": {
                "strategy": "immutable_pull",
                "target_host": "localhost",
                "service_name": "support_bot",
                "runtime_directory": "/opt/support_bot",
                "host_lock_path": "/run/lock/upas-deploy.lock",
                "lock_timeout_seconds": 10,
            },
            "verification": {
                "health_check": {
                    "type": "custom_command",
                    "command": f"{sys.executable} -c 'pass'",
                    "timeout_seconds": 5,
                    "max_retries": 1,
                    "retry_interval_seconds": 1,
                },
                "smoke_test": {
                    "type": "custom_command",
                    "command": f"{sys.executable} -c 'pass'",
                    "timeout_seconds": 5,
                },
            },
            "backup": {
                "type": "database_and_config",
                "engine_hook": f"{sys.executable} -c 'pass'",
                "retention_count": 5,
                "checkpoint_dir": tmpdir,
            },
            "migration": {
                "classification_policy": "explicit_manifest",
                "default_classification": "NONE",
                "two_phase_protocol": False,
            },
            "authorization": {
                "provider": "github_environment_oidc",
                "environment_name": "production",
                "expected_issuer": "https://token.actions.githubusercontent.com",
                "expected_audience": "upas-production-gate",
                "required_claims": ["repository", "environment", "ref", "job_workflow_ref"],
            },
        }

        with open(adapter_path, "w", encoding="utf-8") as f:
            json.dump(adapter_data, f)

        yield {
            "adapter_path": adapter_path,
            "tmpdir": tmpdir,
        }


def test_cli_preflight_command(sample_adapter_file):
    adapter_path = sample_adapter_file["adapter_path"]
    code = main(["preflight", "--adapter", adapter_path])
    assert code == ExitCode.SUCCESS.value


def test_cli_lock_command(sample_adapter_file):
    lock_file = os.path.join(sample_adapter_file["tmpdir"], "test.lock")
    code = main(["lock", "--path", lock_file, "--check"])
    assert code == ExitCode.SUCCESS.value


def test_cli_audit_command_success(sample_adapter_file):
    tmpdir = sample_adapter_file["tmpdir"]
    ev_file = os.path.join(tmpdir, "test.evidence.json")
    man_file = os.path.join(tmpdir, "test.manifest.json")

    ev_data = {
        "operation_id": "op_test_100",
        "correlation_id": "rel_test_100",
        "authoritative_sources": {
            "artifact_provenance": {
                "immutable_digest": "sha256:" + "0" * 64,
            }
        },
        "final_verdict": {
            "state": "VERIFIED",
            "exit_code": 0,
            "completed_at": "2026-08-28T12:00:00Z",
        },
    }

    writer = AtomicEvidenceWriter()
    writer.write_evidence_and_manifest(ev_data, output_evidence_path=ev_file, output_manifest_path=man_file)

    code = main(["audit", "--evidence", ev_file, "--manifest", man_file])
    assert code == ExitCode.SUCCESS.value


def test_cli_verify_command(sample_adapter_file):
    adapter_path = sample_adapter_file["adapter_path"]
    digest = "sha256:" + "1" * 64
    code = main([
        "verify",
        "--adapter", adapter_path,
        "--running-digest", digest,
        "--approved-digest", digest,
    ])
    assert code == ExitCode.SUCCESS.value
