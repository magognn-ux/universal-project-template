"""
Integration tests for UPAS Lifecycle Harness & full CLI deploy workflow.
"""

import json
import os
import sys
import tempfile
import time
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from upas_core.cli.main import main
from upas_core.contracts.enums import ExitCode
from upas_core.evidence.writer import read_and_verify_persisted_evidence
from upas_core.locking.host_lock import AtomicHostLock
from upas_core.security.host_guard import ProductionHostGuard
from upas_core.security.jti_store import SQLiteJtiStore
from upas_core.security.oidc_verifier import GitHubOIDCVerifier
from upas_core.deployment.deployer import ProductionDeployer
from upas_core.cli.runner import LifecycleHarness


@pytest.fixture
def lifecycle_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter_path = os.path.join(tmpdir, "upas.adapter.json")
        backup_file = os.path.join(tmpdir, "backup_support_bot.dump")
        lock_path = os.path.join(tmpdir, "upas.lock")
        jti_db = os.path.join(tmpdir, "jti.db")
        evidence_file = os.path.join(tmpdir, "output.evidence.json")
        manifest_file = os.path.join(tmpdir, "output.manifest.json")

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        verifier = GitHubOIDCVerifier(signing_keys={"key-1": pub})
        host_guard = ProductionHostGuard(verifier=verifier, jti_store=SQLiteJtiStore(jti_db))
        deployer = ProductionDeployer(host_guard=host_guard, host_lock=AtomicHostLock())
        harness = LifecycleHarness(deployer=deployer)

        digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
                "host_lock_path": lock_path,
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
                "engine_hook": f"{sys.executable} -c \"with open(r'{backup_file}', 'w') as f: f.write('BACKUP')\"",
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
                "expected_repository": "octocat/hello-world",
                "required_claims": ["repository", "environment", "ref", "job_workflow_ref"],
            },
        }

        with open(adapter_path, "w", encoding="utf-8") as f:
            json.dump(adapter_data, f)

        def make_token(jti="cli-jti-001"):
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
                "run_id": "999",
            }
            return jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "key-1"})

        yield {
            "harness": harness,
            "adapter_path": adapter_path,
            "digest": digest,
            "make_token": make_token,
            "evidence_file": evidence_file,
            "manifest_file": manifest_file,
            "tmpdir": tmpdir,
        }


def test_full_cli_deploy_lifecycle(lifecycle_env):
    env = lifecycle_env
    token = env["make_token"]("cli-full-deploy-1")

    exit_code = main(
        [
            "deploy",
            "--adapter", env["adapter_path"],
            "--digest", env["digest"],
            "--oidc-token", token,
            "--output-evidence", env["evidence_file"],
            "--output-manifest", env["manifest_file"],
        ],
        harness=env["harness"],
    )

    assert exit_code == ExitCode.SUCCESS.value

    # Verify that evidence was generated and written atomically
    assert os.path.exists(env["evidence_file"])
    assert os.path.exists(env["manifest_file"])

    is_valid, ev_dict, manifest, err = read_and_verify_persisted_evidence(
        env["evidence_file"],
        env["manifest_file"],
    )
    assert is_valid is True
    assert err is None
    assert ev_dict["final_verdict"]["state"] == "VERIFIED"
    assert ev_dict["final_verdict"]["exit_code"] == 0
    assert ev_dict["authoritative_sources"]["artifact_provenance"]["immutable_digest"] == env["digest"]
