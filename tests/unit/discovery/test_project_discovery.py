"""
Unit tests for UPAS Project Discovery and Capability Detector.
"""

import json
import os
from pathlib import Path
import tempfile
import pytest

from upas_core.discovery.detector import (
    CapabilityValidationResult,
    ProjectCapabilityDetector,
    discover_and_validate_project,
    inspect_git_state,
)
from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import UPASError

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"


def test_discover_adapter_in_directory():
    detector = ProjectCapabilityDetector()
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter_file = Path(tmpdir) / "upas.adapter.json"
        adapter_file.write_text(json.dumps({
            "schema_version": "1.0.0",
            "upas_target_version": ">=1.0.0,<2.0.0",
            "project": {"name": "test_app", "type": "application", "language": "python", "runtime_version": "3.11"},
            "zones": [{"name": "z", "paths": ["."], "risk_level": "low", "default_test_level": 1}],
            "test_engine": {
                "runner": "pytest",
                "level_commands": {"level_0": "true", "level_1": "true", "level_2": "true", "level_3": "true", "level_4": "true", "level_5": "true"},
                "test_map": [],
                "escalation_triggers": {
                    "database_migrations": 5, "database_schemas": 4, "api_contracts": 3,
                    "runtime_configuration": 3, "dependency_manifests": 3, "infrastructure_manifests": 4,
                    "security_sensitive_files": 4
                }
            },
            "artifact": {"type": "container_image", "builder": "docker", "registry": "reg", "immutable_tag_format": "sha-{digest}"},
            "resource_gate": {"pre_flight_checks": {"min_free_ram_mb": 1, "max_swap_usage_pct": 100, "max_1m_load_average": 100, "min_free_disk_gb": 1}},
            "deployment": {"strategy": "immutable_pull", "target_host": "h", "service_name": "s", "runtime_directory": "/d"},
            "verification": {"health_check": {"type": "custom_command", "command": "true", "timeout_seconds": 1, "max_retries": 1, "retry_interval_seconds": 1}},
            "backup": {"type": "none", "engine_hook": "echo", "retention_count": 1, "checkpoint_dir": tmpdir},
            "migration": {"classification_policy": "explicit_manifest", "default_classification": "NONE", "two_phase_protocol": False},
            "authorization": {"provider": "github_environment_oidc", "environment_name": "prod", "expected_issuer": "https://token.actions.githubusercontent.com", "expected_audience": "aud", "required_claims": ["repository", "environment", "ref", "job_workflow_ref"]}
        }))

        discovered = detector.discover_adapter(tmpdir)
        assert discovered == str(adapter_file.resolve())


def test_discover_missing_adapter_raises_error():
    detector = ProjectCapabilityDetector()
    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(UPASError) as exc_info:
            detector.discover_adapter(tmpdir)
        assert exc_info.value.exit_code == ExitCode.CAPABILITY_MISMATCH


def test_inspect_git_state_non_repo():
    with tempfile.TemporaryDirectory() as tmpdir:
        state = inspect_git_state(tmpdir)
        assert isinstance(state.is_git_repo, bool)


def test_validate_capabilities_missing_compose_file():
    detector = ProjectCapabilityDetector()
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter_file = Path(tmpdir) / "upas.adapter.json"
        adapter_file.write_text(json.dumps({
            "schema_version": "1.0.0",
            "upas_target_version": ">=1.0.0,<2.0.0",
            "project": {"name": "test_app", "type": "application", "language": "python", "runtime_version": "3.11"},
            "zones": [{"name": "z", "paths": ["."], "risk_level": "low", "default_test_level": 1}],
            "test_engine": {
                "runner": "pytest",
                "level_commands": {"level_0": "true", "level_1": "true", "level_2": "true", "level_3": "true", "level_4": "true", "level_5": "true"},
                "test_map": [],
                "escalation_triggers": {
                    "database_migrations": 5, "database_schemas": 4, "api_contracts": 3,
                    "runtime_configuration": 3, "dependency_manifests": 3, "infrastructure_manifests": 4,
                    "security_sensitive_files": 4
                }
            },
            "artifact": {"type": "container_image", "builder": "docker", "registry": "reg", "immutable_tag_format": "sha-{digest}"},
            "resource_gate": {"pre_flight_checks": {"min_free_ram_mb": 1, "max_swap_usage_pct": 100, "max_1m_load_average": 100, "min_free_disk_gb": 1}},
            "deployment": {
                "strategy": "immutable_pull", "target_host": "h", "service_name": "s", "runtime_directory": "/d",
                "compose_file": "missing-compose.yml"
            },
            "verification": {"health_check": {"type": "custom_command", "command": "true", "timeout_seconds": 1, "max_retries": 1, "retry_interval_seconds": 1}},
            "backup": {"type": "none", "engine_hook": "echo", "retention_count": 1, "checkpoint_dir": tmpdir},
            "migration": {"classification_policy": "explicit_manifest", "default_classification": "NONE", "two_phase_protocol": False},
            "authorization": {"provider": "github_environment_oidc", "environment_name": "prod", "expected_issuer": "https://token.actions.githubusercontent.com", "expected_audience": "aud", "required_claims": ["repository", "environment", "ref", "job_workflow_ref"]}
        }))

        res = detector.validate_capabilities(tmpdir)
        assert res.passed is False
        assert res.exit_code == ExitCode.CAPABILITY_MISMATCH
        assert any("compose_file" in cap for cap in res.missing_capabilities)


def test_inspect_git_state_porcelain_parsing_accuracy(monkeypatch):
    """Verifies that porcelain status lines like ' M file.py' do not truncate the first character."""
    import subprocess
    from unittest.mock import MagicMock

    mock_stdout = " M services/analytics.py\n?? upas.adapter.json\n M database/schema.py\n"

    def mock_run(args, **kwargs):
        mock_res = MagicMock()
        mock_res.returncode = 0
        if "status" in args:
            mock_res.stdout = mock_stdout
        elif "HEAD" in args:
            mock_res.stdout = "0123456789abcdef0123456789abcdef01234567"
        elif "--abbrev-ref" in args:
            mock_res.stdout = "master"
        else:
            mock_res.stdout = ""
        return mock_res

    monkeypatch.setattr(subprocess, "run", mock_run)

    state = inspect_git_state(".")
    assert state.is_dirty is True
    assert "services/analytics.py" in state.modified_files
    assert "database/schema.py" in state.modified_files
    assert "upas.adapter.json" in state.untracked_files
    # Ensure no truncation
    assert "ervices/analytics.py" not in state.modified_files


def test_resolve_changed_files_explicit_cli():
    from upas_core.discovery.detector import resolve_changed_files
    files, source = resolve_changed_files(".", explicit_files="app/main.py, services/api.py, app/main.py")
    assert files == ["app/main.py", "services/api.py"]
    assert source == "cli_explicit_argument"


def test_resolve_changed_files_pr_base_ref(monkeypatch, tmp_path):
    from upas_core.discovery.detector import resolve_changed_files, GitState
    import upas_core.discovery.detector as det
    import subprocess
    from unittest.mock import MagicMock

    # Mock clean working tree
    monkeypatch.setattr(det, "inspect_git_state", lambda p: GitState(
        is_git_repo=True,
        commit_sha="abc1234",
        branch="feature-x",
        is_dirty=False,
        untracked_files=[],
        modified_files=[],
    ))
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    def mock_subprocess_run(args, **kwargs):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "services/analytics.py\ncore/config.py\n"
        return mock_res

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    files, source = resolve_changed_files(str(tmp_path))
    assert files == ["services/analytics.py", "core/config.py"]
    assert "git_diff_pr_base" in source


def test_resolve_changed_files_fallback_when_pr_base_fails(monkeypatch, tmp_path):
    from unittest.mock import MagicMock
    import subprocess
    import upas_core.discovery.detector as det
    from upas_core.discovery.detector import GitState, resolve_changed_files

    monkeypatch.setattr(det, "inspect_git_state", lambda p: GitState(
        is_git_repo=True,
        commit_sha="abc1234",
        branch="feature-x",
        is_dirty=False,
        untracked_files=[],
        modified_files=[],
    ))
    monkeypatch.setenv("GITHUB_BASE_REF", "nonexistent_branch")

    # Simulate git diff returning non-zero / failure for all ref specs
    def mock_subprocess_run(args, **kwargs):
        mock_res = MagicMock()
        mock_res.returncode = 128
        mock_res.stdout = ""
        return mock_res

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    files, source = resolve_changed_files(str(tmp_path))
    assert files == []
    assert source == "clean_working_tree_no_diff"



