"""
Unit tests for `upas init` command and idempotent bootstrapping.
"""

import json
import os
from pathlib import Path
import tempfile
import pytest

from upas_core.cli.init_cmd import initialize_project, write_file_safely, detect_project_details
from upas_core.cli.main import main
from upas_core.contracts.enums import ExitCode


def test_detect_project_details_python():
    with tempfile.TemporaryDirectory() as tmpdir:
        req = Path(tmpdir) / "requirements.txt"
        req.write_text("flask==3.0.0\n")
        details = detect_project_details(tmpdir)
        assert details["language"] == "python"
        assert details["runtime_version"] == "3.11"


def test_detect_project_details_python_312():
    with tempfile.TemporaryDirectory() as tmpdir:
        pyproject = Path(tmpdir) / "pyproject.toml"
        pyproject.write_text("[project]\nrequires-python = '>=3.12'\n")
        details = detect_project_details(tmpdir)
        assert details["language"] == "python"
        assert details["runtime_version"] == "3.12"


def test_write_file_safely_idempotent():
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "file.txt"
        
        # 1. Create
        ok, msg = write_file_safely(target, "hello world")
        assert ok is True
        assert "CREATED" in msg
        assert target.read_text() == "hello world"

        # 2. Identical (No change)
        ok, msg = write_file_safely(target, "hello world")
        assert ok is True
        assert "IDENTICAL" in msg

        # 3. Conflicting without overwrite
        ok, msg = write_file_safely(target, "different content", overwrite=False)
        assert ok is False
        assert "CONFLICT" in msg
        assert target.read_text() == "hello world"

        # 4. Conflicting with overwrite
        ok, msg = write_file_safely(target, "different content", overwrite=True)
        assert ok is True
        assert "OVERWRITTEN" in msg
        assert target.read_text() == "different content"


def test_initialize_project_end_to_end():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create minimal python app
        (Path(tmpdir) / "requirements.txt").write_text("pytest\n")
        
        # 1. Run init
        success, logs = initialize_project(project_dir=tmpdir, custom_name="test_app")
        assert success is True
        
        adapter_file = Path(tmpdir) / "upas.adapter.json"
        workflow_file = Path(tmpdir) / ".github" / "workflows" / "upas.yml"
        
        assert adapter_file.exists()
        assert workflow_file.exists()

        data = json.loads(adapter_file.read_text())
        assert data["project"]["name"] == "test_app"
        assert data["project"]["language"] == "python"

        # 2. Run init second time (idempotent noop)
        success2, logs2 = initialize_project(project_dir=tmpdir, custom_name="test_app")
        assert success2 is True
        assert any("IDENTICAL" in l for l in logs2)


def test_cli_init_command():
    with tempfile.TemporaryDirectory() as tmpdir:
        ret = main(["init", "--project", tmpdir, "--name", "cli_test_app"])
        assert ret == ExitCode.SUCCESS.value
        adapter_file = Path(tmpdir) / "upas.adapter.json"
        workflow_file = Path(tmpdir) / ".github" / "workflows" / "upas.yml"
        assert adapter_file.exists()
        assert workflow_file.exists()
        # Verify workflow is pinned to @v1
        workflow_text = workflow_file.read_text()
        assert "@v1" in workflow_text
        assert "@main" not in workflow_text


def test_initialize_project_infrastructure_archetype():
    from upas_core.adapter.validator import load_and_validate_adapter
    with tempfile.TemporaryDirectory() as tmpdir:
        success, logs = initialize_project(
            project_dir=tmpdir,
            custom_name="my_infra",
            archetype="infrastructure",
        )
        assert success is True
        adapter_path = Path(tmpdir) / "upas.adapter.json"
        assert adapter_path.exists()
        
        # Validate against schema
        loaded = load_and_validate_adapter(str(adapter_path))
        assert loaded.project.name == "my_infra"
        assert loaded.project.type == "infrastructure"
        assert loaded.artifact.type.value == "static_bundle"
        assert (Path(tmpdir) / "scripts" / "verify-health.sh").exists()
        assert (Path(tmpdir) / "scripts" / "backup-all.sh").exists()


def test_initialize_project_library_archetype():
    from upas_core.adapter.validator import load_and_validate_adapter
    with tempfile.TemporaryDirectory() as tmpdir:
        success, logs = initialize_project(
            project_dir=tmpdir,
            custom_name="my_lib",
            archetype="library",
        )
        assert success is True
        adapter_path = Path(tmpdir) / "upas.adapter.json"
        assert adapter_path.exists()
        
        # Validate against schema
        loaded = load_and_validate_adapter(str(adapter_path))
        assert loaded.project.name == "my_lib"
        assert loaded.project.type == "library"
        assert loaded.backup.type == "none"

