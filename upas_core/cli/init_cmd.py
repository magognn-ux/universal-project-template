"""
UPAS Project Bootstrapper & Initializer (`upas init`).
Scaffolds canonical `upas.adapter.json` and caller workflow for new and existing projects.
Guarantees idempotent, non-destructive execution.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import UPASError


DEFAULT_APPLICATION_ADAPTER_TEMPLATE: Dict[str, Any] = {
    "schema_version": "1.0.0",
    "upas_target_version": ">=1.0.0,<2.0.0",
    "project": {
        "name": "sample_app",
        "type": "application",
        "language": "python",
        "runtime_version": "3.11"
    },
    "zones": [
        {
            "name": "core_logic",
            "paths": ["app/core/**", "src/core/**"],
            "risk_level": "medium",
            "default_test_level": 1
        },
        {
            "name": "services_and_handlers",
            "paths": ["app/services/**", "app/handlers/**", "src/services/**"],
            "risk_level": "high",
            "default_test_level": 2
        },
        {
            "name": "database_and_models",
            "paths": ["app/db/**", "app/models/**", "database/**", "models/**"],
            "risk_level": "high",
            "default_test_level": 3
        }
    ],
    "test_engine": {
        "runner": "pytest",
        "level_commands": {
            "level_0": "python -m compileall .",
            "level_1": "pytest tests/unit/ -v",
            "level_2": "pytest tests/integration/ -v",
            "level_3": "pytest tests/ -v -m 'not slow'",
            "level_4": "pytest tests/ -v",
            "level_5": "pytest tests/ -v --cov"
        },
        "test_map": [
            {
                "match": "app/core/",
                "tests": ["tests/unit/"],
                "escalate_to_level": 1
            },
            {
                "match": "app/services/",
                "tests": ["tests/integration/"],
                "escalate_to_level": 2
            }
        ],
        "escalation_triggers": {
            "database_migrations": 5,
            "database_schemas": 4,
            "api_contracts": 3,
            "runtime_configuration": 3,
            "dependency_manifests": 3,
            "infrastructure_manifests": 4,
            "security_sensitive_files": 4
        }
    },
    "artifact": {
        "type": "container_image",
        "builder": "docker_buildx",
        "registry": "ghcr.io/org/sample-app",
        "immutable_tag_format": "sha-{commit_short}"
    },
    "resource_gate": {
        "pre_flight_checks": {
            "min_free_ram_mb": 256,
            "max_swap_usage_pct": 60,
            "max_1m_load_average": 3.0,
            "min_free_disk_gb": 2.0
        }
    },
    "deployment": {
        "strategy": "immutable_pull",
        "target_host": "root@production-host",
        "service_name": "sample-app",
        "runtime_directory": "/opt/sample_app",
        "compose_file": "docker-compose.yml"
    },
    "verification": {
        "health_check": {
            "type": "http_get",
            "endpoint": "http://127.0.0.1:8080/health",
            "expected_status": 200,
            "timeout_seconds": 10,
            "max_retries": 5,
            "retry_interval_seconds": 3
        }
    },
    "backup": {
        "type": "file_snapshot",
        "engine_hook": "scripts/backup.sh",
        "retention_count": 30,
        "checkpoint_dir": "/opt/sample_app/backups"
    },
    "migration": {
        "classification_policy": "explicit_manifest",
        "default_classification": "ADDITIVE_COMPATIBLE",
        "two_phase_protocol": True,
        "pre_deploy_hook": "python -m alembic upgrade head"
    },
    "authorization": {
        "provider": "github_environment_oidc",
        "environment_name": "production",
        "expected_issuer": "https://token.actions.githubusercontent.com",
        "expected_audience": "upas-production-gate",
        "required_claims": ["repository", "environment", "ref", "job_workflow_ref"]
    }
}

DEFAULT_INFRASTRUCTURE_ADAPTER_TEMPLATE: Dict[str, Any] = {
    "schema_version": "1.0.0",
    "upas_target_version": ">=1.0.0,<2.0.0",
    "project": {
        "name": "server-infrastructure",
        "type": "infrastructure",
        "language": "python",
        "runtime_version": "3.11"
    },
    "zones": [
        {
            "name": "documentation",
            "paths": ["docs/**", "README.md"],
            "risk_level": "low",
            "default_test_level": 0
        },
        {
            "name": "platform_scripts",
            "paths": ["scripts/**"],
            "risk_level": "medium",
            "default_test_level": 1
        },
        {
            "name": "ingress_and_proxy",
            "paths": ["nginx/**", "xray/**"],
            "risk_level": "high",
            "default_test_level": 3
        },
        {
            "name": "platform_manifests_and_docker",
            "paths": ["manifests/**", "docker/**"],
            "risk_level": "critical",
            "default_test_level": 4
        }
    ],
    "test_engine": {
        "runner": "pytest",
        "level_commands": {
            "level_0": "python -m compileall scripts",
            "level_1": "pytest tests/unit/ -v --tb=short",
            "level_2": "pytest tests/integration/ -v --tb=short",
            "level_3": "python scripts/test-phase5-verification.py",
            "level_4": "python scripts/test-security-gate.py",
            "level_5": "bash scripts/test-anti-coupling.sh && python scripts/test-security-gate.py"
        },
        "test_map": [
            {
                "match": "nginx/",
                "tests": ["scripts/test-phase5-verification.py"],
                "escalate_to_level": 3
            },
            {
                "match": "manifests/",
                "tests": ["scripts/test-security-gate.py"],
                "escalate_to_level": 4
            }
        ],
        "escalation_triggers": {
            "database_migrations": 5,
            "database_schemas": 4,
            "api_contracts": 3,
            "runtime_configuration": 3,
            "dependency_manifests": 3,
            "infrastructure_manifests": 4,
            "security_sensitive_files": 4
        }
    },
    "artifact": {
        "type": "static_bundle",
        "builder": "tar_sha256",
        "registry": "internal/platform-manifests",
        "immutable_tag_format": "sha-{commit_short}"
    },
    "resource_gate": {
        "pre_flight_checks": {
            "min_free_ram_mb": 512,
            "max_swap_usage_pct": 50,
            "max_1m_load_average": 2.0,
            "min_free_disk_gb": 5.0
        }
    },
    "deployment": {
        "strategy": "static_sync",
        "target_host": "root@production-host",
        "service_name": "server-infrastructure",
        "runtime_directory": "/opt/server-infrastructure",
        "compose_file": "docker/docker-compose.yml"
    },
    "verification": {
        "health_check": {
            "type": "custom_command",
            "command": "bash scripts/verify-health.sh",
            "timeout_seconds": 15,
            "max_retries": 3,
            "retry_interval_seconds": 5
        }
    },
    "backup": {
        "type": "database_and_config",
        "engine_hook": "scripts/backup-all.sh",
        "retention_count": 30,
        "checkpoint_dir": "/opt/server-infrastructure/backups"
    },
    "migration": {
        "classification_policy": "explicit_manifest",
        "default_classification": "ADDITIVE_COMPATIBLE",
        "two_phase_protocol": False
    },
    "authorization": {
        "provider": "github_environment_oidc",
        "environment_name": "production",
        "expected_issuer": "https://token.actions.githubusercontent.com",
        "expected_audience": "upas-production-gate",
        "required_claims": ["repository", "environment", "ref", "job_workflow_ref"]
    }
}

DEFAULT_LIBRARY_ADAPTER_TEMPLATE: Dict[str, Any] = {
    "schema_version": "1.0.0",
    "upas_target_version": ">=1.0.0,<2.0.0",
    "project": {
        "name": "sample_library",
        "type": "library",
        "language": "python",
        "runtime_version": "3.11"
    },
    "zones": [
        {
            "name": "core_logic",
            "paths": ["src/**", "lib/**"],
            "risk_level": "medium",
            "default_test_level": 1
        },
        {
            "name": "test_suite",
            "paths": ["tests/**"],
            "risk_level": "low",
            "default_test_level": 1
        },
        {
            "name": "contracts_and_schemas",
            "paths": ["schemas/**", "contracts/**"],
            "risk_level": "high",
            "default_test_level": 3
        }
    ],
    "test_engine": {
        "runner": "pytest",
        "level_commands": {
            "level_0": "python -m compileall .",
            "level_1": "pytest tests/unit/ -v",
            "level_2": "pytest tests/ -v -m 'not slow'",
            "level_3": "pytest tests/ -v",
            "level_4": "pytest tests/ -v --tb=short",
            "level_5": "pytest tests/ -v --cov"
        },
        "test_map": [
            {
                "match": "schemas/",
                "tests": ["tests/test_schemas_validation.py"],
                "escalate_to_level": 3
            }
        ],
        "escalation_triggers": {
            "database_migrations": 5,
            "database_schemas": 4,
            "api_contracts": 3,
            "runtime_configuration": 3,
            "dependency_manifests": 3,
            "infrastructure_manifests": 4,
            "security_sensitive_files": 4
        }
    },
    "artifact": {
        "type": "static_bundle",
        "builder": "build_wheel",
        "registry": "internal/pypi",
        "immutable_tag_format": "sha-{commit_short}"
    },
    "resource_gate": {
        "pre_flight_checks": {
            "min_free_ram_mb": 128,
            "max_swap_usage_pct": 70,
            "max_1m_load_average": 4.0,
            "min_free_disk_gb": 1.0
        }
    },
    "deployment": {
        "strategy": "static_sync",
        "target_host": "localhost",
        "service_name": "sample-library",
        "runtime_directory": "/opt/sample-library"
    },
    "verification": {
        "health_check": {
            "type": "custom_command",
            "command": "python -m compileall .",
            "timeout_seconds": 10,
            "max_retries": 1,
            "retry_interval_seconds": 1
        }
    },
    "backup": {
        "type": "none",
        "engine_hook": "echo 'No backup required for library'",
        "retention_count": 1,
        "checkpoint_dir": "/tmp"
    },
    "migration": {
        "classification_policy": "explicit_manifest",
        "default_classification": "NONE",
        "two_phase_protocol": False
    },
    "authorization": {
        "provider": "github_environment_oidc",
        "environment_name": "production",
        "expected_issuer": "https://token.actions.githubusercontent.com",
        "expected_audience": "upas-production-gate",
        "required_claims": ["repository", "environment", "ref", "job_workflow_ref"]
    }
}

DEFAULT_PYTHON_ADAPTER_TEMPLATE = DEFAULT_APPLICATION_ADAPTER_TEMPLATE

CALLER_WORKFLOW_TEMPLATE = """# ==============================================================================
# UPAS — Caller Workflow (Universal Project Automation Standard)
# Connects this repository to the central UPAS reusable workflow engine.
# Versioning: Pinned to immutable release @v1.0.1.
# ==============================================================================
name: UPAS Pipeline

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master, develop ]
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  upas-ci:
    name: UPAS Automation Engine
    # Calls the central reusable UPAS workflow from universal-project-template
    uses: magognn-ux/universal-project-template/.github/workflows/upas-pipeline.yml@v1.0.1
    secrets: inherit
"""


def detect_project_details(project_dir: str) -> Dict[str, Any]:
    """Inspects project files to determine language, runtime and project name."""
    p = Path(project_dir).resolve()
    project_name = p.name or "my_project"

    language = "python"
    runtime_version = "3.11"

    if (p / "pyproject.toml").exists() or (p / "requirements.txt").exists():
        language = "python"
        if (p / "pyproject.toml").exists():
            content = (p / "pyproject.toml").read_text(errors="ignore")
            if "3.12" in content:
                runtime_version = "3.12"
            elif "3.11" in content:
                runtime_version = "3.11"
    elif (p / "package.json").exists():
        language = "nodejs"
        runtime_version = "20"
    elif (p / "go.mod").exists():
        language = "go"
        runtime_version = "1.22"

    return {
        "name": project_name,
        "language": language,
        "runtime_version": runtime_version,
    }


def write_file_safely(
    file_path: Path,
    content: str,
    overwrite: bool = False
) -> Tuple[bool, str]:
    """
    Writes file safely adhering to idempotency rules:
    - If identical: NOOP
    - If missing: CREATE
    - If conflicting & overwrite=False: CONFLICT_ERROR
    - If conflicting & overwrite=True: OVERWRITTEN
    """
    file_path.parent.mkdir(parents=True, exist_ok=True)

    if file_path.exists():
        existing_content = file_path.read_text(encoding="utf-8", errors="ignore")
        if existing_content.strip() == content.strip():
            return True, f"IDENTICAL (No change needed): {file_path.name}"
        if not overwrite:
            return False, (
                f"CONFLICT: '{file_path.name}' already exists with differing content. "
                f"Use --overwrite to safely update, or inspect existing file."
            )
        file_path.write_text(content, encoding="utf-8")
        return True, f"OVERWRITTEN: {file_path.name}"

    file_path.write_text(content, encoding="utf-8")
    return True, f"CREATED: {file_path.name}"


def initialize_project(
    project_dir: str = ".",
    overwrite: bool = False,
    custom_name: Optional[str] = None,
    archetype: str = "application",
) -> Tuple[bool, List[str]]:
    """
    Idempotently scaffolds UPAS connection files for a project.
    Supports 'application', 'infrastructure', and 'library' archetypes.
    """
    p = Path(project_dir).resolve()
    if not p.exists():
        p.mkdir(parents=True, exist_ok=True)

    details = detect_project_details(str(p))
    proj_name = custom_name or details["name"]

    # Select base template by archetype
    if archetype == "infrastructure":
        base_template = DEFAULT_INFRASTRUCTURE_ADAPTER_TEMPLATE
    elif archetype == "library":
        base_template = DEFAULT_LIBRARY_ADAPTER_TEMPLATE
    else:
        base_template = DEFAULT_APPLICATION_ADAPTER_TEMPLATE

    # 1. Prepare upas.adapter.json
    adapter_data = json.loads(json.dumps(base_template))
    adapter_data["project"]["name"] = proj_name
    adapter_data["project"]["language"] = details["language"]
    adapter_data["project"]["runtime_version"] = details["runtime_version"]

    if archetype == "application":
        adapter_data["artifact"]["registry"] = f"ghcr.io/org/{proj_name.replace('_', '-')}"
        adapter_data["deployment"]["service_name"] = proj_name.replace('_', '-')
        adapter_data["deployment"]["runtime_directory"] = f"/opt/{proj_name}"
        adapter_data["backup"]["checkpoint_dir"] = f"/opt/{proj_name}/backups"

        # Auto-detect test directory structure
        has_unit_dir = (p / "tests" / "unit").is_dir() or (p / "test" / "unit").is_dir()
        has_tests_dir = (p / "tests").is_dir() or (p / "test").is_dir()
        test_dir_name = "tests" if (p / "tests").is_dir() else ("test" if (p / "test").is_dir() else "tests")

        if not has_unit_dir and has_tests_dir:
            adapter_data["test_engine"]["level_commands"]["level_1"] = f"pytest {test_dir_name}/ -v"
            adapter_data["test_engine"]["level_commands"]["level_2"] = f"pytest {test_dir_name}/ -v"
            adapter_data["test_engine"]["level_commands"]["level_3"] = f"pytest {test_dir_name}/ -v"
            adapter_data["test_engine"]["level_commands"]["level_4"] = f"pytest {test_dir_name}/ -v"
            adapter_data["test_engine"]["level_commands"]["level_5"] = f"pytest {test_dir_name}/ -v"
        elif not has_tests_dir:
            (p / test_dir_name / "unit").mkdir(parents=True, exist_ok=True)
            starter_test = "def test_baseline():\n    assert True\n"
            write_file_safely(p / test_dir_name / "unit" / "test_baseline.py", starter_test, overwrite=False)

        # Auto-detect compose file if present
        if (p / "docker-compose.prod.yml").exists():
            adapter_data["deployment"]["compose_file"] = "docker-compose.prod.yml"
        elif (p / "docker-compose.yml").exists():
            adapter_data["deployment"]["compose_file"] = "docker-compose.yml"
        elif (p / "compose.yml").exists():
            adapter_data["deployment"]["compose_file"] = "compose.yml"
        else:
            starter_compose = (
                f"version: '3.8'\nservices:\n  {proj_name.replace('_', '-')}:\n"
                f"    image: ghcr.io/org/{proj_name.replace('_', '-')}:latest\n    restart: unless-stopped\n"
            )
            write_file_safely(p / "docker-compose.yml", starter_compose, overwrite=False)

        backup_script = p / "scripts" / "backup.sh"
        if not backup_script.exists():
            starter_backup = "#!/bin/sh\necho '[UPAS BACKUP] Snapshotting state...'\nexit 0\n"
            write_file_safely(backup_script, starter_backup, overwrite=False)

    elif archetype == "infrastructure":
        adapter_data["deployment"]["service_name"] = proj_name.replace('_', '-')
        adapter_data["deployment"]["runtime_directory"] = f"/opt/{proj_name}"
        adapter_data["backup"]["checkpoint_dir"] = f"/opt/{proj_name}/backups"
        scripts_dir = p / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        if not (scripts_dir / "verify-health.sh").exists():
            write_file_safely(scripts_dir / "verify-health.sh", "#!/bin/sh\necho '[UPAS INFRA] Health OK'\nexit 0\n", overwrite=False)
        if not (scripts_dir / "backup-all.sh").exists():
            write_file_safely(scripts_dir / "backup-all.sh", "#!/bin/sh\necho '[UPAS INFRA] Backup OK'\nexit 0\n", overwrite=False)

    elif archetype == "library":
        adapter_data["deployment"]["service_name"] = proj_name.replace('_', '-')
        adapter_data["deployment"]["runtime_directory"] = f"/opt/{proj_name}"

    adapter_path = p / "upas.adapter.json"
    adapter_content = json.dumps(adapter_data, indent=2) + "\n"

    # 2. Prepare caller workflow
    workflow_path = p / ".github" / "workflows" / "upas.yml"

    logs: List[str] = []
    
    # Write adapter
    ok1, msg1 = write_file_safely(adapter_path, adapter_content, overwrite=overwrite)
    logs.append(msg1)
    if not ok1:
        return False, logs

    # Write caller workflow
    ok2, msg2 = write_file_safely(workflow_path, CALLER_WORKFLOW_TEMPLATE, overwrite=overwrite)
    logs.append(msg2)
    if not ok2:
        return False, logs

    return True, logs

