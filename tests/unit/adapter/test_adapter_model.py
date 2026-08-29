"""
Unit tests for UPAS Canonical Adapter Model and Validator.
Verifies typed parsing, schema compliance, SemVer compatibility, and contract invariants.
"""

import json
from pathlib import Path
import pytest

from upas_core.adapter.model import ProjectAdapter
from upas_core.adapter.validator import (
    load_adapter_from_dict,
    load_and_validate_adapter,
    validate_adapter_dict,
)
from upas_core.contracts.enums import (
    ExitCode,
    InfraAccess,
    InfraType,
    MigrationClassification,
    RiskLevel,
    TestLevel,
)
from upas_core.contracts.errors import (
    EscalationViolationError,
    IncompatibleVersionError,
    SharedInfraViolationError,
    UPASError,
)

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"


def test_load_valid_support_bot_adapter():
    adapter_path = FIXTURES_DIR / "valid" / "support_bot_adapter.json"
    adapter = load_and_validate_adapter(str(adapter_path))

    assert isinstance(adapter, ProjectAdapter)
    assert adapter.project.name == "support_bot"
    assert adapter.project.language == "python"
    assert adapter.project.runtime_version == "3.11"
    assert len(adapter.zones) == 3
    assert adapter.zones[0].name == "core_app"
    assert adapter.zones[0].risk_level == RiskLevel.MEDIUM
    assert adapter.zones[0].default_test_level == TestLevel.L1
    assert adapter.test_engine.runner == "pytest"
    assert adapter.test_engine.escalation_triggers.database_migrations == 5
    assert adapter.artifact.registry == "ghcr.io/org/support-bot"
    assert adapter.deployment.service_name == "support-bot"
    assert adapter.deployment.host_lock_path == "/run/lock/upas-deploy.lock"
    assert adapter.migration.two_phase_protocol is True
    assert adapter.authorization.environment_name == "production"


def test_load_valid_tour_monitor_adapter():
    adapter_path = FIXTURES_DIR / "valid" / "tour_monitor_adapter.json"
    adapter = load_and_validate_adapter(str(adapter_path))

    assert isinstance(adapter, ProjectAdapter)
    assert adapter.project.name == "tour_monitor"
    assert len(adapter.infrastructure_dependencies) == 2
    assert adapter.infrastructure_dependencies[0].name == "shared-postgres"
    assert adapter.infrastructure_dependencies[0].access == InfraAccess.READONLY_CONSUMER


def test_invalid_adapter_missing_required_fields():
    invalid_data = {
        "schema_version": "1.0.0",
        "upas_target_version": ">=1.0.0,<2.0.0",
        "project": {"name": "test"},
    }
    with pytest.raises(UPASError) as exc_info:
        validate_adapter_dict(invalid_data)
    assert exc_info.value.exit_code == ExitCode.TESTS_FAILED


def test_invalid_adapter_schema_version():
    adapter_path = FIXTURES_DIR / "invalid" / "invalid_schema_version_adapter.json"
    with open(adapter_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    with pytest.raises(UPASError):
        validate_adapter_dict(data)


def test_incompatible_core_version_fails_closed():
    adapter_path = FIXTURES_DIR / "valid" / "support_bot_adapter.json"
    with open(adapter_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Require UPAS Core 2.x which is incompatible with current Core 1.0.0
    data["upas_target_version"] = ">=2.0.0,<3.0.0"
    with pytest.raises(IncompatibleVersionError) as exc_info:
        validate_adapter_dict(data)
    assert exc_info.value.exit_code == ExitCode.INCOMPATIBLE_VERSION_ERROR


def test_lowered_db_migration_escalation_fails_closed():
    adapter_path = FIXTURES_DIR / "invalid" / "lowered_db_migration_escalation_adapter.json"
    with open(adapter_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    with pytest.raises((EscalationViolationError, UPASError)):
        validate_adapter_dict(data)


def test_non_additive_migration_without_two_phase_protocol_fails_closed():
    adapter_path = FIXTURES_DIR / "invalid" / "incompatible_migration_one_phase_adapter.json"
    with open(adapter_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    with pytest.raises(UPASError):
        validate_adapter_dict(data)


def test_shared_infra_write_access_fails_closed():
    adapter_path = FIXTURES_DIR / "invalid" / "shared_infra_write_access_adapter.json"
    with open(adapter_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    with pytest.raises((SharedInfraViolationError, UPASError)):
        validate_adapter_dict(data)


def test_non_absolute_host_lock_path_fails_closed():
    adapter_path = FIXTURES_DIR / "invalid" / "invalid_host_lock_path_adapter.json"
    with open(adapter_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    with pytest.raises(UPASError):
        validate_adapter_dict(data)


def test_adapter_helper_conversions():
    adapter_path = FIXTURES_DIR / "valid" / "support_bot_adapter.json"
    adapter = load_and_validate_adapter(str(adapter_path))

    mig_spec = adapter.to_migration_spec()
    assert mig_spec.classification == MigrationClassification.ADDITIVE_COMPATIBLE
    assert mig_spec.two_phase_protocol is True
    assert mig_spec.pre_deploy_hook == "python -m app.db.migrations"

    oidc_cfg = adapter.to_oidc_config(repository="org/support_bot")
    assert oidc_cfg.expected_repository == "org/support_bot"
    assert oidc_cfg.expected_environment == "production"
    assert oidc_cfg.expected_audience == "upas-production-gate"
