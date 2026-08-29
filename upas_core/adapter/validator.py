"""
UPAS Project Adapter Validator and Loader.
Enforces schema validation against upas.adapter.schema.json and semantic invariant validation.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
import jsonschema

from upas_core.adapter.model import (
    ArtifactSpec,
    AuthorizationSpec,
    BackupSpec,
    DeploymentSpec,
    HealthCheckSpec,
    InfrastructureDependencySpec,
    MigrationAdapterSpec,
    ProjectAdapter,
    ProjectSpec,
    ResourceGateSpec,
    SmokeTestSpec,
    TestEngineSpec,
    VerificationSpec,
)
from upas_core.compatibility.checker import check_compatibility
from upas_core.contracts.artifacts import ArtifactType
from upas_core.contracts.enums import (
    ExitCode,
    InfraAccess,
    InfraType,
    MigrationClassification,
    MigrationPolicy,
    RiskLevel,
    TestLevel,
)
from upas_core.contracts.errors import (
    EscalationViolationError,
    IncompatibleVersionError,
    SharedInfraViolationError,
    UPASError,
)
from upas_core.contracts.testing import EscalationTriggers, TestMapEntry, ZoneSpec

UPAS_CORE_VERSION = "1.0.0"

_SCHEMA_CACHE: Optional[Dict[str, Any]] = None


def get_adapter_json_schema() -> Dict[str, Any]:
    """Loads and caches the canonical upas.adapter.schema.json."""
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        # Resolve schema path relative to this file or root schemas/
        candidates = [
            Path(__file__).parent.parent.parent / "schemas" / "upas.adapter.schema.json",
            Path(__file__).parent.parent / "schemas" / "upas.adapter.schema.json",
            Path("schemas/upas.adapter.schema.json"),
        ]
        schema_path = next((p for p in candidates if p.exists()), None)
        if not schema_path:
            raise UPASError(
                "Canonical schema 'upas.adapter.schema.json' not found in workspace",
                exit_code=ExitCode.TESTS_FAILED,
            )
        with open(schema_path, "r", encoding="utf-8") as f:
            _SCHEMA_CACHE = json.load(f)
    return _SCHEMA_CACHE


def validate_adapter_dict(data: Dict[str, Any], enforce_core_version: bool = True) -> None:
    """
    Validates a raw dictionary against the UPAS Adapter schema and semantic invariants.
    Raises UPASError or specific contract errors on failure.
    """
    if not isinstance(data, dict):
        raise UPASError("Adapter data must be a JSON object", exit_code=ExitCode.TESTS_FAILED)

    # 1. JSON Schema validation
    schema = get_adapter_json_schema()
    try:
        validator = jsonschema.Draft7Validator(schema)
        errors = list(validator.iter_errors(data))
        if errors:
            first_err = errors[0]
            raise UPASError(
                f"Adapter schema validation error: {first_err.message} at path '{list(first_err.path)}'",
                exit_code=ExitCode.TESTS_FAILED,
            )
    except jsonschema.ValidationError as exc:
        raise UPASError(f"Adapter schema validation error: {exc.message}", exit_code=ExitCode.TESTS_FAILED) from exc

    # 2. Core Version Compatibility Gate
    if enforce_core_version:
        target_constraint = data.get("upas_target_version", "")
        compat_res = check_compatibility(UPAS_CORE_VERSION, target_constraint)
        if not compat_res.compatible:
            raise IncompatibleVersionError(
                compat_res.error_message or f"Adapter target version '{target_constraint}' is incompatible with Core {UPAS_CORE_VERSION}"
            )

    # 3. Escalation Triggers Invariant
    triggers = data.get("test_engine", {}).get("escalation_triggers", {})
    db_mig = triggers.get("database_migrations")
    if db_mig not in (4, 5):
        raise EscalationViolationError(
            f"Invalid database_migrations escalation trigger: {db_mig} (must be 4 or 5)"
        )

    # 4. Migration Two-Phase Protocol Invariant
    mig = data.get("migration", {})
    default_class = mig.get("default_classification", "NONE")
    two_phase = mig.get("two_phase_protocol", False)
    if default_class in ("POTENTIALLY_INCOMPATIBLE", "DESTRUCTIVE_IRREVERSIBLE") and not two_phase:
        raise UPASError(
            f"Migration classification '{default_class}' strictly requires 'two_phase_protocol: true'",
            exit_code=ExitCode.TESTS_FAILED,
        )

    # 5. Infrastructure Access Invariant
    infra_deps = data.get("infrastructure_dependencies", [])
    for dep in infra_deps:
        if dep.get("type") != "external" or dep.get("access") != "readonly_consumer":
            raise SharedInfraViolationError(
                f"Infrastructure dependency '{dep.get('name')}' must be type 'external' and access 'readonly_consumer'"
            )

    # 6. Host lock path invariant
    dep_cfg = data.get("deployment", {})
    lock_path = dep_cfg.get("host_lock_path", "/run/lock/upas-deploy.lock")
    if not lock_path.startswith("/"):
        raise UPASError(f"Host lock path must be an absolute POSIX path, got '{lock_path}'", exit_code=ExitCode.TESTS_FAILED)


def load_adapter_from_dict(data: Dict[str, Any], enforce_core_version: bool = True) -> ProjectAdapter:
    """
    Validates and deserializes raw dictionary into typed ProjectAdapter.
    """
    validate_adapter_dict(data, enforce_core_version=enforce_core_version)

    # Project
    p_dict = data["project"]
    project_spec = ProjectSpec(
        name=p_dict["name"],
        type=p_dict["type"],
        language=p_dict["language"],
        runtime_version=str(p_dict["runtime_version"]),
    )

    # Zones
    zones = [
        ZoneSpec(
            name=z["name"],
            paths=list(z["paths"]),
            risk_level=RiskLevel(z["risk_level"]),
            default_test_level=TestLevel(z["default_test_level"]),
        )
        for z in data["zones"]
    ]

    # Test Engine
    te_dict = data["test_engine"]
    test_map = [
        TestMapEntry(
            match=tm["match"],
            tests=list(tm["tests"]),
            escalate_to_level=TestLevel(tm["escalate_to_level"]) if "escalate_to_level" in tm else None,
        )
        for tm in te_dict.get("test_map", [])
    ]
    trig_dict = te_dict["escalation_triggers"]
    triggers = EscalationTriggers(
        database_migrations=trig_dict["database_migrations"],
        database_schemas=trig_dict["database_schemas"],
        api_contracts=trig_dict["api_contracts"],
        runtime_configuration=trig_dict["runtime_configuration"],
        dependency_manifests=trig_dict["dependency_manifests"],
        infrastructure_manifests=trig_dict["infrastructure_manifests"],
        security_sensitive_files=trig_dict["security_sensitive_files"],
    )
    test_engine = TestEngineSpec(
        runner=te_dict["runner"],
        level_commands=dict(te_dict["level_commands"]),
        test_map=test_map,
        escalation_triggers=triggers,
    )

    # Artifact
    art_dict = data["artifact"]
    artifact = ArtifactSpec(
        type=ArtifactType(art_dict["type"]),
        builder=art_dict["builder"],
        registry=art_dict["registry"],
        immutable_tag_format=art_dict["immutable_tag_format"],
    )

    # Resource Gate
    rg_dict = data["resource_gate"]["pre_flight_checks"]
    resource_gate = ResourceGateSpec(
        min_free_ram_mb=float(rg_dict["min_free_ram_mb"]),
        max_swap_usage_pct=float(rg_dict["max_swap_usage_pct"]),
        max_1m_load_average=float(rg_dict["max_1m_load_average"]),
        min_free_disk_gb=float(rg_dict["min_free_disk_gb"]),
        required_shared_containers=list(rg_dict.get("required_shared_containers", [])),
    )

    # Deployment
    dep_dict = data["deployment"]
    deployment = DeploymentSpec(
        strategy=dep_dict["strategy"],
        target_host=dep_dict["target_host"],
        service_name=dep_dict["service_name"],
        runtime_directory=dep_dict["runtime_directory"],
        compose_file=dep_dict.get("compose_file"),
        concurrency_group=dep_dict.get("concurrency_group", "production-deploy"),
        host_lock_path=dep_dict.get("host_lock_path", "/run/lock/upas-deploy.lock"),
        lock_timeout_seconds=int(dep_dict.get("lock_timeout_seconds", 30)),
    )

    # Verification
    ver_dict = data["verification"]
    hc_dict = ver_dict["health_check"]
    health_check = HealthCheckSpec(
        type=hc_dict["type"],
        timeout_seconds=int(hc_dict["timeout_seconds"]),
        max_retries=int(hc_dict["max_retries"]),
        retry_interval_seconds=int(hc_dict["retry_interval_seconds"]),
        endpoint=hc_dict.get("endpoint"),
        expected_status=hc_dict.get("expected_status"),
        command=hc_dict.get("command"),
    )
    smoke_test = None
    if "smoke_test" in ver_dict:
        st_dict = ver_dict["smoke_test"]
        smoke_test = SmokeTestSpec(
            type=st_dict["type"],
            command=st_dict["command"],
            timeout_seconds=int(st_dict["timeout_seconds"]),
        )
    verification = VerificationSpec(health_check=health_check, smoke_test=smoke_test)

    # Backup
    bak_dict = data["backup"]
    backup = BackupSpec(
        type=bak_dict["type"],
        engine_hook=bak_dict["engine_hook"],
        retention_count=int(bak_dict["retention_count"]),
        checkpoint_dir=bak_dict["checkpoint_dir"],
    )

    # Migration
    mig_dict = data["migration"]
    migration = MigrationAdapterSpec(
        classification_policy=MigrationPolicy(mig_dict["classification_policy"]),
        default_classification=MigrationClassification(mig_dict["default_classification"]),
        two_phase_protocol=bool(mig_dict["two_phase_protocol"]),
        pre_deploy_hook=mig_dict.get("pre_deploy_hook"),
        post_deploy_finalize_hook=mig_dict.get("post_deploy_finalize_hook"),
    )

    # Authorization
    auth_dict = data["authorization"]
    authorization = AuthorizationSpec(
        provider=auth_dict["provider"],
        environment_name=auth_dict["environment_name"],
        expected_issuer=auth_dict["expected_issuer"],
        expected_audience=auth_dict["expected_audience"],
        required_claims=list(auth_dict["required_claims"]),
    )

    # Infrastructure Dependencies
    infra_deps = [
        InfrastructureDependencySpec(
            name=ind["name"],
            type=InfraType(ind["type"]),
            access=InfraAccess(ind["access"]),
            health_endpoint_or_container=ind.get("health_endpoint_or_container"),
        )
        for ind in data.get("infrastructure_dependencies", [])
    ]

    return ProjectAdapter(
        schema_version=data["schema_version"],
        upas_target_version=data["upas_target_version"],
        project=project_spec,
        zones=zones,
        test_engine=test_engine,
        artifact=artifact,
        resource_gate=resource_gate,
        deployment=deployment,
        verification=verification,
        backup=backup,
        migration=migration,
        authorization=authorization,
        infrastructure_dependencies=infra_deps,
        raw_dict=data,
    )


def load_and_validate_adapter(adapter_path: str, enforce_core_version: bool = True) -> ProjectAdapter:
    """
    Reads JSON from file path, validates schema and invariants, and returns typed ProjectAdapter.
    """
    if not os.path.exists(adapter_path):
        raise UPASError(
            f"UPAS adapter file not found: '{adapter_path}'",
            exit_code=ExitCode.TESTS_FAILED,
        )

    try:
        with open(adapter_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise UPASError(
            f"Failed to parse UPAS adapter file '{adapter_path}': {exc}",
            exit_code=ExitCode.TESTS_FAILED,
        ) from exc

    return load_adapter_from_dict(data, enforce_core_version=enforce_core_version)
