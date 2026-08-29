"""
UPAS Canonical Adapter Data Model.
Typed data representation of the project-specific adapter contract (upas.adapter.schema.json).
Encapsulates project facts, test strategies, deployment configuration, and security policies.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from upas_core.contracts.artifacts import ArtifactType
from upas_core.contracts.enums import (
    InfraAccess,
    InfraType,
    MigrationClassification,
    MigrationPolicy,
    RiskLevel,
    TestLevel,
)
from upas_core.contracts.migrations import MigrationSpec
from upas_core.contracts.security import OIDCExpectedConfig
from upas_core.contracts.testing import EscalationTriggers, TestMapEntry, ZoneSpec


@dataclass(frozen=True)
class ProjectSpec:
    """Project identity and runtime specification."""
    name: str
    type: str
    language: str
    runtime_version: str


@dataclass(frozen=True)
class TestEngineSpec:
    """Test engine and test escalation specification."""
    runner: str
    level_commands: Dict[str, str]
    test_map: List[TestMapEntry]
    escalation_triggers: EscalationTriggers


@dataclass(frozen=True)
class ArtifactSpec:
    """Artifact packaging and registry specification."""
    type: ArtifactType
    builder: str
    registry: str
    immutable_tag_format: str


@dataclass(frozen=True)
class ResourceGateSpec:
    """Resource thresholds and shared dependencies for preflight gate."""
    min_free_ram_mb: float
    max_swap_usage_pct: float
    max_1m_load_average: float
    min_free_disk_gb: float
    required_shared_containers: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class DeploymentSpec:
    """Deployment target and runtime orchestration configuration."""
    strategy: str
    target_host: str
    service_name: str
    runtime_directory: str
    compose_file: Optional[str] = None
    concurrency_group: str = "production-deploy"
    host_lock_path: str = "/run/lock/upas-deploy.lock"
    lock_timeout_seconds: int = 30


@dataclass(frozen=True)
class HealthCheckSpec:
    """Post-deployment runtime health check specification."""
    type: str
    timeout_seconds: int
    max_retries: int
    retry_interval_seconds: int
    endpoint: Optional[str] = None
    expected_status: Optional[int] = None
    command: Optional[str] = None


@dataclass(frozen=True)
class SmokeTestSpec:
    """Post-deployment runtime smoke test specification."""
    type: str
    command: str
    timeout_seconds: int


@dataclass(frozen=True)
class VerificationSpec:
    """Verification strategy containing health check and smoke test."""
    health_check: HealthCheckSpec
    smoke_test: Optional[SmokeTestSpec] = None


@dataclass(frozen=True)
class BackupSpec:
    """Pre-deploy backup hook and retention specification."""
    type: str
    engine_hook: str
    retention_count: int
    checkpoint_dir: str


@dataclass(frozen=True)
class MigrationAdapterSpec:
    """Database migration policy specification in adapter."""
    classification_policy: MigrationPolicy
    default_classification: MigrationClassification
    two_phase_protocol: bool
    pre_deploy_hook: Optional[str] = None
    post_deploy_finalize_hook: Optional[str] = None


@dataclass(frozen=True)
class InfrastructureDependencySpec:
    """External shared infrastructure dependency specification."""
    name: str
    type: InfraType
    access: InfraAccess
    health_endpoint_or_container: Optional[str] = None


@dataclass(frozen=True)
class AuthorizationSpec:
    """Production authorization and OIDC verification specification."""
    provider: str
    environment_name: str
    expected_issuer: str
    expected_audience: str
    required_claims: List[str]


@dataclass(frozen=True)
class ProjectAdapter:
    """Canonical typed representation of the entire upas.adapter.json."""
    schema_version: str
    upas_target_version: str
    project: ProjectSpec
    zones: List[ZoneSpec]
    test_engine: TestEngineSpec
    artifact: ArtifactSpec
    resource_gate: ResourceGateSpec
    deployment: DeploymentSpec
    verification: VerificationSpec
    backup: BackupSpec
    migration: MigrationAdapterSpec
    authorization: AuthorizationSpec
    infrastructure_dependencies: List[InfrastructureDependencySpec] = field(default_factory=list)
    raw_dict: Dict[str, Any] = field(default_factory=dict)

    def to_migration_spec(self) -> MigrationSpec:
        """Converts adapter migration configuration into core MigrationSpec."""
        return MigrationSpec(
            classification=self.migration.default_classification,
            policy=self.migration.classification_policy,
            two_phase_protocol=self.migration.two_phase_protocol,
            pre_deploy_hook=self.migration.pre_deploy_hook,
            post_deploy_finalize_hook=self.migration.post_deploy_finalize_hook,
        )

    def to_oidc_config(self, repository: Optional[str] = None) -> OIDCExpectedConfig:
        """Converts adapter authorization configuration into core OIDCExpectedConfig."""
        return OIDCExpectedConfig(
            expected_issuer=self.authorization.expected_issuer,
            expected_audience=self.authorization.expected_audience,
            expected_repository=repository or "octocat/hello-world",
            expected_environment=self.authorization.environment_name,
            required_claims=list(self.authorization.required_claims),
        )
