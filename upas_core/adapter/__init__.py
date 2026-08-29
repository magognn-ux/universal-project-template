"""
UPAS Project Adapter Subsystem.
Provides typed loading, validation, discovery, and serialization of UPAS project adapters.
"""

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
from upas_core.adapter.validator import (
    load_adapter_from_dict,
    load_and_validate_adapter,
    validate_adapter_dict,
)

__all__ = [
    "ArtifactSpec",
    "AuthorizationSpec",
    "BackupSpec",
    "DeploymentSpec",
    "HealthCheckSpec",
    "InfrastructureDependencySpec",
    "MigrationAdapterSpec",
    "ProjectAdapter",
    "ProjectSpec",
    "ResourceGateSpec",
    "SmokeTestSpec",
    "TestEngineSpec",
    "VerificationSpec",
    "load_adapter_from_dict",
    "load_and_validate_adapter",
    "validate_adapter_dict",
]
