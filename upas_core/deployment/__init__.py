"""
UPAS Deployment Module.
Provides immutable artifact verification, migration orchestration,
rollback safety arbitration, and end-to-end deployment pipeline primitives.
"""

from upas_core.deployment.artifact_verifier import (
    CanonicalArtifactVerifier,
    verify_artifact_digest_chain,
)
from upas_core.deployment.rollback_arbiter import (
    DefaultRollbackSafetyArbiter,
    evaluate_rollback_safety,
)
from upas_core.deployment.migration_runner import (
    SafeMigrationRunner,
)
from upas_core.deployment.deployer import (
    ProductionDeployer,
    DeploymentContext,
    DeploymentExecutionResult,
)

__all__ = [
    "CanonicalArtifactVerifier",
    "verify_artifact_digest_chain",
    "DefaultRollbackSafetyArbiter",
    "evaluate_rollback_safety",
    "SafeMigrationRunner",
    "ProductionDeployer",
    "DeploymentContext",
    "DeploymentExecutionResult",
]
