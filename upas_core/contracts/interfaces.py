"""
UPAS Core Abstract Interfaces & Protocols.
Implementation-neutral typing contracts for runtime primitives.
All interfaces represent contracts to be implemented in Phase 2C.
"""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from upas_core.contracts.artifacts import ArtifactDescriptor, ArtifactVerificationResult
from upas_core.contracts.enums import TestLevel
from upas_core.contracts.evidence import EvidenceRecord
from upas_core.contracts.execution import CommandSpec, ExecutionResult
from upas_core.contracts.migrations import MigrationResult, MigrationSpec, RollbackDecision
from upas_core.contracts.results import (
    CompatibilityResult,
    GuardResult,
    LockHandle,
    LockResult,
    PreflightResult,
)
from upas_core.contracts.security import AuthResult, OIDCExpectedConfig
from upas_core.contracts.testing import TestPlan


@runtime_checkable
class OIDCVerifier(Protocol):
    """Protocol for cryptographic OIDC token verification."""

    def verify_token(self, token: str, config: OIDCExpectedConfig) -> AuthResult:
        """Verify token against JWKS, claims, expiry, and audience."""
        ...


@runtime_checkable
class JtiStore(Protocol):
    """Protocol for atomic JTI replay prevention storage."""

    def has_jti(self, jti: str) -> bool:
        """Check if JTI has already been used."""
        ...

    def record_jti(self, jti: str, exp: int) -> bool:
        """Record JTI with expiration timestamp. Returns False if already recorded."""
        ...


@runtime_checkable
class HostGuard(Protocol):
    """Protocol for Host-Side authorization enforcement."""

    def authorize_production_mutation(self, token: str, config: OIDCExpectedConfig) -> AuthResult:
        """Evaluate whether a production mutation is authorized."""
        ...


@runtime_checkable
class HostLock(Protocol):
    """Protocol for atomic host deployment locking."""

    def acquire(self, lock_path: str, timeout_seconds: int) -> LockResult:
        """Acquire atomic host lock with timeout and stale PID reclamation."""
        ...

    def release(self, handle: LockHandle) -> bool:
        """Release previously acquired host lock."""
        ...

    def check_liveness(self, pid: int) -> bool:
        """Check if lock holder PID is actively running."""
        ...


@runtime_checkable
class CommandRunner(Protocol):
    """Protocol for safe subprocess execution."""

    def run(self, spec: CommandSpec) -> ExecutionResult:
        """Execute command safely without shell, enforcing timeout and process-tree cleanup."""
        ...


@runtime_checkable
class ArtifactVerifier(Protocol):
    """Protocol for immutable artifact digest verification."""

    def validate_descriptor(self, descriptor: ArtifactDescriptor) -> ArtifactVerificationResult:
        """Validate artifact descriptor structure and canonical immutable pinning."""
        ...

    def verify_runtime_digest(self, expected_digest: str, runtime_target: str) -> ArtifactVerificationResult:
        """Verify pulled and running container digest matches expected digest."""
        ...


@runtime_checkable
class MigrationOrchestrator(Protocol):
    """Protocol for database migration execution and two-phase orchestration."""

    def execute_pre_deploy(self, spec: MigrationSpec) -> MigrationResult:
        """Execute pre-deployment backward-compatible migration phase."""
        ...

    def execute_post_deploy(self, spec: MigrationSpec) -> MigrationResult:
        """Execute post-deployment finalization phase."""
        ...


@runtime_checkable
class RollbackSafetyArbiter(Protocol):
    """Protocol for determining automated rollback safety."""

    def evaluate_rollback(self, spec: MigrationSpec, failure_context: str) -> RollbackDecision:
        """Determine if automatic app rollback is safe or if EMERGENCY_HALT must trigger."""
        ...


@runtime_checkable
class TestEscalationEngine(Protocol):
    """Protocol for dependency-aware test budget and escalation resolution."""
    __test__ = False

    def resolve_plan(
        self,
        changed_files: List[str],
        requested_level: Optional[TestLevel] = None,
    ) -> TestPlan:
        """Resolve minimal necessary test tier and commands based on changed files."""
        ...


@runtime_checkable
class CapabilityValidator(Protocol):
    """Protocol for validating manifest against executable CLI capabilities."""

    def validate_manifest(self, manifest: Dict[str, Any], cli_dispatcher: Any) -> List[str]:
        """Verify all declared capabilities exist in CLI runtime without documentation drift."""
        ...


@runtime_checkable
class InfrastructureGuard(Protocol):
    """Protocol for enforcing shared external infrastructure boundaries."""

    def check_boundary(self, target_resource: str, access_mode: str) -> GuardResult:
        """Verify application does not mutate external shared infrastructure."""
        ...


@runtime_checkable
class CompatibilityChecker(Protocol):
    """Protocol for pre-mutation Core/Adapter SemVer compatibility check."""

    def check_compatibility(self, core_version: str, target_constraint: str) -> CompatibilityResult:
        """Evaluate SemVer compatibility. Fail-closed with Exit 126 on mismatch."""
        ...


@runtime_checkable
class ResourcePreflight(Protocol):
    """Protocol for pre-flight host resource threshold verification."""

    def inspect_resources(self, thresholds: Dict[str, Any]) -> PreflightResult:
        """Check RAM, swap, load average, and disk headroom."""
        ...


@runtime_checkable
class EvidenceGenerator(Protocol):
    """Protocol for generating and validating immutable evidence audit records."""

    def build_evidence(self, record: EvidenceRecord) -> Dict[str, Any]:
        """Serialize and validate evidence record against evidence.schema.json."""
        ...
