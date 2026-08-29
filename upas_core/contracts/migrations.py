"""
UPAS Database Migration Safety Contracts.
Defines migration classification specifications, two-phase protocol requirements,
and safe rollback decision contracts (Invariant 4: Database Migration Safety).
"""

from dataclasses import dataclass
from typing import Optional
from upas_core.contracts.enums import FinalVerdictState, MigrationClassification, MigrationPolicy, StepStatus
from upas_core.contracts.errors import MigrationError


@dataclass(frozen=True)
class MigrationSpec:
    """
    Database migration specification matching upas.adapter.schema.json.
    Enforces two_phase_protocol=True for POTENTIALLY_INCOMPATIBLE and DESTRUCTIVE_IRREVERSIBLE.
    """
    classification: MigrationClassification
    policy: MigrationPolicy
    two_phase_protocol: bool
    pre_deploy_hook: Optional[str] = None
    post_deploy_finalize_hook: Optional[str] = None

    def __post_init__(self):
        if self.classification in (
            MigrationClassification.POTENTIALLY_INCOMPATIBLE,
            MigrationClassification.DESTRUCTIVE_IRREVERSIBLE,
        ):
            if not self.two_phase_protocol:
                raise MigrationError(
                    f"Migration classification '{self.classification.value}' strictly requires "
                    f"two_phase_protocol=True."
                )


@dataclass(frozen=True)
class MigrationResult:
    """Result of a migration phase execution."""
    phase: str
    status: StepStatus
    exit_code: int
    duration_ms: int
    error_message: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return self.status == StepStatus.PASS and self.exit_code == 0


@dataclass(frozen=True)
class RollbackDecision:
    """
    Arbiter decision on whether automated application rollback is safe.
    If migration was non-additive, automated rollback is FORBIDDEN and EMERGENCY_HALT is triggered.
    """
    can_safe_rollback_app: bool
    requires_database_restore_approval: bool
    target_state: FinalVerdictState
    reason: str

    @classmethod
    def for_classification(cls, classification: MigrationClassification, failure_context: str) -> "RollbackDecision":
        """
        Evaluate rollback safety based on migration classification.
        ADDITIVE_COMPATIBLE -> Safe app rollback permitted.
        POTENTIALLY_INCOMPATIBLE / DESTRUCTIVE_IRREVERSIBLE -> Automated rollback blocked, EMERGENCY_HALT.
        """
        if classification in (
            MigrationClassification.NONE,
            MigrationClassification.ADDITIVE_COMPATIBLE,
        ):
            return cls(
                can_safe_rollback_app=True,
                requires_database_restore_approval=False,
                target_state=FinalVerdictState.ROLLED_BACK,
                reason=f"Additive/No schema migration: safe automated app rollback permitted. Context: {failure_context}",
            )
        else:
            return cls(
                can_safe_rollback_app=False,
                requires_database_restore_approval=True,
                target_state=FinalVerdictState.EMERGENCY_HALT,
                reason=(
                    f"Non-additive migration ({classification.value}) applied: automated app rollback "
                    f"is FORBIDDEN to prevent schema corruption. Explicit human DB restore approval required. "
                    f"Context: {failure_context}"
                ),
            )
