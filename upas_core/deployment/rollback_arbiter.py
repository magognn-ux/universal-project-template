"""
UPAS Rollback Safety Arbiter.
Implements the RollbackSafetyArbiter protocol.
Enforces Invariant 4: Database Migration Safety & Safe Rollback (Exit Code 81).
"""

from typing import Optional
from upas_core.contracts.enums import FinalVerdictState, MigrationClassification
from upas_core.contracts.interfaces import RollbackSafetyArbiter
from upas_core.contracts.migrations import MigrationSpec, RollbackDecision


class DefaultRollbackSafetyArbiter(RollbackSafetyArbiter):
    """
    Arbiter determining whether automated application rollback is safe,
    or if an incompatible database migration requires EMERGENCY_HALT.
    """

    def evaluate_rollback(
        self,
        spec: MigrationSpec,
        failure_context: str,
    ) -> RollbackDecision:
        """
        Evaluates rollback safety based on migration classification in spec.
        ADDITIVE_COMPATIBLE -> Safe app rollback permitted.
        NON_ADDITIVE -> Automated rollback forbidden, triggers EMERGENCY_HALT.
        """
        if not spec or not isinstance(spec, MigrationSpec):
            return RollbackDecision(
                can_safe_rollback_app=False,
                requires_database_restore_approval=True,
                target_state=FinalVerdictState.EMERGENCY_HALT,
                reason=f"Unknown or missing migration specification. Context: {failure_context}",
            )

        return RollbackDecision.for_classification(
            classification=spec.classification,
            failure_context=failure_context,
        )


def evaluate_rollback_safety(
    spec: MigrationSpec,
    failure_context: str,
    arbiter: Optional[RollbackSafetyArbiter] = None,
) -> RollbackDecision:
    """Convenience functional interface for evaluating rollback safety."""
    a = arbiter or DefaultRollbackSafetyArbiter()
    return a.evaluate_rollback(spec, failure_context)
