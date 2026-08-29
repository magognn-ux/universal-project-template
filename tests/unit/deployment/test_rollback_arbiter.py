"""
Unit tests for UPAS Rollback Safety Arbiter.
Tests additive rollback permission vs non-additive EMERGENCY_HALT escalation.
"""

from upas_core.contracts.enums import FinalVerdictState, MigrationClassification, MigrationPolicy
from upas_core.contracts.migrations import MigrationSpec
from upas_core.deployment.rollback_arbiter import (
    DefaultRollbackSafetyArbiter,
    evaluate_rollback_safety,
)


def test_additive_migration_allows_safe_app_rollback():
    arbiter = DefaultRollbackSafetyArbiter()
    spec = MigrationSpec(
        classification=MigrationClassification.ADDITIVE_COMPATIBLE,
        policy=MigrationPolicy.EXPLICIT_MANIFEST,
        two_phase_protocol=False,
    )

    decision = arbiter.evaluate_rollback(spec, "Health check failed after deploy")
    assert decision.can_safe_rollback_app is True
    assert decision.requires_database_restore_approval is False
    assert decision.target_state == FinalVerdictState.ROLLED_BACK


def test_no_migration_allows_safe_app_rollback():
    arbiter = DefaultRollbackSafetyArbiter()
    spec = MigrationSpec(
        classification=MigrationClassification.NONE,
        policy=MigrationPolicy.EXPLICIT_MANIFEST,
        two_phase_protocol=False,
    )

    decision = arbiter.evaluate_rollback(spec, "Smoke test failure")
    assert decision.can_safe_rollback_app is True
    assert decision.requires_database_restore_approval is False
    assert decision.target_state == FinalVerdictState.ROLLED_BACK


def test_potentially_incompatible_migration_triggers_emergency_halt():
    arbiter = DefaultRollbackSafetyArbiter()
    spec = MigrationSpec(
        classification=MigrationClassification.POTENTIALLY_INCOMPATIBLE,
        policy=MigrationPolicy.EXPLICIT_MANIFEST,
        two_phase_protocol=True,
    )

    decision = arbiter.evaluate_rollback(spec, "Container failed to boot")
    assert decision.can_safe_rollback_app is False
    assert decision.requires_database_restore_approval is True
    assert decision.target_state == FinalVerdictState.EMERGENCY_HALT
    assert "automated app rollback is FORBIDDEN" in decision.reason


def test_destructive_migration_triggers_emergency_halt():
    spec = MigrationSpec(
        classification=MigrationClassification.DESTRUCTIVE_IRREVERSIBLE,
        policy=MigrationPolicy.EXPLICIT_MANIFEST,
        two_phase_protocol=True,
    )

    decision = evaluate_rollback_safety(spec, "Fatal crash loop")
    assert decision.can_safe_rollback_app is False
    assert decision.requires_database_restore_approval is True
    assert decision.target_state == FinalVerdictState.EMERGENCY_HALT
