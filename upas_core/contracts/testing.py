"""
UPAS Test Engine Contracts.
Models test budget tiers (L0-L5), zones, test mapping, and escalation invariants.
Enforces non-lowerable database migration triggers (Level 4 or 5).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from upas_core.contracts.enums import RiskLevel, TestLevel
from upas_core.contracts.errors import EscalationViolationError


@dataclass(frozen=True)
class ZoneSpec:
    """Project zone specification matching upas.adapter.schema.json."""
    name: str
    paths: List[str]
    risk_level: RiskLevel
    default_test_level: TestLevel

    def __post_init__(self):
        if not self.name:
            raise ValueError("ZoneSpec.name cannot be empty")
        if not self.paths:
            raise ValueError("ZoneSpec.paths cannot be empty")


@dataclass(frozen=True)
class TestMapEntry:
    """Targeted test map rule matching upas.adapter.schema.json."""
    __test__ = False

    match: str
    tests: List[str]
    escalate_to_level: Optional[TestLevel] = None

    def __post_init__(self):
        if not self.match:
            raise ValueError("TestMapEntry.match cannot be empty")
        if not self.tests:
            raise ValueError("TestMapEntry.tests cannot be empty")


@dataclass(frozen=True)
class EscalationTriggers:
    """
    Escalation triggers matching upas.adapter.schema.json.
    Strictly enforces database_migrations in (4, 5).
    """
    database_migrations: int
    database_schemas: int
    api_contracts: int
    runtime_configuration: int
    dependency_manifests: int
    infrastructure_manifests: int
    security_sensitive_files: int

    def __post_init__(self):
        if self.database_migrations not in (4, 5):
            raise ValueError(
                f"Invalid database_migrations escalation level: {self.database_migrations} (must be 4 or 5)"
            )
        for field_name, val in (
            ("database_schemas", self.database_schemas),
            ("api_contracts", self.api_contracts),
            ("dependency_manifests", self.dependency_manifests),
            ("infrastructure_manifests", self.infrastructure_manifests),
            ("security_sensitive_files", self.security_sensitive_files),
        ):
            if val not in (3, 4, 5):
                raise ValueError(f"Invalid {field_name} escalation level: {val} (must be 3, 4, or 5)")
        if self.runtime_configuration not in (3, 4):
            raise ValueError(
                f"Invalid runtime_configuration escalation level: {self.runtime_configuration} (must be 3 or 4)"
            )


@dataclass(frozen=True)
class TestPlan:
    """Resolved test execution plan calculated by TestBudgetEngine."""
    __test__ = False

    resolved_level: TestLevel
    commands: List[str]
    target_tests: List[str]
    reason: str
    escalated_by: List[str] = field(default_factory=list)

    def escalate_to(self, min_level: TestLevel, reason: str) -> "TestPlan":
        """
        Escalate to higher level if required. Refuses to downgrade.
        """
        if min_level < self.resolved_level:
            raise EscalationViolationError(
                f"Cannot downgrade test plan from Level {self.resolved_level.value} to Level {min_level.value}"
            )
        if min_level == self.resolved_level:
            return self
        new_escalated_by = list(self.escalated_by) + [reason]
        return TestPlan(
            resolved_level=min_level,
            commands=self.commands,
            target_tests=self.target_tests,
            reason=f"Escalated: {reason}",
            escalated_by=new_escalated_by,
        )
