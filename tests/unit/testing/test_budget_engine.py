"""
Unit tests for UPAS Test Budget & Escalation Engine.
"""

from pathlib import Path
import pytest

from upas_core.adapter.validator import load_and_validate_adapter
from upas_core.contracts.enums import RiskLevel, TestLevel
from upas_core.contracts.errors import EscalationViolationError
from upas_core.testing.engine import DefaultTestEscalationEngine

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"


@pytest.fixture
def support_bot_adapter():
    adapter_path = FIXTURES_DIR / "valid" / "support_bot_adapter.json"
    return load_and_validate_adapter(str(adapter_path))


def test_resolve_test_plan_no_modified_files(support_bot_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=[],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
    )
    assert plan.resolved_level == TestLevel.L0
    assert "compileall" in plan.commands[0]


def test_resolve_test_plan_targeted_utility(support_bot_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["app/utils/formatting.py"],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
    )
    assert plan.resolved_level == TestLevel.L1
    assert "tests/test_formatting.py" in plan.target_tests


def test_resolve_test_plan_services_zone_escalation(support_bot_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["app/services/support_threads.py"],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
    )
    assert plan.resolved_level == TestLevel.L2
    assert "pytest tests/test_repositories.py tests/test_services.py" in plan.commands[0]


def test_resolve_test_plan_database_migration_escalation_to_l5(support_bot_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["app/db/migrations.py"],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
    )
    # support_bot_adapter specifies database_migrations: 5
    assert plan.resolved_level == TestLevel.L5
    assert "pytest tests/ -v" in plan.commands[0]
    assert any("migration" in reason.lower() for reason in plan.escalated_by)


def test_resolve_test_plan_database_schema_escalation_to_l4(support_bot_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["app/db/schema.sql"],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
    )
    # support_bot_adapter specifies database_schemas: 4
    assert plan.resolved_level == TestLevel.L4
    assert "test_governance_scripts.py" in plan.commands[0]


def test_resolve_test_plan_forced_cli_level(support_bot_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["app/utils/formatting.py"],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
        force_min_level=TestLevel.L3,
    )
    assert plan.resolved_level == TestLevel.L3
    assert "level 3" in plan.reason.lower()


def test_test_plan_cannot_downgrade(support_bot_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["app/db/migrations.py"],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
    )
    assert plan.resolved_level == TestLevel.L5

    with pytest.raises(EscalationViolationError):
        plan.escalate_to(TestLevel.L1, reason="Illegal downgrade attempt")


@pytest.fixture
def tour_monitor_adapter():
    from upas_core.adapter.validator import load_and_validate_adapter
    # Load actual tour-monitor adapter from sister project or template
    adapter_path = Path("C:/Users/user/Projects/tour-monitor/upas.adapter.json")
    if adapter_path.exists():
        return load_and_validate_adapter(str(adapter_path))
    # Fallback to fixture
    return load_and_validate_adapter(str(FIXTURES_DIR / "valid" / "support_bot_adapter.json"))


def test_tour_monitor_services_analytics_resolves_to_l2(tour_monitor_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["services/analytics.py"],
        test_engine=tour_monitor_adapter.test_engine,
        zones=tour_monitor_adapter.zones,
    )
    assert plan.resolved_level == TestLevel.L2
    assert "services_and_tasks" in plan.reason or "services" in plan.reason


def test_tour_monitor_database_schema_resolves_to_l4(tour_monitor_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["database/schema.py"],
        test_engine=tour_monitor_adapter.test_engine,
        zones=tour_monitor_adapter.zones,
    )
    assert plan.resolved_level == TestLevel.L4


def test_tour_monitor_multiple_files_resolves_to_max_level(tour_monitor_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["services/analytics.py", "database/schema.py"],
        test_engine=tour_monitor_adapter.test_engine,
        zones=tour_monitor_adapter.zones,
    )
    assert plan.resolved_level == TestLevel.L4


def test_tour_monitor_upas_files_do_not_downgrade_level(tour_monitor_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["services/analytics.py", "upas.adapter.json", ".github/workflows/upas.yml"],
        test_engine=tour_monitor_adapter.test_engine,
        zones=tour_monitor_adapter.zones,
    )
    assert plan.resolved_level == TestLevel.L2


def test_tour_monitor_only_upas_files_baseline_l1(tour_monitor_adapter):
    engine = DefaultTestEscalationEngine()
    plan = engine.resolve_test_plan(
        modified_files=["upas.adapter.json", ".github/workflows/upas.yml"],
        test_engine=tour_monitor_adapter.test_engine,
        zones=tour_monitor_adapter.zones,
    )
    assert plan.resolved_level == TestLevel.L1
    assert plan.resolved_level != TestLevel.L5


def test_execute_test_plan_with_quoted_arguments(tmp_path):
    """Verifies that quotes in test commands are preserved by shlex.split."""
    from upas_core.contracts.testing import TestPlan
    from upas_core.contracts.execution import CommandSpec, ExecutionResult, ExecutionStatus
    from upas_core.contracts.interfaces import CommandRunner

    class CapturingRunner(CommandRunner):
        def __init__(self):
            self.executed_specs = []

        def run(self, spec: CommandSpec) -> ExecutionResult:
            self.executed_specs.append(spec)
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                stdout="OK",
                stderr="",
                duration_ms=5,
                command=spec.argv,
            )

    runner = CapturingRunner()
    engine = DefaultTestEscalationEngine(command_runner=runner)

    plan = TestPlan(
        resolved_level=TestLevel.L1,
        commands=['pytest -k "test_a or test_b" --tb=short', 'python -c "import sys; sys.exit(0)"'],
        target_tests=[],
        reason="Test quoted args",
        escalated_by=[],
    )

    res = engine.execute_test_plan(plan=plan, project_dir=str(tmp_path))
    assert res.status == ExecutionStatus.SUCCESS
    assert len(runner.executed_specs) == 2
    # Verify first command argv: "test_a or test_b" should be a single token
    assert runner.executed_specs[0].argv == ["pytest", "-k", "test_a or test_b", "--tb=short"]
    # Verify second command argv: "import sys; sys.exit(0)" should be a single token
    assert runner.executed_specs[1].argv == ["python", "-c", "import sys; sys.exit(0)"]


def test_test_budget_strict_monotonicity_supremum(support_bot_adapter):
    """Proves that Test Budget computation strictly computes the mathematical supremum (max)."""
    engine = DefaultTestEscalationEngine()

    # Case 1: L1 file alone -> resolves to L1
    plan1 = engine.resolve_test_plan(
        modified_files=["app/utils/formatting.py"],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
    )
    assert plan1.resolved_level == TestLevel.L1

    # Case 2: L1 file + L2 file -> resolves to L2 (cannot downgrade to L1)
    plan2 = engine.resolve_test_plan(
        modified_files=["app/utils/formatting.py", "app/services/support_threads.py"],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
    )
    assert plan2.resolved_level == TestLevel.L2

    # Case 3: L1 file + L2 file + L4 trigger -> resolves to L4 (cannot downgrade to L2 or L1)
    plan3 = engine.resolve_test_plan(
        modified_files=["app/utils/formatting.py", "app/services/support_threads.py", "app/db/schema.sql"],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
    )
    assert plan3.resolved_level == TestLevel.L4

    # Case 4: L1 file + L2 file + L4 trigger + L5 migration -> resolves to L5
    plan4 = engine.resolve_test_plan(
        modified_files=[
            "app/utils/formatting.py",
            "app/services/support_threads.py",
            "app/db/schema.sql",
            "app/db/migrations.py",
        ],
        test_engine=support_bot_adapter.test_engine,
        zones=support_bot_adapter.zones,
    )
    assert plan4.resolved_level == TestLevel.L5


