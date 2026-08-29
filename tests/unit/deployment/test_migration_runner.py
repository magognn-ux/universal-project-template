"""
Unit tests for UPAS Safe Migration Runner.
Tests pre-deploy and post-deploy execution hooks and fail-closed error handling.
"""

import sys
from upas_core.contracts.enums import MigrationClassification, MigrationPolicy, StepStatus
from upas_core.contracts.migrations import MigrationSpec
from upas_core.deployment.migration_runner import SafeMigrationRunner
from upas_core.execution.runner import SafeCommandRunner


def test_migration_runner_none_classification_passes():
    runner = SafeMigrationRunner()
    spec = MigrationSpec(
        classification=MigrationClassification.NONE,
        policy=MigrationPolicy.EXPLICIT_MANIFEST,
        two_phase_protocol=False,
    )

    res_pre = runner.execute_pre_deploy(spec)
    assert res_pre.is_success is True
    assert res_pre.exit_code == 0

    res_post = runner.execute_post_deploy(spec)
    assert res_post.is_success is True


def test_migration_runner_successful_hook_execution():
    runner = SafeMigrationRunner(runner=SafeCommandRunner())
    spec = MigrationSpec(
        classification=MigrationClassification.ADDITIVE_COMPATIBLE,
        policy=MigrationPolicy.EXPLICIT_MANIFEST,
        two_phase_protocol=False,
        pre_deploy_hook=f"{sys.executable} -c 'print(\"running additive migration\")'",
    )

    res = runner.execute_pre_deploy(spec)
    assert res.is_success is True
    assert res.status == StepStatus.PASS
    assert res.exit_code == 0


def test_migration_runner_failed_hook_fails_closed():
    runner = SafeMigrationRunner(runner=SafeCommandRunner())
    spec = MigrationSpec(
        classification=MigrationClassification.ADDITIVE_COMPATIBLE,
        policy=MigrationPolicy.EXPLICIT_MANIFEST,
        two_phase_protocol=False,
        pre_deploy_hook=f"{sys.executable} -c 'import sys; sys.stderr.write(\"db syntax error\"); sys.exit(1)'",
    )

    res = runner.execute_pre_deploy(spec)
    assert res.is_success is False
    assert res.status == StepStatus.FAIL
    assert res.exit_code == 70
    assert "db syntax error" in res.error_message
