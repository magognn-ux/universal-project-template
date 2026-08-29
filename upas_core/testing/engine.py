"""
UPAS Test Budget & Escalation Engine.
Authoritative implementation of the TestEscalationEngine contract.
Maps modified file paths to zones, targeted test rules, and non-lowerable escalation tiers (L0-L5).
"""

import fnmatch
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from upas_core.adapter.model import ProjectAdapter, TestEngineSpec
from upas_core.contracts.enums import ExecutionStatus, ExitCode, RiskLevel, TestLevel
from upas_core.contracts.errors import EscalationViolationError
from upas_core.contracts.execution import ExecutionResult
from upas_core.contracts.interfaces import CommandRunner, TestEscalationEngine
from upas_core.contracts.testing import EscalationTriggers, TestMapEntry, TestPlan, ZoneSpec
from upas_core.execution.runner import SafeCommandRunner


def _normalize_rel_path(path: str) -> str:
    """Normalizes path to forward slashes without leading slash."""
    return path.replace("\\", "/").lstrip("/")


def _path_matches_pattern(path: str, pattern: str) -> bool:
    """
    Checks if a normalized relative file path matches a glob pattern or prefix.
    Supports standard wildcards (*, **, ?).
    """
    norm_path = _normalize_rel_path(path)
    norm_pattern = _normalize_rel_path(pattern)

    # Direct equality
    if norm_path == norm_pattern:
        return True

    # Prefix match if pattern ends with /
    if norm_pattern.endswith("/") and norm_path.startswith(norm_pattern):
        return True

    # Wildcard match
    if fnmatch.fnmatch(norm_path, norm_pattern):
        return True

    # Subdirectory match for patterns with **
    if "**" in norm_pattern:
        regex_pattern = norm_pattern.replace(".", r"\.").replace("**", ".*").replace("*", "[^/]*")
        if re.fullmatch(regex_pattern, norm_path):
            return True

    # Fallback to substring if pattern is a folder
    if "/" in norm_pattern and not any(c in norm_pattern for c in "*?[]"):
        if norm_path.startswith(norm_pattern):
            return True

    return False


class DefaultTestEscalationEngine(TestEscalationEngine):
    """
    Authoritative test selection and escalation engine.
    Calculates the exact test budget tier and resolves the executable command suite.
    """

    def __init__(self, command_runner: Optional[CommandRunner] = None):
        self.command_runner = command_runner or SafeCommandRunner()

    def resolve_test_plan(
        self,
        modified_files: List[str],
        test_engine: TestEngineSpec,
        zones: Optional[List[ZoneSpec]] = None,
        force_min_level: Optional[TestLevel] = None,
    ) -> TestPlan:
        """
        Calculates the minimum required test plan given modified files and project specs.
        Strictly enforces database migration triggers (Level 4 or 5) and prevents downgrading.
        """
        if not modified_files:
            # Default to L0 syntax/compilation check if no files changed
            l0_cmd = test_engine.level_commands.get("level_0", "python -m compileall .")
            plan = TestPlan(
                resolved_level=TestLevel.L0,
                commands=[l0_cmd],
                target_tests=[],
                reason="No modified files detected; running L0 baseline check",
                escalated_by=[],
            )
            if force_min_level and force_min_level > plan.resolved_level:
                return self._apply_forced_level(plan, force_min_level, test_engine)
            return plan

        max_level_val = TestLevel.L1.value
        matched_target_tests: List[str] = []
        escalation_reasons: List[str] = []

        # 1. Evaluate Zone Mappings
        if zones:
            for file_path in modified_files:
                for zone in zones:
                    for zone_path in zone.paths:
                        if _path_matches_pattern(file_path, zone_path):
                            if zone.default_test_level.value > max_level_val:
                                max_level_val = zone.default_test_level.value
                                escalation_reasons.append(
                                    f"Zone '{zone.name}' (Risk: {zone.risk_level.value}) sets default level {zone.default_test_level.value}"
                                )

        # 2. Evaluate Targeted Test Map
        for file_path in modified_files:
            for entry in test_engine.test_map:
                if _path_matches_pattern(file_path, entry.match):
                    matched_target_tests.extend(entry.tests)
                    if entry.escalate_to_level and entry.escalate_to_level.value > max_level_val:
                        max_level_val = entry.escalate_to_level.value
                        escalation_reasons.append(
                            f"TestMap rule '{entry.match}' escalated to level {entry.escalate_to_level.value}"
                        )

        # 3. Evaluate Escalation Triggers
        triggers = test_engine.escalation_triggers
        for file_path in modified_files:
            norm = _normalize_rel_path(file_path).lower()
            name = Path(norm).name

            # Database Migrations (must be 4 or 5)
            if "migration" in norm or "alembic" in norm or "migrations" in norm:
                req_level = triggers.database_migrations
                if req_level > max_level_val:
                    max_level_val = req_level
                    escalation_reasons.append(f"Database migration file '{file_path}' triggered Level {req_level} gate")

            # Database Schemas
            elif "schema" in norm or "models" in norm or norm.endswith(".sql"):
                req_level = triggers.database_schemas
                if req_level > max_level_val:
                    max_level_val = req_level
                    escalation_reasons.append(f"Database schema file '{file_path}' triggered Level {req_level} gate")

            # API Contracts
            elif "api" in norm or "contract" in norm or "openapi" in norm or "webhook" in norm:
                req_level = triggers.api_contracts
                if req_level > max_level_val:
                    max_level_val = req_level
                    escalation_reasons.append(f"API contract file '{file_path}' triggered Level {req_level} gate")

            # Runtime Configuration
            elif "config" in norm or "settings" in norm or ".env" in norm or name.startswith(".env"):
                req_level = triggers.runtime_configuration
                if req_level > max_level_val:
                    max_level_val = req_level
                    escalation_reasons.append(f"Runtime configuration file '{file_path}' triggered Level {req_level} gate")

            # Dependency Manifests
            elif name in ("requirements.txt", "requirements-dev.txt", "package.json", "poetry.lock", "cargo.toml", "pyproject.toml"):
                req_level = triggers.dependency_manifests
                if req_level > max_level_val:
                    max_level_val = req_level
                    escalation_reasons.append(f"Dependency manifest '{file_path}' triggered Level {req_level} gate")

            # Infrastructure Manifests
            elif "docker" in norm or "dockerfile" in norm or "compose" in norm or norm.endswith(".tf") or "nginx" in norm:
                req_level = triggers.infrastructure_manifests
                if req_level > max_level_val:
                    max_level_val = req_level
                    escalation_reasons.append(f"Infrastructure manifest '{file_path}' triggered Level {req_level} gate")

            # Security Sensitive Files
            elif "auth" in norm or "security" in norm or "secret" in norm or "oidc" in norm or "ssh" in norm:
                req_level = triggers.security_sensitive_files
                if req_level > max_level_val:
                    max_level_val = req_level
                    escalation_reasons.append(f"Security sensitive file '{file_path}' triggered Level {req_level} gate")

        resolved_test_level = TestLevel(max_level_val)
        level_key = f"level_{resolved_test_level.value}"
        cmd = test_engine.level_commands.get(level_key)
        if not cmd:
            cmd = test_engine.level_commands.get("level_5", "pytest -v")

        # Deduplicate target tests
        deduped_tests = list(dict.fromkeys(matched_target_tests))

        reason = (
            "; ".join(escalation_reasons)
            if escalation_reasons
            else f"Resolved Level {resolved_test_level.value} based on {len(modified_files)} modified file(s)"
        )

        plan = TestPlan(
            resolved_level=resolved_test_level,
            commands=[cmd],
            target_tests=deduped_tests,
            reason=reason,
            escalated_by=escalation_reasons,
        )

        if force_min_level and force_min_level > plan.resolved_level:
            return self._apply_forced_level(plan, force_min_level, test_engine)

        return plan

    def _apply_forced_level(self, plan: TestPlan, force_level: TestLevel, test_engine: TestEngineSpec) -> TestPlan:
        """Applies forced minimum level escalation."""
        cmd = test_engine.level_commands.get(f"level_{force_level.value}") or test_engine.level_commands.get("level_5", "pytest")
        return TestPlan(
            resolved_level=force_level,
            commands=[cmd],
            target_tests=plan.target_tests,
            reason=f"Forced escalation to Level {force_level.value} (was {plan.resolved_level.value})",
            escalated_by=list(plan.escalated_by) + [f"CLI/CI forced level {force_level.value}"],
        )

    def execute_test_plan(self, plan: TestPlan, project_dir: str, timeout_seconds: int = 180) -> ExecutionResult:
        """
        Executes the resolved test plan commands safely in project_dir.
        """
        import os
        import shlex
        import sys
        from upas_core.contracts.execution import CommandSpec

        last_res = None
        proj_abs = os.path.abspath(project_dir)
        env = {
            "PYTHONPATH": f"{proj_abs}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"
        }

        for cmd_str in plan.commands:
            argv = shlex.split(cmd_str, posix=True)
            spec = CommandSpec(
                argv=argv,
                timeout_seconds=timeout_seconds,
                cwd=project_dir,
                env=env,
            )
            res = self.command_runner.run(spec)
            last_res = res
            if res.status != ExecutionStatus.SUCCESS:
                return res

        return last_res or ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            stdout="No test commands executed",
            stderr="",
            duration_ms=0,
            command=[],
        )
