"""
UPAS Project Discovery and Capability Detector.
Discovers UPAS adapters, inspects Git state, and validates project capabilities.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

from upas_core.adapter.model import ProjectAdapter
from upas_core.adapter.validator import load_and_validate_adapter
from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import CapabilityMismatchError, UPASError


@dataclass(frozen=True)
class GitState:
    """Inspected Git repository state."""
    is_git_repo: bool
    commit_sha: str
    branch: str
    is_dirty: bool
    untracked_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class CapabilityValidationResult:
    """Outcome of project capability verification against adapter contract."""
    passed: bool
    project_name: str
    adapter_path: str
    git_state: GitState
    missing_capabilities: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    exit_code: ExitCode = ExitCode.SUCCESS


def inspect_git_state(project_dir: str) -> GitState:
    """
    Safely inspects the Git repository status in project_dir.
    Returns GitState without modifying anything.
    """
    proj_path = Path(project_dir).resolve()
    git_dir = proj_path / ".git"

    if not git_dir.exists() and not (proj_path / "HEAD").exists():
        # Check if parent is git
        try:
            res = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(proj_path),
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                return GitState(
                    is_git_repo=False,
                    commit_sha="0000000000000000000000000000000000000000",
                    branch="detached",
                    is_dirty=False,
                )
        except Exception:
            return GitState(
                is_git_repo=False,
                commit_sha="0000000000000000000000000000000000000000",
                branch="detached",
                is_dirty=False,
            )

    try:
        # Commit SHA
        sha_res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(proj_path),
            capture_output=True,
            text=True,
            check=False,
        )
        commit_sha = sha_res.stdout.strip() if sha_res.returncode == 0 else "0000000000000000000000000000000000000000"

        # Branch
        branch_res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(proj_path),
            capture_output=True,
            text=True,
            check=False,
        )
        branch = branch_res.stdout.strip() if branch_res.returncode == 0 else "unknown"

        # Status --porcelain
        status_res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(proj_path),
            capture_output=True,
            text=True,
            check=False,
        )
        untracked = []
        modified = []
        for line in status_res.stdout.splitlines():
            if not line or len(line) < 4:
                continue
            status_code = line[:2]
            file_path = line[3:].strip()
            if file_path.startswith('"') and file_path.endswith('"'):
                file_path = file_path[1:-1]
            if " -> " in file_path:
                file_path = file_path.split(" -> ")[-1].strip()
            file_path = file_path.replace("\\", "/").lstrip("/")
            if status_code == "??":
                untracked.append(file_path)
            else:
                modified.append(file_path)

        is_dirty = len(untracked) > 0 or len(modified) > 0

        return GitState(
            is_git_repo=True,
            commit_sha=commit_sha,
            branch=branch,
            is_dirty=is_dirty,
            untracked_files=untracked,
            modified_files=modified,
        )
    except Exception:
        return GitState(
            is_git_repo=False,
            commit_sha="0000000000000000000000000000000000000000",
            branch="detached",
            is_dirty=False,
        )


class ProjectCapabilityDetector:
    """
    Authoritative discovery engine for detecting and verifying project capabilities.
    """

    def discover_adapter(self, target_path: str) -> str:
        """
        Discovers the upas.adapter.json given a directory or direct file path.
        """
        p = Path(target_path).resolve()
        if p.is_file():
            return str(p)
        
        adapter_file = p / "upas.adapter.json"
        if adapter_file.exists():
            return str(adapter_file)

        # Look in .upas or root
        dot_upas = p / ".upas" / "upas.adapter.json"
        if dot_upas.exists():
            return str(dot_upas)

        raise UPASError(
            f"No UPAS adapter found in project path '{target_path}'. Expected 'upas.adapter.json'.",
            exit_code=ExitCode.CAPABILITY_MISMATCH,
        )

    def validate_capabilities(
        self,
        project_dir: str,
        adapter: Optional[ProjectAdapter] = None,
        adapter_path: Optional[str] = None,
    ) -> CapabilityValidationResult:
        """
        Validates that the project directory actually provides all capabilities declared in the adapter.
        Fail-closed with ExitCode.CAPABILITY_MISMATCH if any required capability is missing.
        """
        proj_path = Path(project_dir).resolve()
        resolved_adapter_path = adapter_path or self.discover_adapter(project_dir)
        loaded_adapter = adapter or load_and_validate_adapter(resolved_adapter_path)

        git_state = inspect_git_state(str(proj_path))
        missing_capabilities: List[str] = []
        details: Dict[str, Any] = {
            "project_name": loaded_adapter.project.name,
            "language": loaded_adapter.project.language,
            "runtime_version": loaded_adapter.project.runtime_version,
            "test_runner": loaded_adapter.test_engine.runner,
            "artifact_type": loaded_adapter.artifact.type.value,
        }

        # 1. Verify Test Runner tool availability
        test_runner = loaded_adapter.test_engine.runner
        if test_runner == "pytest":
            try:
                import pytest
                details["pytest_version"] = pytest.__version__
            except ImportError:
                missing_capabilities.append("test_runner: pytest not installed in python environment")

        # 2. Verify Compose file if specified in deployment
        if loaded_adapter.deployment.compose_file:
            compose_file = proj_path / loaded_adapter.deployment.compose_file
            if not compose_file.exists():
                missing_capabilities.append(
                    f"compose_file: Declared compose file '{loaded_adapter.deployment.compose_file}' does not exist in project"
                )

        # 3. Verify Backup Hook existence if relative path within project
        backup_hook = loaded_adapter.backup.engine_hook
        if not backup_hook.startswith("/") and not backup_hook.startswith("python -m") and not backup_hook.startswith("docker"):
            hook_path = proj_path / backup_hook
            # Only fail if it's explicitly a local file path
            if (backup_hook.endswith(".py") or backup_hook.endswith(".sh") or backup_hook.endswith(".ps1")) and not hook_path.exists():
                missing_capabilities.append(
                    f"backup_hook: Declared backup hook script '{backup_hook}' not found in project"
                )

        passed = len(missing_capabilities) == 0
        exit_code = ExitCode.SUCCESS if passed else ExitCode.CAPABILITY_MISMATCH

        return CapabilityValidationResult(
            passed=passed,
            project_name=loaded_adapter.project.name,
            adapter_path=resolved_adapter_path,
            git_state=git_state,
            missing_capabilities=missing_capabilities,
            details=details,
            exit_code=exit_code,
        )


def resolve_changed_files(
    project_dir: str,
    explicit_files: Optional[str] = None,
) -> Tuple[List[str], str]:
    """
    Authoritatively resolves the list of changed files for Test Budget calculation.
    Deterministic across local workstations and remote CI environments.
    """
    proj_path = Path(project_dir).resolve()

    # 1. Explicit CLI files flag (backward compatibility & explicit overrides)
    if explicit_files:
        files = [
            f.strip().replace("\\", "/").lstrip("/")
            for f in explicit_files.split(",")
            if f.strip()
        ]
        deduped = list(dict.fromkeys(files))
        return deduped, "cli_explicit_argument"

    # 2. Local working tree (staged, unstaged, untracked via porcelain)
    git_state = inspect_git_state(str(proj_path))
    local_changes = list(dict.fromkeys(git_state.modified_files + git_state.untracked_files))
    if local_changes:
        return local_changes, "git_porcelain_working_tree"

    if not git_state.is_git_repo:
        return [], "non_git_workspace"

    # 3. CI / Commit Diff Inspection (when working tree is clean)
    base_ref = os.environ.get("GITHUB_BASE_REF") or os.environ.get("UPAS_BASE_REF")
    if base_ref:
        for ref_spec in [f"origin/{base_ref}...HEAD", f"{base_ref}...HEAD", f"origin/{base_ref}", base_ref]:
            try:
                diff_res = subprocess.run(
                    ["git", "diff", "--name-only", ref_spec],
                    cwd=str(proj_path),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if diff_res.returncode == 0 and diff_res.stdout.strip():
                    files = [
                        line.strip().replace("\\", "/").lstrip("/")
                        for line in diff_res.stdout.splitlines()
                        if line.strip()
                    ]
                    return list(dict.fromkeys(files)), f"git_diff_pr_base({ref_spec})"
            except Exception:
                pass

    # Check common base branches fallback (origin/main, main, master)
    for fallback_ref in ["origin/main...HEAD", "main...HEAD", "origin/master...HEAD", "master...HEAD"]:
        try:
            diff_res = subprocess.run(
                ["git", "diff", "--name-only", fallback_ref],
                cwd=str(proj_path),
                capture_output=True,
                text=True,
                check=False,
            )
            if diff_res.returncode == 0 and diff_res.stdout.strip():
                files = [
                    line.strip().replace("\\", "/").lstrip("/")
                    for line in diff_res.stdout.splitlines()
                    if line.strip()
                ]
                return list(dict.fromkeys(files)), f"git_diff_fallback_branch({fallback_ref})"
        except Exception:
            pass

    # Check Commit vs Parent (HEAD~1 HEAD or HEAD^!)
    try:
        diff_res = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
            cwd=str(proj_path),
            capture_output=True,
            text=True,
            check=False,
        )
        if diff_res.returncode == 0 and diff_res.stdout.strip():
            files = [
                line.strip().replace("\\", "/").lstrip("/")
                for line in diff_res.stdout.splitlines()
                if line.strip()
            ]
            return list(dict.fromkeys(files)), "git_diff_head_parent"
    except Exception:
        pass

    # Check HEAD single commit diff (initial commit or detached head)
    try:
        diff_res = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
            cwd=str(proj_path),
            capture_output=True,
            text=True,
            check=False,
        )
        if diff_res.returncode == 0 and diff_res.stdout.strip():
            files = [
                line.strip().replace("\\", "/").lstrip("/")
                for line in diff_res.stdout.splitlines()
                if line.strip()
            ]
            return list(dict.fromkeys(files)), "git_diff_tree_head"
    except Exception:
        pass

    return [], "clean_working_tree_no_diff"


def discover_and_validate_project(project_dir: str) -> CapabilityValidationResult:
    """Convenience functional interface for project discovery and validation."""
    detector = ProjectCapabilityDetector()
    return detector.validate_capabilities(project_dir)
