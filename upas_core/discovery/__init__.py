"""
UPAS Project Discovery and Capability Detector Package.
"""

from upas_core.discovery.detector import (
    CapabilityValidationResult,
    GitState,
    ProjectCapabilityDetector,
    discover_and_validate_project,
    inspect_git_state,
)

__all__ = [
    "CapabilityValidationResult",
    "GitState",
    "ProjectCapabilityDetector",
    "discover_and_validate_project",
    "inspect_git_state",
]
