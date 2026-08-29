"""
UPAS Execution Module.
Unified safe subprocess execution with process-tree cleanup and strict timeout enforcement.
"""

from upas_core.execution.runner import SafeCommandRunner, run_command

__all__ = [
    "SafeCommandRunner",
    "run_command",
]
