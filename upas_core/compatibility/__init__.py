"""
UPAS Compatibility Module.
Pre-mutation Core/Adapter SemVer compatibility verification.
"""

from upas_core.compatibility.checker import SemVerCompatibilityChecker, check_compatibility, verify_compatibility

__all__ = [
    "SemVerCompatibilityChecker",
    "check_compatibility",
    "verify_compatibility",
]
