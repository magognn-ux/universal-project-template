"""
UPAS Version Compatibility Gate.
Enforces Invariant 8: Strict Core/Adapter Version Compatibility (Exit Code 126).
Must be evaluated prior to executing any production mutation.
"""

import re
from typing import Optional
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import IncompatibleVersionError
from upas_core.contracts.interfaces import CompatibilityChecker
from upas_core.contracts.results import CompatibilityResult

_SEMVER_REGEX = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?"
    r"(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


def _normalize_semver_constraint(constraint_str: str) -> str:
    """
    Normalizes SemVer expressions like ^1.2.3, ~1.2.3, 1.0.0 into standard packaging specifiers.
    Fails closed if the format contains invalid characters.
    """
    if not constraint_str or not isinstance(constraint_str, str):
        raise ValueError("Target constraint string cannot be empty or non-string")

    tokens = [t.strip() for t in constraint_str.split(",") if t.strip()]
    if not tokens:
        raise ValueError("Target constraint cannot be empty")

    normalized_tokens = []
    for token in tokens:
        if token == "*":
            normalized_tokens.append(">=0.0.0")
            continue

        # Handle Caret: ^1.2.3 -> >=1.2.3, <2.0.0
        caret_match = re.match(r"^\^(\d+)(?:\.(\d+))?(?:\.(\d+))?$", token)
        if caret_match:
            major = int(caret_match.group(1))
            minor = int(caret_match.group(2) or 0)
            patch = int(caret_match.group(3) or 0)
            base_v = f"{major}.{minor}.{patch}"
            if major > 0:
                next_major = f"{major + 1}.0.0"
                normalized_tokens.append(f">={base_v}")
                normalized_tokens.append(f"<{next_major}")
            elif minor > 0:
                next_minor = f"0.{minor + 1}.0"
                normalized_tokens.append(f">={base_v}")
                normalized_tokens.append(f"<{next_minor}")
            else:
                next_patch = f"0.0.{patch + 1}"
                normalized_tokens.append(f">={base_v}")
                normalized_tokens.append(f"<{next_patch}")
            continue

        # Handle Tilde: ~1.2.3 -> >=1.2.3, <1.3.0
        tilde_match = re.match(r"^~(\d+)\.(\d+)(?:\.(\d+))?$", token)
        if tilde_match:
            major = int(tilde_match.group(1))
            minor = int(tilde_match.group(2))
            patch = int(tilde_match.group(3) or 0)
            base_v = f"{major}.{minor}.{patch}"
            next_minor = f"{major}.{minor + 1}.0"
            normalized_tokens.append(f">={base_v}")
            normalized_tokens.append(f"<{next_minor}")
            continue

        # Handle exact version without operator e.g. "1.0.0" -> "==1.0.0"
        if re.match(r"^\d+\.\d+\.\d+", token):
            normalized_tokens.append(f"=={token}")
            continue

        # Direct operator e.g. ">=1.0.0", "<2.0.0", "==1.0.0"
        if any(token.startswith(op) for op in (">=", "<=", ">", "<", "==", "!=")):
            normalized_tokens.append(token)
            continue

        raise ValueError(f"Unsupported constraint token: '{token}'")

    return ",".join(normalized_tokens)


class SemVerCompatibilityChecker(CompatibilityChecker):
    """
    Authoritative implementation of the UPAS Compatibility Checker.
    Evaluates Core version against Adapter upas_target_version constraint.
    """

    def check_compatibility(self, core_version: str, target_constraint: str) -> CompatibilityResult:
        """
        Evaluate SemVer compatibility between Core and Adapter.
        Returns CompatibilityResult with ExitCode.INCOMPATIBLE_VERSION_ERROR on mismatch or invalid input.
        """
        if not core_version or not isinstance(core_version, str):
            return CompatibilityResult(
                compatible=False,
                core_version=str(core_version),
                target_constraint=str(target_constraint),
                error_message="Core version cannot be empty or non-string",
                exit_code=ExitCode.INCOMPATIBLE_VERSION_ERROR,
            )

        if not target_constraint or not isinstance(target_constraint, str):
            return CompatibilityResult(
                compatible=False,
                core_version=core_version,
                target_constraint=str(target_constraint),
                error_message="Target constraint cannot be empty or non-string",
                exit_code=ExitCode.INCOMPATIBLE_VERSION_ERROR,
            )

        # 1. Parse Core version strictly
        if not _SEMVER_REGEX.match(core_version):
            return CompatibilityResult(
                compatible=False,
                core_version=core_version,
                target_constraint=target_constraint,
                error_message=f"Core version '{core_version}' is not a valid strict SemVer (e.g. '1.0.0')",
                exit_code=ExitCode.INCOMPATIBLE_VERSION_ERROR,
            )

        try:
            parsed_core = Version(core_version)
        except InvalidVersion as exc:
            return CompatibilityResult(
                compatible=False,
                core_version=core_version,
                target_constraint=target_constraint,
                error_message=f"Core version '{core_version}' cannot be parsed as SemVer: {exc}",
                exit_code=ExitCode.INCOMPATIBLE_VERSION_ERROR,
            )

        # 2. Normalize and parse target constraint
        try:
            normalized_spec = _normalize_semver_constraint(target_constraint)
            spec_set = SpecifierSet(normalized_spec)
        except (ValueError, InvalidSpecifier) as exc:
            return CompatibilityResult(
                compatible=False,
                core_version=core_version,
                target_constraint=target_constraint,
                error_message=f"Malformed target constraint '{target_constraint}': {exc}",
                exit_code=ExitCode.INCOMPATIBLE_VERSION_ERROR,
            )

        # 3. Evaluate constraint satisfaction
        if parsed_core in spec_set:
            return CompatibilityResult(
                compatible=True,
                core_version=core_version,
                target_constraint=target_constraint,
                error_message=None,
                exit_code=ExitCode.SUCCESS,
            )
        else:
            return CompatibilityResult(
                compatible=False,
                core_version=core_version,
                target_constraint=target_constraint,
                error_message=(
                    f"Core version '{core_version}' does not satisfy Adapter constraint '{target_constraint}' "
                    f"(normalized: '{normalized_spec}')"
                ),
                exit_code=ExitCode.INCOMPATIBLE_VERSION_ERROR,
            )


def check_compatibility(core_version: str, target_constraint: str) -> CompatibilityResult:
    """Convenience functional interface for compatibility checking."""
    checker = SemVerCompatibilityChecker()
    return checker.check_compatibility(core_version, target_constraint)


def verify_compatibility(core_version: str, target_constraint: str) -> None:
    """
    Fail-closed gate. Raises IncompatibleVersionError (exit code 126) if incompatible.
    """
    result = check_compatibility(core_version, target_constraint)
    if not result.compatible:
        raise IncompatibleVersionError(result.error_message or "Version compatibility check failed")
