"""
Targeted tests for UPAS Version Compatibility Gate (Phase 2C-1.1).
Verifies strict SemVer parsing, caret/tilde expansions, range checks, fail-closed handling, and exit code 126.
"""

import pytest
from upas_core.compatibility import SemVerCompatibilityChecker, check_compatibility, verify_compatibility
from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import IncompatibleVersionError


class TestSemVerCompatibilityChecker:
    @pytest.fixture
    def checker(self):
        return SemVerCompatibilityChecker()

    @pytest.mark.parametrize(
        "core_ver,constraint",
        [
            ("1.0.0", "1.0.0"),
            ("1.0.0", ">=1.0.0"),
            ("1.2.3", ">=1.0.0,<2.0.0"),
            ("1.0.0", ">=1.0.0, <=2.0.0"),
            ("1.5.2", "^1.0.0"),
            ("1.2.5", "~1.2.0"),
            ("1.9.9", "*"),
            ("2.1.0", ">=2.0.0, <3.0.0"),
        ],
    )
    def test_compatible_versions_pass(self, checker, core_ver, constraint):
        res = checker.check_compatibility(core_ver, constraint)
        assert res.compatible is True
        assert res.exit_code == ExitCode.SUCCESS
        assert res.error_message is None

    @pytest.mark.parametrize(
        "core_ver,constraint",
        [
            ("2.0.0", "<2.0.0"),
            ("1.0.0", ">=2.0.0"),
            ("0.9.0", ">=1.0.0,<2.0.0"),
            ("2.0.1", "^1.0.0"),
            ("1.3.0", "~1.2.0"),
            ("1.0.0", "1.0.1"),
        ],
    )
    def test_incompatible_versions_fail_closed_with_exit_126(self, checker, core_ver, constraint):
        res = checker.check_compatibility(core_ver, constraint)
        assert res.compatible is False
        assert res.exit_code == ExitCode.INCOMPATIBLE_VERSION_ERROR
        assert res.exit_code == 126
        assert res.error_message is not None

    @pytest.mark.parametrize(
        "invalid_core_ver",
        [
            "",
            "1",
            "1.0",
            "v1.0.0",
            "latest",
            "1.0.0.0",
            None,
        ],
    )
    def test_malformed_core_version_fails_closed(self, checker, invalid_core_ver):
        res = checker.check_compatibility(invalid_core_ver, ">=1.0.0")  # type: ignore
        assert res.compatible is False
        assert res.exit_code == ExitCode.INCOMPATIBLE_VERSION_ERROR
        assert res.exit_code == 126

    @pytest.mark.parametrize(
        "invalid_constraint",
        [
            "",
            "invalid_expression",
            "@@@",
            "===",
            None,
        ],
    )
    def test_malformed_constraint_fails_closed(self, checker, invalid_constraint):
        res = checker.check_compatibility("1.0.0", invalid_constraint)  # type: ignore
        assert res.compatible is False
        assert res.exit_code == ExitCode.INCOMPATIBLE_VERSION_ERROR
        assert res.exit_code == 126

    def test_verify_compatibility_raises_exception_on_incompatible(self):
        with pytest.raises(IncompatibleVersionError) as exc_info:
            verify_compatibility("2.0.0", "<2.0.0")
        assert exc_info.value.exit_code == ExitCode.INCOMPATIBLE_VERSION_ERROR

    def test_verify_compatibility_does_not_raise_on_compatible(self):
        verify_compatibility("1.0.0", ">=1.0.0,<2.0.0")
