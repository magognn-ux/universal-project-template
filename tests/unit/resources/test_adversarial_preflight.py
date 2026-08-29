"""
Adversarial tests for Phase 2C-1 Edge Cases and Bypass Scenarios in Resource Preflight.
Verifies strict rejection of IEEE 754 non-finite values (NaN, +Infinity, -Infinity)
and proves fail-closed behavior with Exit Code 79 (FAILED_PREFLIGHT).
"""

import math
import pytest
from upas_core.contracts.enums import ExitCode
from upas_core.resources import (
    HostResourcePreflight,
    SystemMetrics,
    SystemMetricsCollector,
    inspect_host_resources,
)


class MockCollector(SystemMetricsCollector):
    def __init__(self, metrics: SystemMetrics = None):
        self._metrics = metrics or SystemMetrics(
            ram_free_mb=100.0,
            swap_usage_pct=90.0,
            load_1m=10.0,
            disk_free_gb=1.0,
            running_containers=[],
        )

    def collect(self, disk_path: str = "/") -> SystemMetrics:
        return self._metrics


class TestAdversarialEdgeCases:
    @pytest.fixture
    def base_valid_thresholds(self):
        return {
            "min_free_ram_mb": 512.0,
            "max_swap_usage_pct": 50.0,
            "max_1m_load_average": 4.0,
            "min_free_disk_gb": 10.0,
        }

    # 1. Existing reproducing test (mandatory preservation)
    def test_nan_in_thresholds_must_fail_closed(self):
        nan_thresholds = {
            "min_free_ram_mb": float("nan"),
            "max_swap_usage_pct": float("nan"),
            "max_1m_load_average": float("nan"),
            "min_free_disk_gb": float("nan"),
        }
        res = inspect_host_resources(nan_thresholds, collector=MockCollector())
        assert res.passed is False, f"NaN in thresholds must fail closed, but got passed={res.passed}"
        assert res.exit_code == ExitCode.FAILED_PREFLIGHT
        assert res.exit_code == 79
        assert "finite" in res.error_message.lower()

    # 2. NaN in each numeric threshold individually
    @pytest.mark.parametrize(
        "threshold_key",
        [
            "min_free_ram_mb",
            "max_swap_usage_pct",
            "max_1m_load_average",
            "min_free_disk_gb",
        ],
    )
    def test_individual_nan_threshold_fails_closed(self, base_valid_thresholds, threshold_key):
        thresholds = dict(base_valid_thresholds)
        thresholds[threshold_key] = float("nan")
        res = inspect_host_resources(thresholds, collector=MockCollector())

        assert res.passed is False
        assert res.exit_code == ExitCode.FAILED_PREFLIGHT
        assert res.exit_code == 79
        assert "finite" in res.error_message.lower()

    # 3. +Infinity in each numeric threshold individually
    @pytest.mark.parametrize(
        "threshold_key",
        [
            "min_free_ram_mb",
            "max_swap_usage_pct",
            "max_1m_load_average",
            "min_free_disk_gb",
        ],
    )
    def test_individual_plus_infinity_threshold_fails_closed(self, base_valid_thresholds, threshold_key):
        thresholds = dict(base_valid_thresholds)
        thresholds[threshold_key] = float("inf")
        res = inspect_host_resources(thresholds, collector=MockCollector())

        assert res.passed is False
        assert res.exit_code == ExitCode.FAILED_PREFLIGHT
        assert res.exit_code == 79
        assert "finite" in res.error_message.lower()

    # 4. -Infinity in each numeric threshold individually
    @pytest.mark.parametrize(
        "threshold_key",
        [
            "min_free_ram_mb",
            "max_swap_usage_pct",
            "max_1m_load_average",
            "min_free_disk_gb",
        ],
    )
    def test_individual_minus_infinity_threshold_fails_closed(self, base_valid_thresholds, threshold_key):
        thresholds = dict(base_valid_thresholds)
        thresholds[threshold_key] = float("-inf")
        res = inspect_host_resources(thresholds, collector=MockCollector())

        assert res.passed is False
        assert res.exit_code == ExitCode.FAILED_PREFLIGHT
        assert res.exit_code == 79
        assert "finite" in res.error_message.lower()

    # 5. Mixed finite + non-finite thresholds
    @pytest.mark.parametrize(
        "mixed_thresholds",
        [
            {
                "min_free_ram_mb": 512.0,
                "max_swap_usage_pct": float("nan"),
                "max_1m_load_average": 4.0,
                "min_free_disk_gb": float("inf"),
            },
            {
                "min_free_ram_mb": float("-inf"),
                "max_swap_usage_pct": 50.0,
                "max_1m_load_average": float("nan"),
                "min_free_disk_gb": 10.0,
            },
            {
                "min_free_ram_mb": float("nan"),
                "max_swap_usage_pct": float("inf"),
                "max_1m_load_average": float("-inf"),
                "min_free_disk_gb": float("nan"),
            },
        ],
    )
    def test_mixed_finite_and_non_finite_fails_closed(self, mixed_thresholds):
        res = inspect_host_resources(mixed_thresholds, collector=MockCollector())
        assert res.passed is False
        assert res.exit_code == ExitCode.FAILED_PREFLIGHT
        assert res.exit_code == 79
        assert "finite" in res.error_message.lower()
