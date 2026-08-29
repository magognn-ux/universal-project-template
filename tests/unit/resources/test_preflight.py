"""
Targeted tests for UPAS Resource Preflight Gate (Phase 2C-1.3).
Verifies headroom validation for RAM, Swap, Load, Disk, missing container handling,
fail-closed on invalid config, and Exit Code 79.
"""

import pytest
from upas_core.contracts.enums import ExitCode
from upas_core.resources import (
    HostResourcePreflight,
    SystemMetrics,
    SystemMetricsCollector,
    inspect_host_resources,
)


class MockMetricsCollector(SystemMetricsCollector):
    def __init__(self, metrics: SystemMetrics):
        self.metrics = metrics

    def collect(self, disk_path: str = "/") -> SystemMetrics:
        return self.metrics


class TestHostResourcePreflight:
    @pytest.fixture
    def default_thresholds(self):
        return {
            "min_free_ram_mb": 512,
            "max_swap_usage_pct": 50.0,
            "max_1m_load_average": 4.0,
            "min_free_disk_gb": 10.0,
            "required_shared_containers": ["shared-postgres"],
        }

    def test_all_thresholds_satisfied_passes(self, default_thresholds):
        mock_metrics = SystemMetrics(
            ram_free_mb=2048.0,
            swap_usage_pct=10.0,
            load_1m=1.2,
            disk_free_gb=50.0,
            running_containers=["shared-postgres", "shared-redis"],
        )
        preflight = HostResourcePreflight(collector=MockMetricsCollector(mock_metrics))
        res = preflight.inspect_resources(default_thresholds)

        assert res.passed is True
        assert res.exit_code == ExitCode.SUCCESS
        assert res.error_message is None
        assert len(res.missing_containers) == 0

    def test_low_ram_fails_closed_exit_79(self, default_thresholds):
        mock_metrics = SystemMetrics(
            ram_free_mb=256.0,  # Below 512
            swap_usage_pct=10.0,
            load_1m=1.2,
            disk_free_gb=50.0,
            running_containers=["shared-postgres"],
        )
        preflight = HostResourcePreflight(collector=MockMetricsCollector(mock_metrics))
        res = preflight.inspect_resources(default_thresholds)

        assert res.passed is False
        assert res.exit_code == ExitCode.FAILED_PREFLIGHT
        assert res.exit_code == 79
        assert "RAM" in res.error_message

    def test_excessive_swap_fails_closed(self, default_thresholds):
        mock_metrics = SystemMetrics(
            ram_free_mb=1024.0,
            swap_usage_pct=85.0,  # Above 50%
            load_1m=1.2,
            disk_free_gb=50.0,
            running_containers=["shared-postgres"],
        )
        preflight = HostResourcePreflight(collector=MockMetricsCollector(mock_metrics))
        res = preflight.inspect_resources(default_thresholds)

        assert res.passed is False
        assert res.exit_code == 79
        assert "Swap" in res.error_message

    def test_high_load_average_fails_closed(self, default_thresholds):
        mock_metrics = SystemMetrics(
            ram_free_mb=1024.0,
            swap_usage_pct=10.0,
            load_1m=8.5,  # Above 4.0
            disk_free_gb=50.0,
            running_containers=["shared-postgres"],
        )
        preflight = HostResourcePreflight(collector=MockMetricsCollector(mock_metrics))
        res = preflight.inspect_resources(default_thresholds)

        assert res.passed is False
        assert res.exit_code == 79
        assert "Load" in res.error_message

    def test_low_disk_space_fails_closed(self, default_thresholds):
        mock_metrics = SystemMetrics(
            ram_free_mb=1024.0,
            swap_usage_pct=10.0,
            load_1m=1.0,
            disk_free_gb=2.0,  # Below 10 GB
            running_containers=["shared-postgres"],
        )
        preflight = HostResourcePreflight(collector=MockMetricsCollector(mock_metrics))
        res = preflight.inspect_resources(default_thresholds)

        assert res.passed is False
        assert res.exit_code == 79
        assert "disk" in res.error_message.lower()

    def test_missing_required_container_fails_closed(self, default_thresholds):
        mock_metrics = SystemMetrics(
            ram_free_mb=1024.0,
            swap_usage_pct=10.0,
            load_1m=1.0,
            disk_free_gb=50.0,
            running_containers=["unrelated-container"],  # Missing shared-postgres
        )
        preflight = HostResourcePreflight(collector=MockMetricsCollector(mock_metrics))
        res = preflight.inspect_resources(default_thresholds)

        assert res.passed is False
        assert res.exit_code == 79
        assert "shared-postgres" in res.missing_containers
        assert "missing or inactive" in res.error_message

    def test_missing_threshold_field_fails_closed(self):
        incomplete_thresholds = {
            "min_free_ram_mb": 512,
            # missing disk, swap, load
        }
        res = inspect_host_resources(incomplete_thresholds)
        assert res.passed is False
        assert res.exit_code == 79

    def test_negative_or_impossible_threshold_bounds_fail_closed(self):
        invalid_bounds = {
            "min_free_ram_mb": -100,  # Invalid negative
            "max_swap_usage_pct": 150.0,  # > 100%
            "max_1m_load_average": 2.0,
            "min_free_disk_gb": 10.0,
        }
        res = inspect_host_resources(invalid_bounds)
        assert res.passed is False
        assert res.exit_code == 79

    def test_real_system_collector_runs_safely(self):
        collector = SystemMetricsCollector()
        metrics = collector.collect()
        assert metrics.ram_free_mb >= 0
        assert 0.0 <= metrics.swap_usage_pct <= 100.0
        assert metrics.load_1m >= 0.0
        assert metrics.disk_free_gb >= 0.0
