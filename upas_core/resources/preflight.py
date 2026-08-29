"""
UPAS Host Resource Preflight Gate.
Enforces Invariant 10 / Resource Gate: pre-flight headroom validation before any mutation.
Evaluates RAM, Disk, Swap, Load, and container availability (Exit Code 79).
"""

import math
import os
import shutil
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
import psutil

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import PreflightFailedError
from upas_core.contracts.interfaces import ResourcePreflight
from upas_core.contracts.results import PreflightResult


@dataclass(frozen=True)
class SystemMetrics:
    """Snapshot of current host system metrics."""
    ram_free_mb: float
    swap_usage_pct: float
    load_1m: float
    disk_free_gb: float
    running_containers: List[str]


class SystemMetricsCollector:
    """Default OS-level metrics collector using psutil and shutil."""

    def collect(self, disk_path: str = "/") -> SystemMetrics:
        # 1. RAM: available memory in MB
        mem = psutil.virtual_memory()
        ram_free_mb = round(mem.available / (1024 * 1024), 2)

        # 2. Swap: usage percentage (0.0 to 100.0)
        swap = psutil.swap_memory()
        swap_usage_pct = round(swap.percent, 2)

        # 3. Load average (1 minute)
        if hasattr(os, "getloadavg"):
            try:
                load_1m = round(os.getloadavg()[0], 2)
            except Exception:
                load_1m = 0.0
        else:
            # Fallback for Windows: approximate normalized load based on CPU percent
            cpu_pct = psutil.cpu_percent(interval=None)
            cpu_count = psutil.cpu_count() or 1
            load_1m = round((cpu_pct / 100.0) * cpu_count, 2)

        # 4. Disk: free space in GB on target path / root
        target_dir = disk_path if os.path.exists(disk_path) else os.path.abspath(os.sep)
        disk_usage = shutil.disk_usage(target_dir)
        disk_free_gb = round(disk_usage.free / (1024 * 1024 * 1024), 2)

        # 5. Containers (empty list if Docker daemon not queried directly here)
        running_containers: List[str] = []

        return SystemMetrics(
            ram_free_mb=ram_free_mb,
            swap_usage_pct=swap_usage_pct,
            load_1m=load_1m,
            disk_free_gb=disk_free_gb,
            running_containers=running_containers,
        )


class HostResourcePreflight(ResourcePreflight):
    """
    Authoritative Host Resource Preflight Inspector.
    Validates host readiness against adapter resource_gate thresholds.
    """

    def __init__(self, collector: Optional[SystemMetricsCollector] = None):
        self._collector = collector or SystemMetricsCollector()

    def inspect_resources(self, thresholds: Dict[str, Any]) -> PreflightResult:
        """
        Evaluates system metrics against pre_flight_checks thresholds.
        Fails closed on missing or breached thresholds with ExitCode.FAILED_PREFLIGHT (79).
        """
        if not isinstance(thresholds, dict):
            return PreflightResult(
                passed=False,
                ram_free_mb=0.0,
                swap_usage_pct=100.0,
                load_1m=999.0,
                disk_free_gb=0.0,
                error_message="Resource thresholds must be a dictionary",
                exit_code=ExitCode.FAILED_PREFLIGHT,
            )

        # Extract and validate required thresholds
        try:
            min_ram_mb = float(thresholds["min_free_ram_mb"])
            max_swap_pct = float(thresholds["max_swap_usage_pct"])
            max_load_1m = float(thresholds["max_1m_load_average"])
            min_disk_gb = float(thresholds["min_free_disk_gb"])
            req_containers = thresholds.get("required_shared_containers", [])
        except (KeyError, ValueError, TypeError) as exc:
            return PreflightResult(
                passed=False,
                ram_free_mb=0.0,
                swap_usage_pct=100.0,
                load_1m=999.0,
                disk_free_gb=0.0,
                error_message=f"Invalid or missing threshold configuration: {exc}",
                exit_code=ExitCode.FAILED_PREFLIGHT,
            )

        # Guard against non-finite (NaN, Inf, -Inf) or negative / impossible threshold configurations
        numeric_vals = [min_ram_mb, max_swap_pct, max_load_1m, min_disk_gb]
        if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in numeric_vals):
            return PreflightResult(
                passed=False,
                ram_free_mb=0.0,
                swap_usage_pct=100.0,
                load_1m=999.0,
                disk_free_gb=0.0,
                error_message="Resource thresholds must be finite numeric values (NaN and Infinity are forbidden)",
                exit_code=ExitCode.FAILED_PREFLIGHT,
            )

        if min_ram_mb < 0 or max_swap_pct < 0 or max_swap_pct > 100 or max_load_1m < 0 or min_disk_gb < 0:
            return PreflightResult(
                passed=False,
                ram_free_mb=0.0,
                swap_usage_pct=100.0,
                load_1m=999.0,
                disk_free_gb=0.0,
                error_message="Resource thresholds contain invalid or negative bounds",
                exit_code=ExitCode.FAILED_PREFLIGHT,
            )

        # Collect current system metrics
        try:
            metrics = self._collector.collect()
        except Exception as exc:
            return PreflightResult(
                passed=False,
                ram_free_mb=0.0,
                swap_usage_pct=100.0,
                load_1m=999.0,
                disk_free_gb=0.0,
                error_message=f"Failed to collect system metrics: {exc}",
                exit_code=ExitCode.FAILED_PREFLIGHT,
            )

        violations = []

        # 1. RAM check
        if metrics.ram_free_mb < min_ram_mb:
            violations.append(
                f"Free RAM ({metrics.ram_free_mb} MB) is below minimum threshold ({min_ram_mb} MB)"
            )

        # 2. Swap check
        if metrics.swap_usage_pct > max_swap_pct:
            violations.append(
                f"Swap usage ({metrics.swap_usage_pct}%) exceeds maximum threshold ({max_swap_pct}%)"
            )

        # 3. Load average check
        if metrics.load_1m > max_load_1m:
            violations.append(
                f"1m Load average ({metrics.load_1m}) exceeds maximum threshold ({max_load_1m})"
            )

        # 4. Disk check
        if metrics.disk_free_gb < min_disk_gb:
            violations.append(
                f"Free disk space ({metrics.disk_free_gb} GB) is below minimum threshold ({min_disk_gb} GB)"
            )

        # 5. Required shared containers check
        missing_containers = []
        if req_containers:
            for container in req_containers:
                if container not in metrics.running_containers:
                    missing_containers.append(container)
            if missing_containers:
                violations.append(f"Required containers missing or inactive: {', '.join(missing_containers)}")

        if violations:
            error_msg = "Resource pre-flight check failed: " + "; ".join(violations)
            return PreflightResult(
                passed=False,
                ram_free_mb=metrics.ram_free_mb,
                swap_usage_pct=metrics.swap_usage_pct,
                load_1m=metrics.load_1m,
                disk_free_gb=metrics.disk_free_gb,
                missing_containers=missing_containers,
                error_message=error_msg,
                exit_code=ExitCode.FAILED_PREFLIGHT,  # Exit Code 79
            )

        return PreflightResult(
            passed=True,
            ram_free_mb=metrics.ram_free_mb,
            swap_usage_pct=metrics.swap_usage_pct,
            load_1m=metrics.load_1m,
            disk_free_gb=metrics.disk_free_gb,
            missing_containers=[],
            error_message=None,
            exit_code=ExitCode.SUCCESS,
        )


def inspect_host_resources(thresholds: Dict[str, Any], collector: Optional[SystemMetricsCollector] = None) -> PreflightResult:
    """Convenience functional interface for resource pre-flight checks."""
    preflight = HostResourcePreflight(collector=collector)
    return preflight.inspect_resources(thresholds)
