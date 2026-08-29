# UPAS Phase 2C-1 — Foundation Runtime Primitives Traceability Matrix

This document establishes formal architectural traceability between the frozen UPAS contracts, the Phase 2C-1 runtime implementations, failure modes, exit codes, and automated validation tests.

---

## 1. Traceability Mapping Matrix

| Phase 2B Contract | Runtime Component | Implementation Class | Failure State | Exit Code | Targeted Tests (Automated) | Architecture Invariant |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| `CompatibilityChecker` (`interfaces.py`), `CompatibilityResult` (`results.py`) | `upas_core/compatibility/checker.py` | `SemVerCompatibilityChecker` | `INCOMPATIBLE_VERSION_ERROR` | **126** | `test_compatible_versions_pass`, `test_incompatible_versions_fail_closed_with_exit_126`, `test_malformed_core_version_fails_closed`, `test_malformed_constraint_fails_closed`, `test_verify_compatibility_raises_exception_on_incompatible` | **Invariant 8: Version Fail-Closed Gate** (pre-mutation validation) |
| `CommandRunner` (`interfaces.py`), `CommandSpec`, `ExecutionResult` (`execution.py`) | `upas_core/execution/runner.py` | `SafeCommandRunner` | `EXECUTION_TIMEOUT` / `COMMAND_FAILED` | **124** / non-zero | `test_successful_command_execution`, `test_command_failure_preserves_exit_code_and_stderr`, `test_timeout_triggers_exit_124_and_kills_process`, `test_timeout_terminates_child_process_tree`, `test_shell_injection_is_prevented`, `test_nonexistent_executable_fails_closed` | **Invariant 9: Safe Subprocess Execution** (process-tree cleanup, no `shell=True`) |
| `ResourcePreflight` (`interfaces.py`), `PreflightResult` (`results.py`) | `upas_core/resources/preflight.py` | `HostResourcePreflight`, `SystemMetricsCollector` | `FAILED_PREFLIGHT` | **79** | `test_all_thresholds_satisfied_passes`, `test_low_ram_fails_closed_exit_79`, `test_excessive_swap_fails_closed`, `test_high_load_average_fails_closed`, `test_low_disk_space_fails_closed`, `test_missing_required_container_fails_closed`, `test_missing_threshold_field_fails_closed`, `test_negative_or_impossible_threshold_bounds_fail_closed`, `test_real_system_collector_runs_safely` | **Invariant 10 / Resource Gate** (host pre-flight headroom verification) |

---

## 2. Component Implementation Details

### 2.1 Version Compatibility Gate (`upas_core.compatibility`)
* **File:** [`upas_core/compatibility/checker.py`](file:///c:/Users/user/Projects/universal-project-template/upas_core/compatibility/checker.py)
* **SemVer Engine:** Parses strict SemVer and normalizes expressions (exact `1.0.0`, ranges `>=1.0.0,<2.0.0`, carets `^1.0.0`, tildes `~1.2.0`, wildcards `*`).
* **Fail-Closed Guarantee:** Unparseable core version, malformed constraint string, or version mismatch immediately yields `compatible=False` and exit code `126`.
* **Execution Boundary:** Enforced prior to any filesystem or deployment mutation.

### 2.2 Safe Subprocess Runner (`upas_core.execution`)
* **File:** [`upas_core/execution/runner.py`](file:///c:/Users/user/Projects/universal-project-template/upas_core/execution/runner.py)
* **Safety Invariant:** Direct shell execution is strictly blocked (`shell=False` hardcoded); only explicit string argument lists (`list[str]`) are accepted.
* **Process-Tree Cleanup:** Upon timeout expiration, `_kill_process_tree` recursively terminates and kills all child/grandchild processes using `psutil` with OS-specific fallbacks (`taskkill /F /T /PID` on Windows, `os.killpg` on POSIX).
* **Deterministic Outcome:** On timeout, strictly returns `ExecutionStatus.TIMEOUT` with exit code `124` (`ExitCode.EXECUTION_TIMEOUT`), preventing false positives.

### 2.3 Host Resource Preflight (`upas_core.resources`)
* **File:** [`upas_core/resources/preflight.py`](file:///c:/Users/user/Projects/universal-project-template/upas_core/resources/preflight.py)
* **Monitored Dimensions:** Free RAM (MB), Swap usage (%), 1-minute load average, Free disk headroom (GB), and required shared container availability.
* **Fail-Closed Threshold Evaluation:** Missing metric fields, negative bounds, non-finite values (IEEE 754 `NaN`, `+Infinity`, `-Infinity`), or breached thresholds return `passed=False` with exit code `79` (`ExitCode.FAILED_PREFLIGHT`).

---

## 3. Test Verification Summary

* **Phase 1 Schema Tests:** 31 passed
* **Phase 2B Contract Tests:** 27 passed
* **Phase 2C-1 Targeted & Adversarial Tests:** 60 passed
  * Compatibility: 28 passed
  * Subprocess Runner: 7 passed
  * Resource Preflight: 25 passed (9 functional + 16 adversarial NaN/Infinity/mixed boundary tests)
* **Total Suite Count:** **118 passed, 0 failed, 0 skipped (100% PASS)**
