"""
Full End-to-End Test for New Project Onboarding Lifecycle.
Verifies: NEW PROJECT -> upas init -> upas.adapter.json -> .github/workflows/upas.yml -> discovery -> adapter validation -> precheck -> READY FOR QA
"""

import json
from pathlib import Path
import tempfile
import pytest

from upas_core.cli.main import main
from upas_core.contracts.enums import ExitCode


def test_new_project_onboarding_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        
        # 1. Simulate new project files
        (p / "requirements.txt").write_text("pytest\n")
        (p / "app").mkdir()
        (p / "app" / "core.py").write_text("def add(a, b): return a + b\n")
        (p / "tests").mkdir()
        (p / "tests" / "test_core.py").write_text("from app.core import add\ndef test_add(): assert add(1, 2) == 3\n")
        
        # 2. Step 1: upas init
        ret_init = main(["init", "--project", tmpdir, "--name", "pilot_project"])
        assert ret_init == ExitCode.SUCCESS.value
        assert (p / "upas.adapter.json").exists()
        assert (p / ".github" / "workflows" / "upas.yml").exists()

        # 3. Step 2: upas discover & adapter validation
        ret_discover = main(["discover", "--project", tmpdir, "--adapter", str(p / "upas.adapter.json")])
        assert ret_discover == ExitCode.SUCCESS.value

        # 4. Step 3: upas precheck with changed file app/core.py -> Targeted Test Resolution
        ret_precheck = main([
            "precheck",
            "--project", tmpdir,
            "--adapter", str(p / "upas.adapter.json"),
            "--files", "app/core.py"
        ])
        assert ret_precheck == ExitCode.SUCCESS.value
