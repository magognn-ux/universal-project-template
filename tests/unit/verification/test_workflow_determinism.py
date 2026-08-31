"""
Unit tests for UPAS GitHub Actions Reusable Workflow determinism.
"""
from pathlib import Path

def test_reusable_workflow_engine_checkout_pinned():
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    workflow_file = repo_root / ".github" / "workflows" / "upas-pipeline.yml"
    assert workflow_file.exists()
    content = workflow_file.read_text(encoding="utf-8")
    lines = content.splitlines()
    target_ref = "ref: " + "${{ github.workflow_sha }}"
    for i, line in enumerate(lines):
        if "repository: magognn-ux/universal-project-template" in line:
            surrounding = "\n".join(lines[max(0, i - 2):min(len(lines), i + 4)])
            assert target_ref in surrounding
    assert content.count(target_ref) == 3

