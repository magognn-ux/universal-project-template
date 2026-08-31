# UPAS Immutable Release & Versioning Policy

## 1. Core Principle

All UPAS central releases, reusable workflows, and downstream consumer project tags must strictly adhere to the **Immutable Versioning Standard**.

Once a release tag is published:
* A release tag MUST NEVER be moved (`git tag -f` is strictly forbidden).
* A release tag MUST NEVER be overwritten or deleted.
* Force-pushing tags (`git push --force --tags` or `git push --force`) is prohibited.
* Downstream projects MUST pin reusable workflows to an exact immutable semantic release tag (e.g. `@v1.0.0`, `@v1.0.1`, `@v1.1.0`) or a full commit SHA.
* Floating/mutable major tags (e.g. `@v1`, `@v2`, `@main`, `@master`) MUST NOT be used in production caller workflows.

---

## 2. Semantic Versioning Protocol

Every change to the central UPAS engine requires publishing a new distinct semantic version:

| Change Scope | Version Increment | Example Transition |
| :--- | :--- | :--- |
| **Patch / Bugfix / Hardening** | `PATCH` (`vX.Y.Z+1`) | `v1.0.0` → `v1.0.1` |
| **Backwards-Compatible Feature** | `MINOR` (`vX.Y+1.0`) | `v1.0.1` → `v1.1.0` |
| **Breaking Architectural Change** | `MAJOR` (`vX+1.0.0`) | `v1.1.0` → `v2.0.0` |

---

## 3. Downstream Caller Pinning

Downstream caller projects (such as `support-bot`, `tour-monitor`) must reference the reusable workflow using the exact immutable release tag:

```yaml
jobs:
  upas-ci:
    name: UPAS Automation Engine
    # Pin strictly to an immutable semantic release version
    uses: magognn-ux/universal-project-template/.github/workflows/upas-pipeline.yml@v1.0.1
    with:
      python-version: "3.11"
      adapter-path: "upas.adapter.json"
      target-environment: "production"
    secrets: inherit
```

---

## 4. Tag Protection Governance

1. Repositories hosting UPAS workflows must enforce **GitHub Tag Protection Rules** on pattern `v*` to prevent deletion or force-pushing.
2. The CI/CD pipeline does not accept mutable release references (`:latest`, `@main`, `@v1`) for production deployment gates.
