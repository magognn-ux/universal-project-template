"""
Unit tests for UPAS CLI Argument Parser.
"""

import pytest
from upas_core.cli.parser import parse_cli_args


def test_parser_deploy_defaults():
    args = parse_cli_args(["deploy", "--digest", "sha256:" + "a" * 64])
    assert args.command == "deploy"
    assert args.adapter_path == "upas.adapter.json"
    assert args.digest == "sha256:" + "a" * 64
    assert args.branch == "main"
    assert args.expected_environment == "production"


def test_parser_deploy_custom_flags():
    args = parse_cli_args([
        "deploy",
        "--adapter", "custom.adapter.json",
        "--canonical-reference", "reg.internal/app@sha256:" + "0" * 64,
        "--digest", "sha256:" + "0" * 64,
        "--commit-sha", "1" * 40,
        "--branch", "release-2.0",
        "--oidc-token", "token-xyz",
        "--expected-repository", "org/repo",
        "--expected-environment", "staging",
        "--output-evidence", "evidence.json",
        "--output-manifest", "manifest.json",
    ])
    assert args.command == "deploy"
    assert args.adapter_path == "custom.adapter.json"
    assert args.digest == "sha256:" + "0" * 64
    assert args.commit_sha == "1" * 40
    assert args.branch == "release-2.0"
    assert args.oidc_token == "token-xyz"
    assert args.expected_repository == "org/repo"
    assert args.expected_environment == "staging"
    assert args.evidence_output_path == "evidence.json"
    assert args.manifest_output_path == "manifest.json"


def test_parser_audit():
    args = parse_cli_args([
        "audit",
        "--evidence", "out.evidence.json",
        "--manifest", "out.manifest.json",
    ])
    assert args.command == "audit"
    assert args.evidence_path == "out.evidence.json"
    assert args.manifest_path == "out.manifest.json"


def test_parser_preflight():
    args = parse_cli_args(["preflight", "--adapter", "my_adapter.json"])
    assert args.command == "preflight"
    assert args.adapter_path == "my_adapter.json"


def test_parser_lock():
    args = parse_cli_args(["lock", "--path", "/tmp/upas.lock", "--check"])
    assert args.command == "lock"
    assert args.lock_path == "/tmp/upas.lock"
    assert args.check_only is True
