"""Tests for sanitized secret scanner."""

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType


def load_secret_scan_module() -> ModuleType:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "scan_secrets.py"
    spec = importlib.util.spec_from_file_location("scan_secrets", script_path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Unable to load secret scan script: {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_scan_tree_reports_sanitized_findings(tmp_path: Path) -> None:
    module = load_secret_scan_module()
    root = tmp_path / "repo"
    root.mkdir()
    cookie_name = "__Secure-next-auth." + "session-token.0"
    (root / "leak.txt").write_text(f"{cookie_name}=not-a-real-cookie-value\n", encoding="utf-8")

    findings = module.scan_tree(root)

    assert len(findings) == 1
    assert findings[0].rule == "next-auth-session-cookie"
    assert findings[0].path == "leak.txt"
    assert not hasattr(findings[0], "value")


def test_scan_tree_ignores_placeholders_and_excluded_dirs(tmp_path: Path) -> None:
    module = load_secret_scan_module()
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".env.example").write_text("API_KEY=placeholder\n", encoding="utf-8")
    (root / ".git").mkdir()
    token_line = "TOKEN=" + "not-a-real-token-value-123456"
    (root / ".git" / "config").write_text(f"{token_line}\n", encoding="utf-8")

    assert module.scan_tree(root) == []


def test_scan_git_history_fails_when_git_fails(tmp_path: Path, monkeypatch) -> None:
    module = load_secret_scan_module()

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(args=[], returncode=128, stdout="", stderr="not a repo")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    try:
        module.scan_git_history(tmp_path)
    except RuntimeError as exc:
        assert "git rev-list failed" in str(exc)
    else:
        raise AssertionError("scan_git_history should fail when git rev-list fails")
