"""Tests for clean export script."""

import importlib.util
from pathlib import Path
from types import ModuleType


def load_clean_export_module() -> ModuleType:
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "create_clean_export.py"
    spec = importlib.util.spec_from_file_location("create_clean_export", script_path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Unable to load clean export script: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_create_clean_export_excludes_local_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("secret history", encoding="utf-8")
    (root / ".env").write_text("TOKEN=secret", encoding="utf-8")
    (root / ".env.example").write_text("TOKEN=placeholder", encoding="utf-8")
    (root / "audit-agents" / "data").mkdir(parents=True)
    (root / "audit-agents" / "data" / "targets.db").write_text("db", encoding="utf-8")
    (root / "audit-agents" / "poc").mkdir(parents=True)
    (root / "audit-agents" / "poc" / "local.t.sol").write_text("poc", encoding="utf-8")
    (root / "audit-agents" / "src").mkdir(parents=True)
    (root / "audit-agents" / "src" / "main.py").write_text("print('ok')", encoding="utf-8")

    output = tmp_path / "export"
    load_clean_export_module().create_clean_export(root, output)

    assert not (output / ".git").exists()
    assert not (output / ".env").exists()
    assert not (output / "audit-agents" / "data").exists()
    assert not (output / "audit-agents" / "poc").exists()
    assert (output / ".env.example").exists()
    assert (output / "audit-agents" / "src" / "main.py").exists()
