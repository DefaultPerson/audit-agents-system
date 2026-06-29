#!/usr/bin/env python3
"""Scan a source tree for likely secrets without printing secret values."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "audits",
    "cache",
    "data",
    "htmlcov",
    "lib",
    "logs",
    "out",
    "poc",
    "target",
}

SECRET_PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "next-auth-session-cookie": re.compile(r"__Secure-next-auth\.session-token(?:\.\d+)?="),
    "cloudflare-clearance-cookie": re.compile(r"cf_clearance="),
    "dedaub-cookie": re.compile(r"DEDAUB_COOKIES\s*=\s*[\"']?[^\"'\s#]{24,}", re.I),
    "api-secret-assignment": re.compile(
        r"\b[A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*\b"
        r"\s*=\s*[\"']?[^\"'\s#]{24,}",
    ),
    "openai-style-key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
}

GIT_HISTORY_PATTERN = (
    "PRIVATE KEY|session-token|cf_clearance|DEDAUB_COOKIES|"
    "API[_-]?KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY|sk-[A-Za-z0-9_-]{20,}"
)
PLACEHOLDER_RE = re.compile(
    r"(placeholder|example|your_|change-?me|dummy|test|xxxxx|\.\.\.)",
    re.I,
)


@dataclass(frozen=True)
class SecretFinding:
    """Sanitized secret finding."""

    rule: str
    path: str
    line: int


def _is_excluded(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if rel == Path("scripts/scan_secrets.py"):
        return True
    return bool(set(rel.parts) & EXCLUDED_DIRS)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def scan_text(text: str, path: str) -> list[SecretFinding]:
    """Scan text and return sanitized findings."""
    findings: list[SecretFinding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if PLACEHOLDER_RE.search(line):
            continue
        for rule, pattern in SECRET_PATTERNS.items():
            if pattern.search(line):
                findings.append(SecretFinding(rule=rule, path=path, line=line_number))
    return findings


def scan_tree(root: Path) -> list[SecretFinding]:
    """Scan a source tree for likely secrets."""
    root = root.resolve()
    findings: list[SecretFinding] = []
    for path in root.rglob("*"):
        if _is_excluded(path, root) or path.is_dir():
            continue
        text = _read_text(path)
        if text is None:
            continue
        findings.extend(scan_text(text, str(path.relative_to(root))))
    return findings


def scan_git_history(root: Path) -> list[SecretFinding]:
    """Scan reachable git history for likely secret patterns."""
    root = root.resolve()
    revs = subprocess.run(
        ["git", "rev-list", "--all"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    if revs.returncode != 0:
        raise RuntimeError(f"git rev-list failed: {revs.stderr.strip() or revs.stdout.strip()}")

    findings: list[SecretFinding] = []
    for commit in revs.stdout.splitlines():
        grep = subprocess.run(
            ["git", "grep", "-n", "-I", "-E", GIT_HISTORY_PATTERN, commit, "--", "."],
            cwd=root,
            capture_output=True,
            check=False,
            text=True,
        )
        if grep.returncode not in (0, 1):
            raise RuntimeError(
                f"git grep failed for {commit[:12]}: {grep.stderr.strip() or grep.stdout.strip()}"
            )
        for line in grep.stdout.splitlines():
            _commit, file_path, line_number, raw = line.split(":", 3)
            if PLACEHOLDER_RE.search(raw):
                continue
            findings.append(
                SecretFinding(
                    rule="git-history-secret-pattern",
                    path=file_path,
                    line=int(line_number),
                )
            )
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Tree to scan")
    parser.add_argument("--history", action="store_true", help="Also scan reachable git history")
    args = parser.parse_args()

    findings = scan_tree(args.root)
    if args.history:
        try:
            findings.extend(scan_git_history(args.root))
        except RuntimeError as exc:
            print(f"secret-scan-error: {exc}", file=sys.stderr)
            raise SystemExit(2) from None

    for finding in findings:
        print(f"{finding.rule}: {finding.path}:{finding.line}")
    raise SystemExit(1 if findings else 0)


if __name__ == "__main__":
    main()
