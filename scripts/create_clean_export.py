#!/usr/bin/env python3
"""Create a clean source export without git history or local artifacts."""

from __future__ import annotations

import argparse
import shutil
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
    "research",
    "target",
}

EXCLUDED_SUFFIXES = {
    ".db",
    ".lance",
    ".log",
    ".manifest",
    ".pyc",
    ".sqlite",
    ".sqlite3",
    ".txn",
}

EXCLUDED_NAMES = {
    ".env",
    ".env.local",
    ".mcp.json",
    "pending_poc.json",
}

INCLUDED_ENV_EXAMPLES = {".env.example"}


def should_exclude(path: Path, root: Path) -> bool:
    """Return whether a path must be skipped in the clean export."""
    rel = path.relative_to(root)
    parts = set(rel.parts)

    if parts & EXCLUDED_DIRS:
        return True
    if path.name in EXCLUDED_NAMES:
        return True
    if path.name.startswith(".env.") and path.name not in INCLUDED_ENV_EXAMPLES:
        return True
    return path.suffix in EXCLUDED_SUFFIXES


def create_clean_export(root: Path, output: Path) -> None:
    """Copy a sanitized tree to output."""
    root = root.resolve()
    output = output.resolve()

    if output == root or root in output.parents:
        raise ValueError("Output path must be outside the source repository.")
    if output.exists():
        raise FileExistsError(f"Output already exists: {output}")

    output.mkdir(parents=True)

    for source in root.rglob("*"):
        if should_exclude(source, root):
            if source.is_dir():
                continue
            continue
        if source.is_dir():
            continue

        destination = output / source.relative_to(root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Output directory outside this repo")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root",
    )
    args = parser.parse_args()
    create_clean_export(args.root, args.output)


if __name__ == "__main__":
    main()
