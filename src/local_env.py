"""Local .env file updates for runtime-only credentials."""

from pathlib import Path


def quote_env_value(value: str) -> str:
    """Quote a dotenv value without exposing it through shell syntax."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")
    return f'"{escaped}"'


def set_env_value(path: str | Path, key: str, value: str) -> Path:
    """Set or append one key in a local dotenv file."""
    env_path = Path(path)
    env_path.parent.mkdir(parents=True, exist_ok=True)
    line = f"{key}={quote_env_value(value.strip())}\n"

    if not env_path.exists():
        env_path.write_text(line, encoding="utf-8")
        return env_path

    lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
    replaced = False
    output: list[str] = []
    for existing in lines:
        if existing.startswith(f"{key}="):
            output.append(line)
            replaced = True
        else:
            output.append(existing)

    if not replaced:
        if output and not output[-1].endswith("\n"):
            output[-1] += "\n"
        output.append(line)

    env_path.write_text("".join(output), encoding="utf-8")
    return env_path
