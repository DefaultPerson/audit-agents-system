"""Tests for local dotenv updates."""

from pathlib import Path

from src.local_env import quote_env_value, set_env_value


def test_quote_env_value_removes_newlines_and_escapes_quotes() -> None:
    quoted = quote_env_value('a"b\nc')

    assert quoted == '"a\\"bc"'


def test_set_env_value_appends_and_replaces(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("ETH_RPC_URL=https://example.invalid\nDEDAUB_COOKIES=old\n", encoding="utf-8")

    set_env_value(env_path, "DEDAUB_COOKIES", "new cookie; with spaces")

    text = env_path.read_text(encoding="utf-8")
    assert "ETH_RPC_URL=https://example.invalid" in text
    assert 'DEDAUB_COOKIES="new cookie; with spaces"' in text
    assert "DEDAUB_COOKIES=old" not in text


def test_set_env_value_creates_file(tmp_path: Path) -> None:
    env_path = tmp_path / "nested" / ".env"

    result = set_env_value(env_path, "DEDAUB_COOKIES", "cookie")

    assert result == env_path
    assert env_path.read_text(encoding="utf-8") == 'DEDAUB_COOKIES="cookie"\n'
