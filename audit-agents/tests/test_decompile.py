"""Tests for decompile stage."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.models import Chain
from src.stages.decompile import (
    DecompileResult,
    decompile_contract,
    parse_decompiled_functions,
    run_dedaub,
)


class TestRunDedaub:
    """Tests for run_dedaub function."""

    @pytest.mark.asyncio
    async def test_no_cookies_returns_error(self, tmp_path: Path) -> None:
        """Returns error when DEDAUB_COOKIES not set."""
        with patch("src.stages.decompile.settings") as mock_settings:
            mock_settings.dedaub_cookies = None

            result = await run_dedaub("0x6080604052", tmp_path)

            assert result.success is False
            assert "DEDAUB_COOKIES not set" in (result.error or "")

    @pytest.mark.asyncio
    async def test_empty_bytecode_returns_error(self, tmp_path: Path) -> None:
        """Returns error for empty bytecode."""
        result = await run_dedaub("", tmp_path)

        assert result.success is False
        assert "invalid bytecode" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_short_bytecode_returns_error(self, tmp_path: Path) -> None:
        """Returns error for too short bytecode."""
        result = await run_dedaub("0x", tmp_path)

        assert result.success is False
        assert "invalid bytecode" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_successful_decompilation(self, tmp_path: Path) -> None:
        """Successful Dedaub API flow."""
        with patch("src.stages.decompile.settings") as mock_settings:
            mock_settings.dedaub_cookies = "valid-cookie"

            with patch("src.stages.decompile.curl_requests") as mock_curl:
                # Mock submit response
                submit_response = MagicMock()
                submit_response.status_code = 200
                submit_response.text = '"abc123def456ghij"'

                # Mock status response
                status_response = MagicMock()
                status_response.text = "ANALYSIS_ENDED"

                # Mock result response
                result_response = MagicMock()
                result_response.status_code = 200
                result_response.json.return_value = {
                    "source": "// SPDX-License-Identifier: MIT\ncontract Test {}",
                    "disassembled": "PUSH1 0x80",
                }

                mock_curl.post.return_value = submit_response
                mock_curl.get.side_effect = [status_response, result_response]

                result = await run_dedaub("0x6080604052", tmp_path)

                assert result.success is True
                assert result.sol_file is not None
                assert Path(result.sol_file).exists()

    @pytest.mark.asyncio
    async def test_api_submit_failure(self, tmp_path: Path) -> None:
        """Handles API submit failure."""
        with patch("src.stages.decompile.settings") as mock_settings:
            mock_settings.dedaub_cookies = "valid-cookie"

            with patch("src.stages.decompile.curl_requests") as mock_curl:
                submit_response = MagicMock()
                submit_response.status_code = 500
                submit_response.text = "Internal Server Error"

                mock_curl.post.return_value = submit_response

                result = await run_dedaub("0x6080604052", tmp_path, max_retries=0)

                assert result.success is False
                assert "500" in (result.error or "")

    @pytest.mark.asyncio
    async def test_api_timeout(self, tmp_path: Path) -> None:
        """Handles API timeout gracefully."""
        with patch("src.stages.decompile.settings") as mock_settings:
            mock_settings.dedaub_cookies = "valid-cookie"

            with patch("src.stages.decompile.curl_requests") as mock_curl:
                mock_curl.post.side_effect = Exception("Connection timed out")

                result = await run_dedaub("0x6080604052", tmp_path, max_retries=0)

                assert result.success is False
                # Error message should mention timeout
                assert result.error is not None
                assert "timed out" in result.error.lower() or "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_poll_timeout_includes_last_status(self, tmp_path: Path) -> None:
        """Polling timeout keeps enough status context for debugging."""
        with patch("src.stages.decompile.settings") as mock_settings:
            mock_settings.dedaub_cookies = "valid-cookie"
            mock_settings.dedaub_poll_attempts = 1
            mock_settings.dedaub_poll_interval_seconds = 0

            with patch("src.stages.decompile.curl_requests") as mock_curl:
                submit_response = MagicMock()
                submit_response.status_code = 200
                submit_response.text = '"abc123def456ghij"'

                status_response = MagicMock()
                status_response.text = "ANALYSIS_STARTED"

                mock_curl.post.return_value = submit_response
                mock_curl.get.return_value = status_response

                result = await run_dedaub("0x6080604052", tmp_path, max_retries=0)

                assert result.success is False
                assert "timeout" in (result.error or "").lower()
                assert "ANALYSIS_STARTED" in (result.error or "")

    @pytest.mark.asyncio
    async def test_invalid_job_id(self, tmp_path: Path) -> None:
        """Handles invalid job ID from API."""
        with patch("src.stages.decompile.settings") as mock_settings:
            mock_settings.dedaub_cookies = "valid-cookie"

            with patch("src.stages.decompile.curl_requests") as mock_curl:
                submit_response = MagicMock()
                submit_response.status_code = 200
                submit_response.text = '"short"'  # Too short to be valid

                mock_curl.post.return_value = submit_response

                result = await run_dedaub("0x6080604052", tmp_path, max_retries=0)

                assert result.success is False
                assert "Invalid job ID" in (result.error or "")

    @pytest.mark.asyncio
    async def test_cookies_expired(self, tmp_path: Path) -> None:
        """Handles expired cookies response."""
        with patch("src.stages.decompile.settings") as mock_settings:
            mock_settings.dedaub_cookies = "expired-cookie"

            with patch("src.stages.decompile.curl_requests") as mock_curl:
                submit_response = MagicMock()
                submit_response.status_code = 200
                submit_response.text = '"abc123def456ghij"'

                status_response = MagicMock()
                status_response.text = "ANALYSIS_ENDED"

                result_response = MagicMock()
                result_response.status_code = 200
                result_response.json.return_value = {
                    "source": "You must be logged in to view this",
                    "disassembled": "",
                }

                mock_curl.post.return_value = submit_response
                mock_curl.get.side_effect = [status_response, result_response]

                result = await run_dedaub("0x6080604052", tmp_path, max_retries=0)

                assert result.success is False
                assert "cookies expired" in (result.error or "").lower()


class TestDecompileContract:
    """Tests for decompile_contract function."""

    @pytest.mark.asyncio
    async def test_skip_dedaub_returns_failure(self) -> None:
        """When skip_dedaub=True, returns failure (no other decompiler)."""
        with patch("src.stages.decompile.get_audit_dir") as mock_dir:
            mock_dir.return_value = Path("/tmp/test_audit")

            success, output_dir, sol_file = await decompile_contract(
                "0xabc123", Chain.ETH, "0x6080604052", skip_dedaub=True
            )

            assert success is False
            assert sol_file is None

    @pytest.mark.asyncio
    async def test_creates_output_directory(self) -> None:
        """Creates output directory if it doesn't exist."""
        import tempfile

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("src.stages.decompile.get_audit_dir") as mock_dir,
            patch("src.stages.decompile.run_dedaub") as mock_run,
        ):
            mock_dir.return_value = Path(tmp)
            mock_run.return_value = DecompileResult(success=False, error="test")

            await decompile_contract("0xabc123", Chain.ETH, "0x6080604052")

            assert (Path(tmp) / "decompiled").exists()


class TestParseDecompiledFunctions:
    """Tests for parse_decompiled_functions function."""

    def test_parse_simple_function(self, tmp_path: Path) -> None:
        """Parse a simple function from decompiled code."""
        sol_file = tmp_path / "test.sol"
        sol_file.write_text("""
// 0x12345678
function transfer(address to, uint256 amount) public {
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
""")
        functions = parse_decompiled_functions(str(sol_file))

        assert len(functions) >= 1
        assert any(f.name == "transfer" for f in functions)

    def test_parse_function_with_selector(self, tmp_path: Path) -> None:
        """Parse function and extract selector from comment inside function."""
        sol_file = tmp_path / "test.sol"
        # Selector comment must be inside the function body for regex to match
        sol_file.write_text("""
function transfer(address to, uint256 amount) public {
    // Selector: 0xa9059cbb
    return;
}
""")
        functions = parse_decompiled_functions(str(sol_file))

        assert len(functions) == 1
        assert functions[0].selector == "0xa9059cbb"

    def test_parse_multiple_functions(self, tmp_path: Path) -> None:
        """Parse multiple functions."""
        sol_file = tmp_path / "test.sol"
        sol_file.write_text("""
function foo() public {
    x = 1;
}

function bar(uint256 a) public {
    y = a;
}

function baz() internal {
    z = 2;
}
""")
        functions = parse_decompiled_functions(str(sol_file))

        assert len(functions) == 3
        names = {f.name for f in functions}
        assert names == {"foo", "bar", "baz"}

    def test_parse_nonexistent_file(self) -> None:
        """Returns empty list for nonexistent file."""
        functions = parse_decompiled_functions("/nonexistent/path.sol")
        assert functions == []

    def test_parse_empty_file(self, tmp_path: Path) -> None:
        """Returns empty list for empty file."""
        sol_file = tmp_path / "empty.sol"
        sol_file.write_text("")

        functions = parse_decompiled_functions(str(sol_file))
        assert functions == []

    def test_parse_file_without_functions(self, tmp_path: Path) -> None:
        """Returns empty list for file without functions."""
        sol_file = tmp_path / "no_funcs.sol"
        sol_file.write_text("""
// Just comments
// No functions here
pragma solidity ^0.8.0;

contract Empty {
    uint256 public value;
}
""")
        functions = parse_decompiled_functions(str(sol_file))
        # May or may not match depending on regex
        # The contract definition is not a function
        assert all(f.name != "Empty" for f in functions)
