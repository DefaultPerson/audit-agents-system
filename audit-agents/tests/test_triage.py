"""Tests for triage stage."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import Chain, SkipReason
from src.stages.triage import (
    _code_hash,
    check_contract_verified,
    detect_proxy,
    triage_contract,
)


class TestCodeHash:
    """Tests for _code_hash function."""

    def test_deterministic(self):
        """Hash is deterministic."""
        bytecode = bytes.fromhex("6080604052")
        h1 = _code_hash(bytecode)
        h2 = _code_hash(bytecode)
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex

    def test_different_bytecode_different_hash(self):
        """Different bytecode produces different hash."""
        h1 = _code_hash(bytes.fromhex("6080604052"))
        h2 = _code_hash(bytes.fromhex("6080604053"))
        assert h1 != h2


class TestDetectProxy:
    """Tests for detect_proxy function."""

    @pytest.mark.asyncio
    async def test_eip1167_minimal_proxy(self):
        """EIP-1167 clone with embedded impl address."""
        impl = "1234567890abcdef1234567890abcdef12345678"
        # Standard EIP-1167 bytecode
        bytecode = bytes.fromhex(
            f"363d3d373d3d3d363d73{impl}5af43d82803e903d91602b57fd5bf3"
        )

        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."

        is_proxy, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert is_proxy is True
        assert impl_addr == f"0x{impl}"

    @pytest.mark.asyncio
    async def test_eip1967_transparent_proxy(self):
        """EIP-1967 proxy with impl in storage slot."""
        impl_hex = "ab" * 20

        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."
        mock_w3.eth.get_storage_at = AsyncMock(
            return_value=bytes.fromhex("00" * 12 + impl_hex)
        )

        bytecode = bytes.fromhex("6080604052")  # Not EIP-1167
        is_proxy, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert is_proxy is True
        assert impl_addr.lower() == f"0x{impl_hex}".lower()

    @pytest.mark.asyncio
    async def test_not_a_proxy(self):
        """Regular contract, no proxy."""
        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."
        mock_w3.eth.get_storage_at = AsyncMock(return_value=b"\x00" * 32)

        bytecode = bytes.fromhex("6080604052348015")
        is_proxy, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert is_proxy is False
        assert impl_addr is None

    @pytest.mark.asyncio
    async def test_eip1967_beacon_proxy(self):
        """EIP-1967 beacon proxy detection."""
        beacon_hex = "be" * 20

        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."

        # First call (impl slot) returns zero, second call (beacon slot) returns beacon
        mock_w3.eth.get_storage_at = AsyncMock(
            side_effect=[
                b"\x00" * 32,  # EIP1967_IMPL_SLOT
                bytes.fromhex("00" * 12 + beacon_hex),  # EIP1967_BEACON_SLOT
            ]
        )

        bytecode = bytes.fromhex("6080604052")
        is_proxy, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        # Beacon detected but no impl address (we don't call beacon.implementation in triage)
        assert is_proxy is True
        assert impl_addr is None


class TestCheckContractVerified:
    """Tests for check_contract_verified function."""

    @pytest.mark.asyncio
    async def test_no_api_key(self):
        """Returns False when no API key configured."""
        with patch("src.stages.triage.get_chain_config") as mock_config:
            mock_config.return_value.explorer_api_key = None

            is_verified, name = await check_contract_verified("0xabc", Chain.ETH)

            assert is_verified is False
            assert name is None

    @pytest.mark.asyncio
    async def test_verified_contract(self):
        """Returns True for verified contract."""
        with patch("src.stages.triage.get_chain_config") as mock_config:
            mock_config.return_value.explorer_api_key = "test-key"
            mock_config.return_value.explorer_api_url = "https://api.etherscan.io/v2/api"
            mock_config.return_value.chain_id = 1

            with patch("httpx.AsyncClient") as mock_client_class:
                mock_response = MagicMock()
                mock_response.json.return_value = {
                    "status": "1",
                    "result": [
                        {
                            "SourceCode": "pragma solidity ^0.8.0; contract Test {}",
                            "ContractName": "Test",
                        }
                    ],
                }

                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client

                is_verified, name = await check_contract_verified("0xabc", Chain.ETH)

                assert is_verified is True
                assert name == "Test"

    @pytest.mark.asyncio
    async def test_unverified_contract(self):
        """Returns False for unverified contract."""
        with patch("src.stages.triage.get_chain_config") as mock_config:
            mock_config.return_value.explorer_api_key = "test-key"
            mock_config.return_value.explorer_api_url = "https://api.etherscan.io/v2/api"
            mock_config.return_value.chain_id = 1

            with patch("httpx.AsyncClient") as mock_client_class:
                mock_response = MagicMock()
                mock_response.json.return_value = {
                    "status": "1",
                    "result": [{"SourceCode": "", "ContractName": ""}],
                }

                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client

                is_verified, name = await check_contract_verified("0xabc", Chain.ETH)

                assert is_verified is False

    @pytest.mark.asyncio
    async def test_api_timeout(self):
        """Returns False on timeout."""
        import httpx

        with patch("src.stages.triage.get_chain_config") as mock_config:
            mock_config.return_value.explorer_api_key = "test-key"
            mock_config.return_value.explorer_api_url = "https://api.etherscan.io/v2/api"
            mock_config.return_value.chain_id = 1

            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
                mock_client_class.return_value.__aenter__.return_value = mock_client

                is_verified, name = await check_contract_verified("0xabc", Chain.ETH)

                assert is_verified is False
                assert name is None


class TestTriageContract:
    """Tests for triage_contract function."""

    @pytest.mark.asyncio
    async def test_no_bytecode_eoa(self):
        """EOA (no code) should be skipped."""
        with patch("src.stages.triage.get_chain_config") as mock_config:
            mock_config.return_value.rpc_url = "https://eth.drpc.org"

            with patch("src.stages.triage.AsyncWeb3") as mock_w3_class:
                mock_w3 = MagicMock()
                mock_w3.eth.get_code = AsyncMock(return_value=b"")
                mock_w3.to_checksum_address.return_value = "0x..."
                mock_w3_class.return_value = mock_w3

                result = await triage_contract("0xabc123def456789012345678901234567890abcd", Chain.ETH)

                assert result.passed is False
                assert result.skip_reason == SkipReason.NO_CODE

    @pytest.mark.asyncio
    async def test_low_balance_skipped(self):
        """Contract below min balance should be skipped."""
        with patch("src.stages.triage.get_chain_config") as mock_config:
            mock_config.return_value.rpc_url = "https://eth.drpc.org"

            with patch("src.stages.triage.AsyncWeb3") as mock_w3_class:
                mock_w3 = MagicMock()
                mock_w3.eth.get_code = AsyncMock(return_value=bytes.fromhex("6080604052"))
                mock_w3.eth.get_storage_at = AsyncMock(return_value=b"\x00" * 32)
                mock_w3.to_checksum_address.return_value = "0x..."
                mock_w3_class.return_value = mock_w3

                with patch(
                    "src.stages.triage.check_contract_verified",
                    return_value=(False, None),
                ):
                    result = await triage_contract(
                        "0xabc123def456789012345678901234567890abcd",
                        Chain.ETH,
                        balance_usd=1000,
                    )

                    assert result.passed is False
                    assert result.skip_reason == SkipReason.LOW_BALANCE

    @pytest.mark.asyncio
    async def test_verified_non_proxy_skipped(self):
        """Verified non-proxy contract should be skipped."""
        with patch("src.stages.triage.get_chain_config") as mock_config:
            mock_config.return_value.rpc_url = "https://eth.drpc.org"

            with patch("src.stages.triage.AsyncWeb3") as mock_w3_class:
                mock_w3 = MagicMock()
                mock_w3.eth.get_code = AsyncMock(return_value=bytes.fromhex("6080604052"))
                mock_w3.eth.get_storage_at = AsyncMock(return_value=b"\x00" * 32)
                mock_w3.to_checksum_address.return_value = "0x..."
                mock_w3_class.return_value = mock_w3

                with patch(
                    "src.stages.triage.check_contract_verified",
                    return_value=(True, "TokenContract"),
                ):
                    result = await triage_contract(
                        "0xabc123def456789012345678901234567890abcd",
                        Chain.ETH,
                        balance_usd=500000,
                    )

                    assert result.passed is False
                    assert result.skip_reason == SkipReason.VERIFIED

    @pytest.mark.asyncio
    async def test_unverified_contract_passes(self):
        """Unverified contract with sufficient balance should pass."""
        with patch("src.stages.triage.get_chain_config") as mock_config:
            mock_config.return_value.rpc_url = "https://eth.drpc.org"

            with patch("src.stages.triage.AsyncWeb3") as mock_w3_class:
                mock_w3 = MagicMock()
                mock_w3.eth.get_code = AsyncMock(return_value=bytes.fromhex("6080604052"))
                mock_w3.eth.get_storage_at = AsyncMock(return_value=b"\x00" * 32)
                mock_w3.to_checksum_address.return_value = "0x..."
                mock_w3_class.return_value = mock_w3

                with patch(
                    "src.stages.triage.check_contract_verified",
                    return_value=(False, None),
                ):
                    result = await triage_contract(
                        "0xabc123def456789012345678901234567890abcd",
                        Chain.ETH,
                        balance_usd=500000,
                    )

                    assert result.passed is True
                    assert result.skip_reason is None

    @pytest.mark.asyncio
    async def test_proxy_contract_passes_even_if_verified(self):
        """Proxy contract should pass even if verified (impl may not be)."""
        impl = "1234567890abcdef1234567890abcdef12345678"
        proxy_bytecode = bytes.fromhex(
            f"363d3d373d3d3d363d73{impl}5af43d82803e903d91602b57fd5bf3"
        )

        with patch("src.stages.triage.get_chain_config") as mock_config:
            mock_config.return_value.rpc_url = "https://eth.drpc.org"

            with patch("src.stages.triage.AsyncWeb3") as mock_w3_class:
                mock_w3 = MagicMock()
                mock_w3.eth.get_code = AsyncMock(return_value=proxy_bytecode)
                mock_w3.to_checksum_address.return_value = "0x..."
                mock_w3_class.return_value = mock_w3

                with patch(
                    "src.stages.triage.check_contract_verified",
                    return_value=(True, "ProxyContract"),
                ):
                    result = await triage_contract(
                        "0xabc123def456789012345678901234567890abcd",
                        Chain.ETH,
                        balance_usd=500000,
                    )

                    # Proxy passes even if verified
                    assert result.passed is True
                    assert result.is_proxy is True
