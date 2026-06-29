"""Tests for resolve stage."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import Chain, ProxyType
from src.stages.resolve import (
    _extract_address_from_slot,
    _extract_eip1167_impl,
    detect_proxy,
    extract_selectors,
    resolve_contract,
)


class TestExtractAddressFromSlot:
    """Tests for _extract_address_from_slot function."""

    def test_32_byte_slot(self):
        """Standard 32-byte storage slot."""
        slot = bytes.fromhex("00" * 12 + "ab" * 20)
        addr = _extract_address_from_slot(slot)
        assert addr == "0x" + "ab" * 20

    def test_20_byte_return(self):
        """20-byte direct return (e.g., from beacon.implementation())."""
        slot = bytes.fromhex("cd" * 20)
        addr = _extract_address_from_slot(slot)
        assert addr == "0x" + "cd" * 20

    def test_zero_address(self):
        """Zero address returns None."""
        slot = bytes.fromhex("00" * 32)
        addr = _extract_address_from_slot(slot)
        assert addr is None

    def test_zero_address_20_bytes(self):
        """20-byte zero address returns None."""
        slot = bytes.fromhex("00" * 20)
        addr = _extract_address_from_slot(slot)
        assert addr is None

    def test_short_slot(self):
        """Short slot (< 20 bytes) returns None."""
        slot = bytes.fromhex("1234")
        addr = _extract_address_from_slot(slot)
        assert addr is None

    def test_empty_slot(self):
        """Empty slot returns None."""
        addr = _extract_address_from_slot(b"")
        assert addr is None

    def test_none_slot(self):
        """None slot returns None."""
        addr = _extract_address_from_slot(None)
        assert addr is None


class TestExtractEip1167Impl:
    """Tests for _extract_eip1167_impl function."""

    def test_standard_pattern(self):
        """Standard EIP-1167 minimal proxy."""
        impl = "1234567890abcdef1234567890abcdef12345678"
        bytecode = bytes.fromhex(
            f"363d3d373d3d3d363d73{impl}5af43d82803e903d91602b57fd5bf3"
        )
        result = _extract_eip1167_impl(bytecode)
        assert result == f"0x{impl}"

    def test_pattern_in_middle(self):
        """EIP-1167 pattern embedded in larger bytecode."""
        impl = "abcdef1234567890abcdef1234567890abcdef12"
        prefix = "6080604052"
        bytecode = bytes.fromhex(
            f"{prefix}363d3d373d3d3d363d73{impl}5af43d82803e903d91602b57fd5bf3"
        )
        result = _extract_eip1167_impl(bytecode)
        assert result == f"0x{impl}"

    def test_not_eip1167(self):
        """Regular contract bytecode."""
        bytecode = bytes.fromhex("6080604052348015")
        result = _extract_eip1167_impl(bytecode)
        assert result is None

    def test_empty_bytecode(self):
        """Empty bytecode returns None."""
        result = _extract_eip1167_impl(b"")
        assert result is None


class TestDetectProxy:
    """Tests for detect_proxy function."""

    @pytest.mark.asyncio
    async def test_eip1167_minimal_proxy(self):
        """EIP-1167 minimal proxy detection."""
        impl = "ab" * 20
        bytecode = bytes.fromhex(
            f"363d3d373d3d3d363d73{impl}5af43d82803e903d91602b57fd5bf3"
        )

        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."

        proxy_type, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert proxy_type == ProxyType.EIP1167
        assert impl_addr == f"0x{impl}"

    @pytest.mark.asyncio
    async def test_eip1967_impl_slot(self):
        """EIP-1967 transparent proxy detection via impl slot."""
        impl_hex = "cd" * 20

        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."
        mock_w3.eth.get_storage_at = AsyncMock(
            return_value=bytes.fromhex("00" * 12 + impl_hex)
        )

        bytecode = bytes.fromhex("6080604052")
        proxy_type, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert proxy_type == ProxyType.EIP1967
        assert impl_addr == "0x" + impl_hex

    @pytest.mark.asyncio
    async def test_eip1967_beacon_proxy(self):
        """EIP-1967 beacon proxy detection."""
        beacon_hex = "be" * 20
        impl_hex = "cd" * 20

        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."

        # Impl slot empty, beacon slot has address
        mock_w3.eth.get_storage_at = AsyncMock(
            side_effect=[
                b"\x00" * 32,  # EIP1967_IMPL_SLOT
                bytes.fromhex("00" * 12 + beacon_hex),  # EIP1967_BEACON_SLOT
            ]
        )
        # beacon.implementation() call returns impl
        mock_w3.eth.call = AsyncMock(
            return_value=bytes.fromhex("00" * 12 + impl_hex)
        )

        bytecode = bytes.fromhex("6080604052")
        proxy_type, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert proxy_type == ProxyType.EIP1967
        assert impl_addr == "0x" + impl_hex

    @pytest.mark.asyncio
    async def test_eip1822_uups_proxy(self):
        """EIP-1822 (UUPS) proxy detection."""
        impl_hex = "ef" * 20

        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."

        # Impl slot empty, beacon slot empty, UUPS slot has address
        mock_w3.eth.get_storage_at = AsyncMock(
            side_effect=[
                b"\x00" * 32,  # EIP1967_IMPL_SLOT
                b"\x00" * 32,  # EIP1967_BEACON_SLOT
                bytes.fromhex("00" * 12 + impl_hex),  # EIP1822_IMPL_SLOT
            ]
        )

        bytecode = bytes.fromhex("6080604052")
        proxy_type, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert proxy_type == ProxyType.EIP1967  # UUPS reports as EIP1967
        assert impl_addr == "0x" + impl_hex

    @pytest.mark.asyncio
    async def test_diamond_proxy(self):
        """Diamond (EIP-2535) proxy detection."""
        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."

        # All slots empty except diamond storage
        mock_w3.eth.get_storage_at = AsyncMock(
            side_effect=[
                b"\x00" * 32,  # EIP1967_IMPL_SLOT
                b"\x00" * 32,  # EIP1967_BEACON_SLOT
                b"\x00" * 32,  # EIP1822_IMPL_SLOT
                bytes.fromhex("ab" * 32),  # DIAMOND_STORAGE_SLOT (non-zero)
            ]
        )

        bytecode = bytes.fromhex("6080604052")
        proxy_type, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert proxy_type == ProxyType.DIAMOND
        assert impl_addr is None  # Diamond doesn't have single impl

    @pytest.mark.asyncio
    async def test_gnosis_safe_proxy(self):
        """Gnosis Safe proxy detection."""
        singleton_hex = "aa" * 20

        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."

        # All slots empty except singleton (slot 0)
        mock_w3.eth.get_storage_at = AsyncMock(
            side_effect=[
                b"\x00" * 32,  # EIP1967_IMPL_SLOT
                b"\x00" * 32,  # EIP1967_BEACON_SLOT
                b"\x00" * 32,  # EIP1822_IMPL_SLOT
                b"\x00" * 32,  # DIAMOND_STORAGE_SLOT
                bytes.fromhex("00" * 12 + singleton_hex),  # GNOSIS_SINGLETON_SLOT
            ]
        )
        mock_w3.eth.call = AsyncMock(side_effect=Exception("revert"))

        # Bytecode contains execTransaction selector (6a761202)
        bytecode = bytes.fromhex("60806040526a761202")
        proxy_type, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert proxy_type == ProxyType.GNOSIS_SAFE
        assert impl_addr == "0x" + singleton_hex

    @pytest.mark.asyncio
    async def test_custom_proxy_via_implementation_call(self):
        """Custom proxy detected via implementation() call."""
        impl_hex = "ff" * 20

        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."

        # All storage slots empty
        mock_w3.eth.get_storage_at = AsyncMock(return_value=b"\x00" * 32)
        # But implementation() call succeeds
        mock_w3.eth.call = AsyncMock(
            return_value=bytes.fromhex("00" * 12 + impl_hex)
        )

        bytecode = bytes.fromhex("6080604052348015")
        proxy_type, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert proxy_type == ProxyType.CUSTOM
        assert impl_addr == "0x" + impl_hex

    @pytest.mark.asyncio
    async def test_no_proxy(self):
        """Non-proxy contract."""
        mock_w3 = MagicMock()
        mock_w3.to_checksum_address.return_value = "0x..."
        mock_w3.eth.get_storage_at = AsyncMock(return_value=b"\x00" * 32)
        mock_w3.eth.call = AsyncMock(side_effect=Exception("revert"))

        bytecode = bytes.fromhex("6080604052348015600f57")
        proxy_type, impl_addr = await detect_proxy(mock_w3, "0xabc", bytecode)

        assert proxy_type == ProxyType.NONE
        assert impl_addr is None


class TestExtractSelectors:
    """Tests for extract_selectors function."""

    def test_empty_bytecode(self):
        """Empty bytecode returns empty list."""
        selectors = extract_selectors(b"")
        assert selectors == []

    def test_none_bytecode(self):
        """None bytecode returns empty list."""
        selectors = extract_selectors(None)
        assert selectors == []

    def test_minimal_bytecode(self):
        """Minimal bytecode that EVMole can parse."""
        # Simple PUSH1 STOP
        bytecode = bytes.fromhex("6000")
        selectors = extract_selectors(bytecode)
        assert isinstance(selectors, list)

    def test_returns_list_of_hex_strings(self):
        """Selectors are returned as 0x-prefixed hex strings."""
        # Real contract bytecode with known selectors
        # This is a minimal ERC20 stub
        bytecode = bytes.fromhex(
            "608060405234801561001057600080fd5b506004361061003f576000357c0100000000000000000000"
        )
        selectors = extract_selectors(bytecode)
        assert isinstance(selectors, list)
        for sel in selectors:
            assert sel.startswith("0x")
            assert len(sel) == 10  # 0x + 8 hex chars


class TestResolveContract:
    """Tests for resolve_contract function."""

    @pytest.mark.asyncio
    async def test_resolve_non_proxy(self):
        """Resolve a non-proxy contract."""
        with patch("src.stages.resolve.get_chain_config") as mock_config:
            mock_config.return_value.rpc_url = "https://eth.drpc.org"

            with patch("src.stages.resolve.AsyncWeb3") as mock_w3_class:
                mock_w3 = MagicMock()
                mock_w3.eth.get_code = AsyncMock(return_value=bytes.fromhex("6080604052"))
                mock_w3.eth.get_storage_at = AsyncMock(return_value=b"\x00" * 32)
                mock_w3.eth.call = AsyncMock(side_effect=Exception("revert"))
                mock_w3.to_checksum_address.return_value = "0x..."
                mock_w3_class.return_value = mock_w3

                result = await resolve_contract(
                    "0xabc123def456789012345678901234567890abcd", Chain.ETH
                )

                assert result.is_proxy is False
                assert result.proxy_type is None
                assert result.original_address == "0xabc123def456789012345678901234567890abcd"
                assert result.resolved_address == "0xabc123def456789012345678901234567890abcd"

    @pytest.mark.asyncio
    async def test_resolve_eip1167_proxy(self):
        """Resolve EIP-1167 minimal proxy."""
        impl = "1234567890abcdef1234567890abcdef12345678"
        proxy_bytecode = bytes.fromhex(
            f"363d3d373d3d3d363d73{impl}5af43d82803e903d91602b57fd5bf3"
        )
        impl_bytecode = bytes.fromhex("608060405234801561001057")

        with patch("src.stages.resolve.get_chain_config") as mock_config:
            mock_config.return_value.rpc_url = "https://eth.drpc.org"

            with patch("src.stages.resolve.AsyncWeb3") as mock_w3_class:
                mock_w3 = MagicMock()
                mock_w3.eth.get_code = AsyncMock(
                    side_effect=[proxy_bytecode, impl_bytecode]
                )
                mock_w3.to_checksum_address.return_value = "0x..."
                mock_w3_class.return_value = mock_w3

                result = await resolve_contract(
                    "0xproxy123456789012345678901234567890abcd", Chain.ETH
                )

                assert result.is_proxy is True
                assert result.proxy_type == ProxyType.EIP1167
                assert result.resolved_address == f"0x{impl}"

    @pytest.mark.asyncio
    async def test_resolve_eoa(self):
        """Resolve EOA (no bytecode)."""
        with patch("src.stages.resolve.get_chain_config") as mock_config:
            mock_config.return_value.rpc_url = "https://eth.drpc.org"

            with patch("src.stages.resolve.AsyncWeb3") as mock_w3_class:
                mock_w3 = MagicMock()
                mock_w3.eth.get_code = AsyncMock(return_value=b"")
                mock_w3.to_checksum_address.return_value = "0x..."
                mock_w3_class.return_value = mock_w3

                result = await resolve_contract(
                    "0xeoa0123456789012345678901234567890abcdef", Chain.ETH
                )

                assert result.is_proxy is False
                assert result.proxy_type is None
                assert result.selectors == []

    @pytest.mark.asyncio
    async def test_resolve_eip1967_proxy(self):
        """Resolve EIP-1967 transparent proxy."""
        impl_hex = "ab" * 20
        proxy_bytecode = bytes.fromhex("6080604052")
        impl_bytecode = bytes.fromhex("608060405234801561001057600080fd5b50")

        with patch("src.stages.resolve.get_chain_config") as mock_config:
            mock_config.return_value.rpc_url = "https://eth.drpc.org"

            with patch("src.stages.resolve.AsyncWeb3") as mock_w3_class:
                mock_w3 = MagicMock()
                mock_w3.eth.get_code = AsyncMock(
                    side_effect=[proxy_bytecode, impl_bytecode]
                )
                mock_w3.eth.get_storage_at = AsyncMock(
                    return_value=bytes.fromhex("00" * 12 + impl_hex)
                )
                mock_w3.to_checksum_address.return_value = "0x..."
                mock_w3_class.return_value = mock_w3

                result = await resolve_contract(
                    "0xproxy123456789012345678901234567890abcd", Chain.ETH
                )

                assert result.is_proxy is True
                assert result.proxy_type == ProxyType.EIP1967
                assert result.resolved_address == f"0x{impl_hex}"
