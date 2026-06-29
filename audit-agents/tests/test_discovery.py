"""Tests for the discovery module."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.discovery.light_mode import LightModeScanner, parse_balance
from src.discovery.orchestrator import (
    DiscoveryCriteria,
    DiscoveryOrchestrator,
)
from src.discovery.rust_wrapper import RustExtractor
from src.models import Chain, ContractStatus, ContractTarget

# ============================================
# LightModeScanner Tests
# ============================================


class TestParseBalance:
    """Tests for balance parsing."""

    def test_parse_simple_balance(self):
        """Test parsing simple balance."""
        assert parse_balance("1000") == 1000.0

    def test_parse_balance_with_commas(self):
        """Test parsing balance with commas."""
        assert parse_balance("29,888,000.158986") == 29888000.158986

    def test_parse_balance_with_symbol(self):
        """Test parsing balance with currency symbol."""
        assert parse_balance("29,888,000.158986 BNB") == 29888000.158986

    def test_parse_balance_empty(self):
        """Test parsing empty string."""
        assert parse_balance("") == 0.0

    def test_parse_balance_invalid(self):
        """Test parsing invalid string."""
        assert parse_balance("abc") == 0.0


class TestLightModeScanner:
    """Tests for LightModeScanner."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return LightModeScanner()

    @pytest.mark.asyncio
    async def test_scan_unknown_chain(self, scanner):
        """Test scan with unknown chain returns error."""
        contracts, errors = await scanner.scan(
            chain="unknown",
            native_price=100.0,
        )
        assert len(contracts) == 0
        assert len(errors) == 1
        assert "Unknown chain" in errors[0]

    @pytest.mark.asyncio
    async def test_scan_parses_contracts(self, scanner):
        """Test that scan correctly parses HTML response."""
        # Mock HTML response
        mock_html = """
        <html>
        <body>
        <table>
        <tbody>
        <tr>
            <td>1</td>
            <td>
                <a href="/address/0x1234567890123456789012345678901234567890">
                    Contract
                </a>
                <i class="fa-file-alt"></i>
            </td>
            <td>Test Contract</td>
            <td>
                <span data-bs-toggle="tooltip" title="1,000.0 ETH">1,000 ETH</span>
            </td>
            <td>100</td>
        </tr>
        </tbody>
        </table>
        </body>
        </html>
        """

        mock_response = MagicMock()
        mock_response.text = mock_html
        mock_response.raise_for_status = MagicMock()

        with patch.object(scanner, "_get_client") as mock_client:
            mock_async_client = AsyncMock()
            mock_async_client.get.return_value = mock_response
            mock_client.return_value = mock_async_client

            contracts, errors = await scanner.scan(
                chain="eth",
                native_price=3500.0,
                min_balance_usd=100_000,
                limit=100,
            )

        # Should find 1 contract with balance 1000 ETH * $3500 = $3.5M
        assert len(contracts) == 1
        assert contracts[0].address == "0x1234567890123456789012345678901234567890"
        assert contracts[0].balance_usd == 3_500_000.0


# ============================================
# RustExtractor Tests
# ============================================


class TestRustExtractor:
    """Tests for RustExtractor."""

    @pytest.fixture
    def extractor(self, tmp_path):
        """Create extractor with test path."""
        return RustExtractor(binary_path=tmp_path / "nonexistent")

    def test_is_available_false(self, extractor):
        """Test is_available returns False when binary missing."""
        assert not extractor.is_available()

    def test_build_command_includes_snapshot_block(self, extractor):
        """Test extractor command pins snapshot block when provided."""
        command = extractor._build_command(
            chain="bsc",
            rpc="http://localhost:8545",
            min_balance_usd=250_000,
            output_path="/tmp/targets.db",
            snapshot_block=123456,
        )

        assert "--block" in command
        assert command[command.index("--block") + 1] == "123456"
        assert command[command.index("--min-balance") + 1] == "250000"

    @pytest.mark.asyncio
    async def test_extract_no_rpc(self, extractor):
        """Test extract fails without RPC URL or binary."""
        # Mock env to ensure no ERIGON_RPC_URL
        with patch.dict("os.environ", {}, clear=True):
            contracts, errors = await extractor.extract(chain="eth")

        assert len(contracts) == 0
        assert len(errors) == 1
        # Either binary not found or RPC not set
        assert any(x in errors[0] for x in ["ERIGON_RPC_URL", "not available", "build failed"])


# ============================================
# DiscoveryOrchestrator Tests
# ============================================


class TestDiscoveryOrchestrator:
    """Tests for DiscoveryOrchestrator."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database."""
        db = AsyncMock()
        db.upsert_contract = AsyncMock()
        db.add_to_queue = AsyncMock()
        return db

    @pytest.fixture
    def orchestrator(self, mock_db):
        """Create orchestrator with mock db."""
        orch = DiscoveryOrchestrator(db=mock_db)
        return orch

    @pytest.mark.asyncio
    async def test_simulate_adds_test_contracts(self, orchestrator, mock_db):
        """Test simulate adds test contracts to DB and queue."""
        result = await orchestrator.simulate("eth", enqueue=True)

        assert result.contracts_found == 2
        assert result.contracts_added_to_queue == 2
        assert result.total_value_usd > 0

        # Verify DB calls
        assert mock_db.upsert_contract.call_count == 2
        assert mock_db.add_to_queue.call_count == 2

    @pytest.mark.asyncio
    async def test_discover_light_mode(self, orchestrator, mock_db):
        """Test discover in light mode."""
        # Mock scanner
        mock_contract = ContractTarget(
            address="0x1234567890123456789012345678901234567890",
            chain=Chain.ETH,
            balanceUsd=1_000_000,
            balanceNative="1000000000000000000000",
            age=365,
            verified=False,
            status=ContractStatus.NEW,
            foundAt=datetime.now(UTC),
        )

        with patch.object(
            orchestrator._light_scanner,
            "scan",
            return_value=([mock_contract], []),
        ), patch.object(
            orchestrator._price_service,
            "get_native_prices",
            return_value={"eth": 3500.0},
        ):
            result = await orchestrator.discover("eth", mode="light", enqueue=True)

        assert result.contracts_found == 1
        assert result.contracts_added_to_queue == 1
        assert result.mode == "light"

        # Verify both upsert and queue calls
        mock_db.upsert_contract.assert_called_once()
        mock_db.add_to_queue.assert_called_once()

    @pytest.mark.asyncio
    async def test_discover_full_mode_passes_snapshot_block(self, orchestrator, mock_db):
        """Test full discovery pins Rust extractor boundary."""
        with patch.object(
            orchestrator._rust_extractor,
            "extract",
            return_value=([], []),
        ) as mock_extract, patch.object(
            orchestrator._price_service,
            "get_native_prices",
            return_value={"bsc": 500.0},
        ):
            result = await orchestrator.discover("bsc", mode="full", snapshot_block=123456)

        assert result.mode == "full"
        mock_extract.assert_awaited_once()
        assert mock_extract.await_args.kwargs["snapshot_block"] == 123456


class TestDiscoveryCriteria:
    """Tests for DiscoveryCriteria."""

    def test_default_values(self):
        """Test default criteria values."""
        criteria = DiscoveryCriteria()
        assert criteria.min_balance_usd == 100_000
        assert criteria.min_age_days == 0
        assert criteria.limit == 10_000

    def test_custom_values(self):
        """Test custom criteria values."""
        criteria = DiscoveryCriteria(
            min_balance_usd=500_000,
            min_age_days=365,
            chains=["eth", "bsc"],
            limit=1000,
        )
        assert criteria.min_balance_usd == 500_000
        assert criteria.min_age_days == 365
        assert criteria.chains == ["eth", "bsc"]
        assert criteria.limit == 1000


# ============================================
# Integration Tests
# ============================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_discovery_flow():
    """Test complete discovery flow with real API (rate limited)."""
    orchestrator = DiscoveryOrchestrator()
    try:
        result = await orchestrator.simulate("eth", enqueue=True)
        assert result.contracts_found > 0
        assert result.contracts_added_to_queue > 0
    finally:
        await orchestrator.close()
