"""Tests for the price module."""

from unittest.mock import MagicMock, patch

import pytest

from src.price.cache import PriceCache
from src.price.defillama import (
    FALLBACK_PRICES,
    PriceService,
)

# ============================================
# Cache Tests
# ============================================


class TestPriceCache:
    """Tests for PriceCache."""

    def test_set_and_get(self):
        """Test basic set and get."""
        cache = PriceCache(ttl_seconds=60)
        cache.set("eth", 3500.0)
        assert cache.get("eth") == 3500.0

    def test_get_missing(self):
        """Test get returns None for missing key."""
        cache = PriceCache()
        assert cache.get("nonexistent") is None

    def test_expiration(self):
        """Test cache expiration."""
        cache = PriceCache(ttl_seconds=0)  # Immediate expiration
        cache.set("eth", 3500.0)
        # Should be expired
        assert cache.get("eth") is None

    def test_clear(self):
        """Test cache clear."""
        cache = PriceCache()
        cache.set("eth", 3500.0)
        cache.set("bsc", 600.0)
        cache.clear()
        assert cache.get("eth") is None
        assert cache.get("bsc") is None

    def test_cleanup(self):
        """Test cleanup removes expired entries."""
        cache = PriceCache(ttl_seconds=0)
        cache.set("eth", 3500.0)
        cache.set("bsc", 600.0)
        removed = cache.cleanup()
        assert removed == 2


# ============================================
# PriceService Tests
# ============================================


class TestPriceService:
    """Tests for PriceService."""

    @pytest.mark.asyncio
    async def test_get_native_prices_from_cache(self):
        """Test that cached prices are returned."""
        service = PriceService()
        service._cache.set("coingecko:ethereum", 3500.0)

        prices = await service.get_native_prices(["eth"])
        assert prices["eth"] == 3500.0

    @pytest.mark.asyncio
    async def test_get_native_prices_api_success(self):
        """Test successful API fetch."""
        service = PriceService()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "coins": {
                "coingecko:ethereum": {"price": 3600.0},
            }
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(service, "_fetch_prices", return_value={"coingecko:ethereum": 3600.0}):
            prices = await service.get_native_prices(["eth"])

        assert prices["eth"] == 3600.0

    @pytest.mark.asyncio
    async def test_get_native_prices_api_failure_uses_fallback(self):
        """Test fallback prices on API failure."""
        service = PriceService()

        # Mock fetch to return empty (API failure)
        with patch.object(service, "_fetch_prices", return_value={}):
            prices = await service.get_native_prices(["eth"])

        assert prices["eth"] == FALLBACK_PRICES["eth"]

    @pytest.mark.asyncio
    async def test_get_token_price(self):
        """Test getting token price."""
        service = PriceService()

        with patch.object(
            service, "_fetch_prices", return_value={"eth:0x1234": 1.5}
        ):
            price = await service.get_token_price("eth", "0x1234")

        assert price == 1.5

    @pytest.mark.asyncio
    async def test_get_token_price_not_found(self):
        """Test token price not found returns None."""
        service = PriceService()

        with patch.object(service, "_fetch_prices", return_value={}):
            price = await service.get_token_price("eth", "0x1234")

        assert price is None


# ============================================
# Integration Tests (requires network)
# ============================================


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_price_fetch():
    """Test actual API call to DeFiLlama."""
    service = PriceService()
    try:
        prices = await service.get_native_prices(["eth"])
        assert "eth" in prices
        assert prices["eth"] > 0
    finally:
        await service.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_multiple_chains():
    """Test fetching multiple chain prices."""
    service = PriceService()
    try:
        prices = await service.get_native_prices(["eth", "bsc", "polygon"])
        assert len(prices) == 3
        assert all(p > 0 for p in prices.values())
    finally:
        await service.close()
