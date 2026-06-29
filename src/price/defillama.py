"""
DeFiLlama price service for fetching cryptocurrency prices.
https://coins.llama.fi/prices/current/{coins}
"""

import logging

import httpx

from .cache import PriceCache

logger = logging.getLogger(__name__)

# DeFiLlama coin IDs for native tokens
NATIVE_COIN_IDS: dict[str, str] = {
    "eth": "coingecko:ethereum",
    "bsc": "coingecko:binancecoin",
    "arbitrum": "coingecko:ethereum",
    "base": "coingecko:ethereum",
    "polygon": "coingecko:matic-network",
    "avalanche": "coingecko:avalanche-2",
    "optimism": "coingecko:ethereum",
    "fantom": "coingecko:fantom",
    "gnosis": "coingecko:gnosis",
}

# Fallback prices when API unavailable
FALLBACK_PRICES: dict[str, float] = {
    "eth": 3500.0,
    "bsc": 600.0,
    "arbitrum": 3500.0,
    "base": 3500.0,
    "polygon": 0.5,
    "avalanche": 35.0,
    "optimism": 3500.0,
    "fantom": 0.5,
    "gnosis": 1.0,
}

# Type aliases
type PriceDict = dict[str, float]


class PriceService:
    """Service for fetching cryptocurrency prices from DeFiLlama."""

    BASE_URL = "https://coins.llama.fi"
    TIMEOUT = 10.0

    def __init__(self, cache_ttl: int = 60):
        """
        Initialize price service.

        Args:
            cache_ttl: Cache TTL in seconds (default: 60)
        """
        self._cache = PriceCache(ttl_seconds=cache_ttl)
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.TIMEOUT)
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get_native_prices(self, chains: list[str]) -> PriceDict:
        """
        Fetch native token prices for multiple chains.

        Args:
            chains: List of chain IDs (e.g., ["eth", "bsc"])

        Returns:
            Dict mapping chain ID to price in USD
        """
        result: PriceDict = {}
        coins_to_fetch: list[str] = []
        chain_to_coin: dict[str, str] = {}

        for chain in chains:
            chain_lower = chain.lower()
            coin_id = NATIVE_COIN_IDS.get(chain_lower, f"coingecko:{chain_lower}")

            # Check cache first
            cached = self._cache.get(coin_id)
            if cached is not None:
                result[chain_lower] = cached
                logger.debug("Cache hit for %s: $%.2f", chain_lower, cached)
            else:
                coins_to_fetch.append(coin_id)
                chain_to_coin[chain_lower] = coin_id

        # Fetch missing prices
        if coins_to_fetch:
            fetched = await self._fetch_prices(coins_to_fetch)
            for chain, coin_id in chain_to_coin.items():
                if coin_id in fetched:
                    price = fetched[coin_id]
                    result[chain] = price
                    self._cache.set(coin_id, price)
                    logger.debug("Fetched %s price: $%.2f", chain, price)
                else:
                    # Use fallback
                    fallback = FALLBACK_PRICES.get(chain, 1.0)
                    result[chain] = fallback
                    logger.warning("Using fallback price for %s: $%.2f", chain, fallback)

        return result

    async def get_token_price(self, chain: str, address: str) -> float | None:
        """
        Fetch price for a specific token.

        Args:
            chain: Chain ID (e.g., "eth")
            address: Token contract address

        Returns:
            Price in USD or None if not found
        """
        chain_lower = chain.lower()
        coin_id = f"{chain_lower}:{address.lower()}"

        # Check cache
        cached = self._cache.get(coin_id)
        if cached is not None:
            return cached

        # Fetch from API
        prices = await self._fetch_prices([coin_id])
        if coin_id in prices:
            price = prices[coin_id]
            self._cache.set(coin_id, price)
            return price

        return None

    async def _fetch_prices(self, coin_ids: list[str]) -> dict[str, float]:
        """
        Fetch prices from DeFiLlama API.

        Args:
            coin_ids: List of DeFiLlama coin IDs

        Returns:
            Dict mapping coin_id to price
        """
        if not coin_ids:
            return {}

        coins_param = ",".join(coin_ids)
        url = f"{self.BASE_URL}/prices/current/{coins_param}"

        try:
            client = await self._get_client()
            response = await client.get(url)
            response.raise_for_status()

            data = response.json()
            coins_data = data.get("coins", {})

            result: dict[str, float] = {}
            for coin_id in coin_ids:
                if coin_id in coins_data:
                    price = coins_data[coin_id].get("price")
                    if price is not None:
                        result[coin_id] = float(price)

            return result

        except httpx.HTTPStatusError as e:
            logger.error("DeFiLlama API error: %s", e.response.status_code)
            return {}
        except httpx.RequestError as e:
            logger.error("DeFiLlama request failed: %s", e)
            return {}
        except Exception as e:
            logger.error("Unexpected error fetching prices: %s", e)
            return {}


# Module-level convenience functions
_price_service: PriceService | None = None


def _get_service() -> PriceService:
    """Get or create default price service."""
    global _price_service
    if _price_service is None:
        _price_service = PriceService()
    return _price_service


async def get_native_price(chain: str) -> float:
    """
    Get native token price for a chain.

    Args:
        chain: Chain ID (e.g., "eth")

    Returns:
        Price in USD
    """
    service = _get_service()
    prices = await service.get_native_prices([chain])
    return prices.get(chain.lower(), FALLBACK_PRICES.get(chain.lower(), 1.0))


async def get_token_price(chain: str, address: str) -> float | None:
    """
    Get token price.

    Args:
        chain: Chain ID (e.g., "eth")
        address: Token contract address

    Returns:
        Price in USD or None
    """
    service = _get_service()
    return await service.get_token_price(chain, address)
