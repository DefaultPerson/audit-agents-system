"""
Light mode scanner - discover contracts via HTML scraping from block explorers.
No local node required, but rate-limited.

NOTICE: Research/educational concept demonstration. Block-explorer scraping
must respect each provider's Terms of Service and rate limits, and must only
be used for authorized security assessments or on testnet.
"""

import asyncio
import logging
import re
from datetime import UTC, datetime

import httpx
from bs4 import BeautifulSoup

from ..models import Chain, ContractStatus, ContractTarget

logger = logging.getLogger(__name__)

# Explorer URLs for different chains
EXPLORER_URLS: dict[str, str] = {
    "eth": "https://etherscan.io",
    "bsc": "https://bscscan.com",
    "base": "https://basescan.org",
    "polygon": "https://polygonscan.com",
    "arbitrum": "https://arbiscan.io",
    "avalanche": "https://snowtrace.io",
    "optimism": "https://optimistic.etherscan.io",
    "fantom": "https://ftmscan.com",
}

# Labels to skip (exchanges, bridges, known contracts)
SKIP_LABELS = [
    "binance",
    "coinbase",
    "kraken",
    "token hub",
    "null:",
    "bridge",
    "gnosis safe",
    "multisig",
    "wrapped",
    "weth",
    "wbnb",
]


def parse_balance(balance_str: str) -> float:
    """Parse balance string like '29,888,000.158986 BNB' to float."""
    match = re.search(r"[\d,]+\.?\d*", balance_str)
    if not match:
        return 0.0
    return float(match.group().replace(",", ""))


class LightModeScanner:
    """
    Scanner that discovers contracts by scraping block explorer top accounts pages.

    Rate limited to 1 request per second with 5s backoff on errors.
    """

    RATE_LIMIT = 1.0  # seconds between requests
    ERROR_BACKOFF = 5.0  # seconds to wait after error

    def __init__(self, proxies: list[str] | None = None):
        """
        Initialize scanner.

        Args:
            proxies: Optional list of proxy URLs for rotation
        """
        self._proxies = proxies or []
        self._proxy_index = 0
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            # Rotate proxy if available
            transport = None
            if self._proxies:
                proxy = self._proxies[self._proxy_index % len(self._proxies)]
                self._proxy_index += 1
                transport = httpx.AsyncHTTPTransport(proxy=proxy)

            self._client = httpx.AsyncClient(
                timeout=30.0,
                transport=transport,
                headers={
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "accept-language": "en-US,en;q=0.9",
                    "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "cache-control": "max-age=0",
                },
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def scan(
        self,
        chain: str,
        native_price: float,
        min_balance_usd: float = 100_000,
        limit: int = 10_000,
    ) -> tuple[list[ContractTarget], list[str]]:
        """
        Scan block explorer for high-value contracts.

        Args:
            chain: Chain ID (e.g., "eth", "bsc")
            native_price: Native token price in USD
            min_balance_usd: Minimum balance threshold
            limit: Maximum number of accounts to scan

        Returns:
            Tuple of (contracts list, errors list)
        """
        base_url = EXPLORER_URLS.get(chain.lower())
        if not base_url:
            return [], [f"Unknown chain: {chain}"]

        chain_enum = Chain(chain.lower())
        contracts: list[ContractTarget] = []
        errors: list[str] = []

        pages_needed = (limit + 99) // 100  # 100 accounts per page
        total_scanned = 0

        logger.info("Scanning %s top accounts (up to %d pages)", chain, pages_needed)

        for page in range(1, pages_needed + 1):
            try:
                page_contracts, page_errors = await self._fetch_page(
                    base_url=base_url,
                    chain=chain_enum,
                    page=page,
                    native_price=native_price,
                    min_balance_usd=min_balance_usd,
                )

                contracts.extend(page_contracts)
                errors.extend(page_errors)
                total_scanned += 100

                logger.info(
                    "Page %d/%d: %d contracts found (total: %d)",
                    page,
                    pages_needed,
                    len(page_contracts),
                    len(contracts),
                )

                # Rate limiting
                await asyncio.sleep(self.RATE_LIMIT)

                if total_scanned >= limit:
                    break

            except Exception as e:
                error_msg = f"Error on page {page}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
                await asyncio.sleep(self.ERROR_BACKOFF)

        return contracts, errors

    async def _fetch_page(
        self,
        base_url: str,
        chain: Chain,
        page: int,
        native_price: float,
        min_balance_usd: float,
    ) -> tuple[list[ContractTarget], list[str]]:
        """
        Fetch and parse a single accounts page.

        Args:
            base_url: Explorer base URL
            chain: Chain enum
            page: Page number
            native_price: Native token price in USD
            min_balance_usd: Minimum balance threshold

        Returns:
            Tuple of (contracts list, errors list)
        """
        url = f"{base_url}/accounts/{page}?ps=100"
        errors: list[str] = []

        client = await self._get_client()
        response = await client.get(url)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        contracts: list[ContractTarget] = []

        # Find table rows
        for row in soup.select("tbody tr"):
            cells = row.select("td")
            if len(cells) < 5:
                continue

            try:
                # Address cell (index 1)
                address_cell = cells[1]
                address_link = address_cell.select_one('a[href^="/address/"]')
                if not address_link:
                    continue

                href_attr = address_link.get("href", "")
                href = href_attr if isinstance(href_attr, str) else ""
                address = href.replace("/address/", "").lower()

                # Validate address format
                if not re.match(r"^0x[a-f0-9]{40}$", address):
                    continue

                # Check if contract (has file icon or contract indicator)
                is_contract = bool(
                    address_cell.select_one(".fa-file-alt")
                    or address_cell.select_one('i[data-content*="Contract"]')
                    or address_cell.select_one('[data-bs-title*="Contract"]')
                )
                if not is_contract:
                    continue

                # Label cell (index 2)
                label = cells[2].get_text(strip=True).lower()

                # Skip known labels
                if any(skip in label for skip in SKIP_LABELS):
                    continue

                # Balance cell (index 3)
                balance_cell = cells[3]
                # Try tooltip first for full precision
                balance_tooltip = balance_cell.select_one("[data-bs-toggle='tooltip']")
                tooltip_title = balance_tooltip.get("title", "") if balance_tooltip else ""
                tooltip_str = tooltip_title if isinstance(tooltip_title, str) else ""
                balance_str = tooltip_str or balance_cell.get_text(strip=True)

                balance_native = parse_balance(str(balance_str))
                balance_usd = balance_native * native_price

                # Skip low balance
                if balance_usd < min_balance_usd:
                    continue

                contract = ContractTarget(
                    address=address,
                    chain=chain,
                    balanceUsd=balance_usd,
                    balanceNative=str(int(balance_native * 1e18)),
                    age=0,  # Unknown from scraping
                    verified=False,  # Will check in triage
                    status=ContractStatus.NEW,
                    foundAt=datetime.now(UTC),
                )

                contracts.append(contract)

            except Exception as e:
                errors.append(f"Error parsing row: {e}")
                continue

        return contracts, errors
