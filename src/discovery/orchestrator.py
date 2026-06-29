"""
Discovery orchestrator - coordinates contract discovery and queue integration.

NOTICE: Research/educational concept demonstration. Block-explorer scraping
must respect each provider's Terms of Service and rate limits, and must only
be used for authorized security assessments or on testnet. Discovery records
results only; adding contracts to the audit queue is an explicit, opt-in step
(enqueue=True) and never happens automatically.

The flow:
1. Discovery (light_mode or rust_wrapper) finds contracts
2. upsert_contract() saves to contracts table
3. add_to_queue() adds to queue table only when enqueue=True
4. Daemon picks up from queue via get_next_from_queue()
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from ..db import AsyncDatabase
from ..models import Chain, ContractStatus, ContractTarget
from ..price import PriceService
from .light_mode import LightModeScanner
from .rust_wrapper import RustExtractor

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryCriteria:
    """Criteria for filtering discovered contracts."""

    min_balance_usd: float = 100_000
    min_age_days: int = 0
    chains: list[str] | None = None
    limit: int = 10_000


@dataclass
class DiscoveryResult:
    """Result of a discovery run."""

    chain: str
    mode: str
    contracts_found: int
    contracts_added_to_queue: int
    total_value_usd: float
    duration_seconds: float
    errors: list[str] = field(default_factory=list)


class DiscoveryOrchestrator:
    """
    Orchestrates contract discovery and queue integration.

    Discovered contracts are recorded in the contracts table. Enqueueing for
    audit is a separate, opt-in step (pass enqueue=True) so the public concept
    does not ship a turnkey "scan -> auto-queue -> audit" loop.
    """

    def __init__(self, db: AsyncDatabase | None = None):
        """
        Initialize orchestrator.

        Args:
            db: Database instance (creates new if None)
        """
        self._db = db
        self._price_service = PriceService()
        self._light_scanner = LightModeScanner()
        self._rust_extractor = RustExtractor()

    async def _get_db(self) -> AsyncDatabase:
        """Get or create database."""
        if self._db is None:
            self._db = AsyncDatabase()
            await self._db.connect()
        return self._db

    async def close(self) -> None:
        """Close resources."""
        await self._price_service.close()
        await self._light_scanner.close()
        if self._db:
            await self._db.close()

    async def discover(
        self,
        chain: str,
        mode: Literal["light", "full"] = "light",
        criteria: DiscoveryCriteria | None = None,
        snapshot_block: int | None = None,
        enqueue: bool = False,
    ) -> DiscoveryResult:
        """
        Run discovery for a chain.

        Args:
            chain: Chain ID (e.g., "eth", "bsc")
            mode: "light" for HTML scraping, "full" for Rust extractor
            criteria: Filter criteria (uses defaults if None)
            enqueue: If True, also add discovered contracts to the audit queue.
                Defaults to False so discovery only records results.

        Returns:
            DiscoveryResult with statistics
        """
        start_time = datetime.now(UTC)
        criteria = criteria or DiscoveryCriteria()
        errors: list[str] = []

        logger.info("Starting discovery for %s in %s mode", chain, mode)

        # Get native token price
        prices = await self._price_service.get_native_prices([chain])
        native_price = prices.get(chain.lower(), 1.0)
        logger.info("%s native price: $%.2f", chain, native_price)

        # Run discovery
        contracts: list[ContractTarget] = []
        if mode == "light":
            contracts, scan_errors = await self._light_scanner.scan(
                chain=chain,
                native_price=native_price,
                min_balance_usd=criteria.min_balance_usd,
                limit=criteria.limit,
            )
            errors.extend(scan_errors)
        elif mode == "full":
            contracts, extract_errors = await self._rust_extractor.extract(
                chain=chain,
                min_balance_usd=criteria.min_balance_usd,
                snapshot_block=snapshot_block,
            )
            errors.extend(extract_errors)
        else:
            errors.append(f"Unknown mode: {mode}")

        logger.info("Discovered %d contracts above threshold", len(contracts))

        # Record to database; enqueue only when explicitly requested.
        db = await self._get_db()
        added_to_queue = 0
        total_value = 0.0

        for contract in contracts:
            try:
                # 1. Upsert to contracts table (always records the result)
                await db.upsert_contract(contract)
                total_value += contract.balance_usd

                # 2. Add to queue only if the caller opted in. By default
                # discovery records results without auto-queueing for audit.
                if enqueue:
                    # Priority based on balance: higher balance = higher priority
                    priority = min(int(contract.balance_usd / 100_000), 100)
                    await db.add_to_queue(
                        address=contract.address,
                        chain=Chain(contract.chain.value if isinstance(contract.chain, Chain) else contract.chain),
                        balance_usd=contract.balance_usd,
                        priority=priority,
                    )
                    added_to_queue += 1
                    logger.debug(
                        "Added %s to queue with priority %d ($%.2f)",
                        contract.address[:10],
                        priority,
                        contract.balance_usd,
                    )

            except Exception as e:
                error_msg = f"Failed to save {contract.address}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        duration = (datetime.now(UTC) - start_time).total_seconds()

        result = DiscoveryResult(
            chain=chain,
            mode=mode,
            contracts_found=len(contracts),
            contracts_added_to_queue=added_to_queue,
            total_value_usd=total_value,
            duration_seconds=duration,
            errors=errors,
        )

        logger.info(
            "Discovery complete: %d found, %d queued, $%.2fM total value in %.1fs",
            result.contracts_found,
            result.contracts_added_to_queue,
            result.total_value_usd / 1_000_000,
            result.duration_seconds,
        )

        return result

    async def simulate(self, chain: str, enqueue: bool = False) -> DiscoveryResult:
        """
        Add built-in test contracts for development/testing (no network access).

        Args:
            chain: Chain ID
            enqueue: If True, also add the test contracts to the audit queue.
                Defaults to False so simulate only records results.

        Returns:
            DiscoveryResult with statistics
        """
        start_time = datetime.now(UTC)

        # Test contracts (known high-value unverified)
        test_contracts = [
            ContractTarget(
                address="0x764C64b2A09b09Acb100B80d8c505Aa6a0302EF2",  # TrueBit
                chain=Chain(chain),
                balanceUsd=26_000_000,
                balanceNative="10000000000000000000000",
                age=1825,  # 5 years
                verified=False,
                status=ContractStatus.NEW,
                foundAt=datetime.now(UTC),
            ),
            ContractTarget(
                address="0x27182842E098f60e3D576794A5bFFb0777E025d3",  # Euler
                chain=Chain(chain),
                balanceUsd=200_000_000,
                balanceNative="100000000000000000000000",
                age=730,
                verified=False,
                status=ContractStatus.NEW,
                foundAt=datetime.now(UTC),
            ),
        ]

        db = await self._get_db()
        added = 0
        total_value = 0.0

        for contract in test_contracts:
            await db.upsert_contract(contract)
            total_value += contract.balance_usd
            if enqueue:
                priority = min(int(contract.balance_usd / 100_000), 100)
                await db.add_to_queue(
                    address=contract.address,
                    chain=contract.chain,
                    balance_usd=contract.balance_usd,
                    priority=priority,
                )
                added += 1
            logger.info("Added test contract: %s ($%.2fM)", contract.address, contract.balance_usd / 1_000_000)

        duration = (datetime.now(UTC) - start_time).total_seconds()

        return DiscoveryResult(
            chain=chain,
            mode="simulate",
            contracts_found=len(test_contracts),
            contracts_added_to_queue=added,
            total_value_usd=total_value,
            duration_seconds=duration,
        )
