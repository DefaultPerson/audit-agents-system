"""Tests for database operations."""

import asyncio
from datetime import UTC, datetime

import pytest
from sqlalchemy import inspect

from src.db import AsyncDatabase, Database
from src.models import (
    Chain,
    ContractStatus,
    ContractTarget,
    QueueStatus,
)


class TestDatabase:
    """Tests for synchronous Database class."""

    def test_init_creates_tables(self, db: Database):
        """Test that database initialization creates all tables."""
        async def check():
            await db._async_db._init()
            engine = db._async_db._engine
            assert engine is not None
            async with engine.connect() as conn:

                def get_tables(connection):
                    return set(inspect(connection).get_table_names())

                return await conn.run_sync(get_tables)

        tables = asyncio.run(check())
        assert {"contracts", "audits", "proxy_implementations", "queue"} <= tables

    def test_upsert_contract(self, db: Database, sample_contract: ContractTarget):
        """Test inserting a contract."""
        db.upsert_contract(sample_contract)

        retrieved = db.get_contract(sample_contract.address, sample_contract.chain)
        assert retrieved is not None
        assert retrieved.address == sample_contract.address.lower()
        assert retrieved.balance_usd == sample_contract.balance_usd
        assert retrieved.status == ContractStatus.NEW

    def test_upsert_contract_update(self, db: Database, sample_contract: ContractTarget):
        """Test updating an existing contract."""
        db.upsert_contract(sample_contract)

        # Update the contract
        sample_contract.balance_usd = 200000.0
        db.upsert_contract(sample_contract)

        retrieved = db.get_contract(sample_contract.address, sample_contract.chain)
        assert retrieved is not None
        assert retrieved.balance_usd == 200000.0

    def test_upsert_contract_preserves_skip_status(
        self, db: Database, sample_contract: ContractTarget
    ):
        """Test that 'skip' status is preserved on update."""
        db.upsert_contract(sample_contract)
        db.update_contract_status(
            sample_contract.address, sample_contract.chain, ContractStatus.SKIP
        )

        # Try to update with 'new' status
        sample_contract.status = ContractStatus.NEW
        db.upsert_contract(sample_contract)

        retrieved = db.get_contract(sample_contract.address, sample_contract.chain)
        assert retrieved is not None
        assert retrieved.status == ContractStatus.SKIP

    def test_get_contracts_for_audit(
        self, db: Database, sample_contract: ContractTarget
    ):
        """Test getting contracts eligible for audit."""
        db.upsert_contract(sample_contract)

        contracts = db.get_contracts_for_audit(limit=10)
        assert len(contracts) == 1
        assert contracts[0].address == sample_contract.address.lower()

    def test_get_contracts_for_audit_filters_verified(
        self, db: Database, sample_contract: ContractTarget
    ):
        """Test that verified non-proxy contracts are filtered out."""
        sample_contract.verified = True
        sample_contract.is_proxy = False
        db.upsert_contract(sample_contract)

        contracts = db.get_contracts_for_audit(limit=10)
        assert len(contracts) == 0

    def test_get_contracts_for_audit_includes_verified_proxy(
        self, db: Database, sample_proxy_contract: ContractTarget
    ):
        """Test that verified proxy contracts are included."""
        db.upsert_contract(sample_proxy_contract)

        contracts = db.get_contracts_for_audit(limit=10)
        assert len(contracts) == 1
        assert contracts[0].is_proxy is True

    def test_get_contracts_by_status(
        self, db: Database, sample_contract: ContractTarget
    ):
        """Test getting contracts by status."""
        db.upsert_contract(sample_contract)

        contracts = db.get_contracts_by_status(ContractStatus.NEW)
        assert len(contracts) == 1

        contracts = db.get_contracts_by_status(ContractStatus.AUDITED)
        assert len(contracts) == 0

    def test_get_clone_families_groups_by_code_hash(self, db: Database):
        """Test grouping discovered contracts by runtime bytecode hash."""
        now = datetime.now(UTC)
        for address, chain, value, is_proxy, code_hash in [
            ("0x1111111111111111111111111111111111111111", Chain.ETH, 100000.0, False, "0xaaa"),
            ("0x2222222222222222222222222222222222222222", Chain.BSC, 300000.0, True, "0xaaa"),
            ("0x3333333333333333333333333333333333333333", Chain.ETH, 900000.0, False, "0xbbb"),
        ]:
            db.upsert_contract(
                ContractTarget(
                    address=address,
                    chain=chain,
                    balanceUsd=value,
                    balanceNative="1",
                    age=100,
                    verified=False,
                    isProxy=is_proxy,
                    status=ContractStatus.NEW,
                    codeHash=code_hash,
                    foundAt=now,
                )
            )

        families = db.get_clone_families(min_size=2)

        assert len(families) == 1
        assert families[0].bytecode_hash == "0xaaa"
        assert len(families[0].members) == 2
        assert families[0].total_value_usd == 400000.0
        assert families[0].proxy_count == 1
        assert {chain.value for chain in families[0].chains} == {"eth", "bsc"}

    def test_update_contract_status(
        self, db: Database, sample_contract: ContractTarget
    ):
        """Test updating contract status."""
        db.upsert_contract(sample_contract)
        db.update_contract_status(
            sample_contract.address, sample_contract.chain, ContractStatus.AUDITED
        )

        retrieved = db.get_contract(sample_contract.address, sample_contract.chain)
        assert retrieved is not None
        assert retrieved.status == ContractStatus.AUDITED

    def test_save_audit_result(self, db: Database, sample_contract: ContractTarget):
        """Test saving audit results."""
        db.upsert_contract(sample_contract)

        findings = [{"type": "reentrancy", "severity": "high"}]
        db.save_audit_result(
            sample_contract.address,
            sample_contract.chain,
            "vulnerable",
            findings,
        )

        retrieved = db.get_contract(sample_contract.address, sample_contract.chain)
        assert retrieved is not None
        assert retrieved.status == ContractStatus.VULNERABLE

    def test_proxy_implementation_operations(self, db: Database):
        """Test proxy implementation save and retrieve."""
        address = "0x1234567890abcdef1234567890abcdef12345678"
        impl = "0xabcdef1234567890abcdef1234567890abcdef12"
        chain = Chain.ETH

        db.save_proxy_implementation(address, chain, impl)

        retrieved = db.get_proxy_implementation(address, chain)
        assert retrieved == impl.lower()

    def test_get_stats(self, db: Database, sample_contract: ContractTarget):
        """Test getting database statistics."""
        db.upsert_contract(sample_contract)

        stats = db.get_stats()
        assert stats.total == 1
        assert stats.by_status.get("new", 0) == 1
        assert stats.by_chain.get("eth", 0) == 1
        assert stats.total_value_usd > 0


class TestDatabaseQueue:
    """Tests for queue operations."""

    def test_add_to_queue(self, db: Database):
        """Test adding item to queue."""
        address = "0x1234567890abcdef1234567890abcdef12345678"
        db.add_to_queue(address, Chain.ETH, balance_usd=100000, priority=5)

        item = db.get_queue_item(address, "eth")
        assert item is not None
        assert item.status == QueueStatus.PENDING
        assert item.priority == 5

    def test_get_next_from_queue(self, db: Database):
        """Test getting next item from queue."""
        # Add items with different priorities
        db.add_to_queue(
            "0x1111111111111111111111111111111111111111",
            Chain.ETH,
            priority=1,
        )
        db.add_to_queue(
            "0x2222222222222222222222222222222222222222",
            Chain.ETH,
            priority=10,
        )
        db.add_to_queue(
            "0x3333333333333333333333333333333333333333",
            Chain.ETH,
            priority=5,
        )

        # Should get highest priority first
        item = db.get_next_from_queue()
        assert item is not None
        assert item.address == "0x2222222222222222222222222222222222222222"
        assert item.status == QueueStatus.PROCESSING

    def test_mark_queue_processed(self, db: Database):
        """Test marking queue item as processed."""
        address = "0x1234567890abcdef1234567890abcdef12345678"
        db.add_to_queue(address, Chain.ETH)

        item = db.get_next_from_queue()
        assert item is not None

        db.mark_queue_processed(address, "eth", "success")

        item = db.get_queue_item(address, "eth")
        assert item is not None
        assert item.status == QueueStatus.DONE
        assert item.result == "success"

    def test_mark_queue_failed(self, db: Database):
        """Test marking queue item as failed."""
        address = "0x1234567890abcdef1234567890abcdef12345678"
        db.add_to_queue(address, Chain.ETH)

        item = db.get_next_from_queue()
        assert item is not None

        db.mark_queue_failed(address, "eth", "Connection timeout")

        item = db.get_queue_item(address, "eth")
        assert item is not None
        assert item.status == QueueStatus.FAILED
        assert item.error == "Connection timeout"

    def test_get_queue(self, db: Database):
        """Test getting queue items."""
        for i in range(5):
            db.add_to_queue(
                f"0x{i:040x}",
                Chain.ETH,
                priority=i,
            )

        items = db.get_queue(limit=3)
        assert len(items) == 3
        # Should be ordered by priority descending
        assert items[0].priority >= items[1].priority

    def test_get_queue_by_status(self, db: Database):
        """Test getting queue items by status."""
        db.add_to_queue(
            "0x1111111111111111111111111111111111111111",
            Chain.ETH,
        )
        db.add_to_queue(
            "0x2222222222222222222222222222222222222222",
            Chain.ETH,
        )

        # Mark one as processing
        db.get_next_from_queue()

        pending = db.get_queue_by_status(QueueStatus.PENDING)
        assert len(pending) == 1

        processing = db.get_queue_by_status(QueueStatus.PROCESSING)
        assert len(processing) == 1

    def test_get_queue_stats(self, db: Database):
        """Test getting queue statistics."""
        # Add some items
        db.add_to_queue(
            "0x1111111111111111111111111111111111111111",
            Chain.ETH,
            balance_usd=100000,
        )
        db.add_to_queue(
            "0x2222222222222222222222222222222222222222",
            Chain.BSC,
            balance_usd=200000,
        )

        # Process one
        db.get_next_from_queue()
        db.mark_queue_processed(
            "0x1111111111111111111111111111111111111111",
            "eth",
            "success",
        )

        stats = db.get_queue_stats()
        assert stats.total == 2
        assert stats.done == 1
        assert stats.pending == 1
        assert stats.success_rate == 100

    def test_remove_from_queue(self, db: Database):
        """Test removing item from queue."""
        address = "0x1234567890abcdef1234567890abcdef12345678"
        db.add_to_queue(address, Chain.ETH)

        db.remove_from_queue(address, "eth")

        item = db.get_queue_item(address, "eth")
        assert item is None

    def test_clear_queue(self, db: Database):
        """Test clearing entire queue."""
        for i in range(5):
            db.add_to_queue(f"0x{i:040x}", Chain.ETH)

        db.clear_queue()

        items = db.get_queue()
        assert len(items) == 0


class TestAsyncDatabase:
    """Tests for asynchronous AsyncDatabase class."""

    @pytest.mark.asyncio
    async def test_connect(self, async_db: AsyncDatabase):
        """Test async database connection."""
        assert async_db._engine is not None
        assert async_db._session_factory is not None

    @pytest.mark.asyncio
    async def test_add_to_queue_async(self, async_db: AsyncDatabase):
        """Test async add to queue."""
        address = "0x1234567890abcdef1234567890abcdef12345678"
        await async_db.add_to_queue(address, Chain.ETH, balance_usd=100000, priority=5)

        stats = await async_db.get_queue_stats()
        assert stats.total == 1
        assert stats.pending == 1

    @pytest.mark.asyncio
    async def test_get_next_from_queue_async(self, async_db: AsyncDatabase):
        """Test async get next from queue."""
        await async_db.add_to_queue(
            "0x1111111111111111111111111111111111111111",
            Chain.ETH,
            priority=10,
        )

        item = await async_db.get_next_from_queue()
        assert item is not None
        assert item.status == QueueStatus.PROCESSING

    @pytest.mark.asyncio
    async def test_mark_queue_processed_async(self, async_db: AsyncDatabase):
        """Test async mark queue processed."""
        address = "0x1234567890abcdef1234567890abcdef12345678"
        await async_db.add_to_queue(address, Chain.ETH)

        item = await async_db.get_next_from_queue()
        assert item is not None

        await async_db.mark_queue_processed(address, "eth", "success")

        stats = await async_db.get_queue_stats()
        assert stats.done == 1

    @pytest.mark.asyncio
    async def test_mark_queue_failed_async(self, async_db: AsyncDatabase):
        """Test async mark queue failed."""
        address = "0x1234567890abcdef1234567890abcdef12345678"
        await async_db.add_to_queue(address, Chain.ETH)

        await async_db.get_next_from_queue()
        await async_db.mark_queue_failed(address, "eth", "error")

        stats = await async_db.get_queue_stats()
        assert stats.failed == 1
