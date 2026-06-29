"""
SQLite database operations for contract tracking.
SQLAlchemy 2.0 async ORM with modern declarative syntax.

Provides both sync (Database) and async (AsyncDatabase) interfaces.
"""

import asyncio
import json
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    case,
    func,
    select,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .config import AuditConfig
from .models import (
    Chain,
    CloneFamily,
    ContractStatus,
    ContractTarget,
    DbStats,
    QueueItem,
    QueueStats,
    QueueStatus,
)

# ============================================
# ORM Models (SQLAlchemy 2.0 Declarative)
# ============================================


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


class ContractModel(Base):
    """Contract target in database."""

    __tablename__ = "contracts"
    __table_args__ = (
        Index("idx_contracts_status", "status"),
        Index("idx_contracts_balance", "balance_usd"),
        Index("idx_contracts_age", "age"),
    )

    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    chain: Mapped[str] = mapped_column(String(20), primary_key=True)
    balance_usd: Mapped[float] = mapped_column(Float)
    balance_native: Mapped[str] = mapped_column(String(78))
    age: Mapped[int] = mapped_column(Integer)
    verified: Mapped[int] = mapped_column(Integer, default=0)
    is_proxy: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="new")
    code_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    found_at: Mapped[str] = mapped_column(String(30))
    updated_at: Mapped[str | None] = mapped_column(String(30), nullable=True)


class AuditModel(Base):
    """Audit result in database."""

    __tablename__ = "audits"
    __table_args__ = (
        ForeignKeyConstraint(
            ["address", "chain"],
            ["contracts.address", "contracts.chain"],
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    address: Mapped[str] = mapped_column(String(42))
    chain: Mapped[str] = mapped_column(String(20))
    result: Mapped[str] = mapped_column(String(20))
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    audited_at: Mapped[str] = mapped_column(String(30))


class ProxyImplementationModel(Base):
    """Proxy implementation cache."""

    __tablename__ = "proxy_implementations"

    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    chain: Mapped[str] = mapped_column(String(20), primary_key=True)
    implementation: Mapped[str] = mapped_column(String(42))
    checked_at: Mapped[str] = mapped_column(String(30))


class QueueModel(Base):
    """Audit queue item."""

    __tablename__ = "queue"
    __table_args__ = (
        Index("idx_queue_status", "status"),
        Index("idx_queue_priority", "priority"),
    )

    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    chain: Mapped[str] = mapped_column(String(20), primary_key=True)
    balance_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    added_at: Mapped[str | None] = mapped_column(String(30), nullable=True)
    started_at: Mapped[str | None] = mapped_column(String(30), nullable=True)
    processed_at: Mapped[str | None] = mapped_column(String(30), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


# ============================================
# Async Database (SQLAlchemy 2.0 ORM)
# ============================================


class AsyncDatabase:
    """Async SQLite using SQLAlchemy 2.0 ORM."""

    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path) if db_path else AuditConfig.db_path
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

    async def _init(self) -> async_sessionmaker[AsyncSession]:
        """Initialize engine and session factory."""
        if self._session_factory is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._engine = create_async_engine(
                f"sqlite+aiosqlite:///{self.db_path}",
                echo=False,
            )
            self._session_factory = async_sessionmaker(
                self._engine,
                expire_on_commit=False,
            )
            # Create tables
            async with self._engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        return self._session_factory

    async def connect(self) -> async_sessionmaker[AsyncSession]:
        """Connect and return session factory (backwards compat)."""
        return await self._init()

    async def close(self) -> None:
        """Close database engine."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None

    # ============================================
    # Contract Operations
    # ============================================

    async def upsert_contract(self, contract: ContractTarget) -> None:
        """Insert or update a contract."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = sqlite_insert(ContractModel).values(
                address=contract.address.lower(),
                chain=contract.chain.value,
                balance_usd=contract.balance_usd,
                balance_native=contract.balance_native,
                age=contract.age,
                verified=1 if contract.verified else 0,
                is_proxy=1 if contract.is_proxy else 0,
                status=contract.status.value,
                code_hash=contract.code_hash,
                found_at=contract.found_at.isoformat(),
                updated_at=(contract.updated_at or datetime.now(UTC)).isoformat(),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["address", "chain"],
                set_={
                    "balance_usd": stmt.excluded.balance_usd,
                    "balance_native": stmt.excluded.balance_native,
                    "age": stmt.excluded.age,
                    "verified": stmt.excluded.verified,
                    "is_proxy": stmt.excluded.is_proxy,
                    "status": case(
                        (ContractModel.status == "skip", "skip"),
                        else_=stmt.excluded.status,
                    ),
                    "code_hash": stmt.excluded.code_hash,
                    "updated_at": stmt.excluded.updated_at,
                },
            )
            await session.execute(stmt)
            await session.commit()

    async def get_contract(self, address: str, chain: Chain) -> ContractTarget | None:
        """Get a single contract by address and chain."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = select(ContractModel).where(
                ContractModel.address == address.lower(),
                ContractModel.chain == chain.value,
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            return self._model_to_contract(row) if row else None

    async def get_contracts_for_audit(self, limit: int = 10) -> list[ContractTarget]:
        """Get contracts eligible for audit (new, unverified or proxy, meets criteria)."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = (
                select(ContractModel)
                .where(
                    ContractModel.status == "new",
                    (ContractModel.verified == 0) | (ContractModel.is_proxy == 1),
                    ContractModel.balance_usd >= AuditConfig.min_balance_usd,
                    ContractModel.age >= AuditConfig.min_age_days,
                )
                .order_by(ContractModel.balance_usd.desc())
                .limit(limit)
            )
            result = await session.execute(stmt)
            return [self._model_to_contract(row) for row in result.scalars()]

    async def get_contracts_by_status(
        self, status: ContractStatus, limit: int = 100
    ) -> list[ContractTarget]:
        """Get contracts by status."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = (
                select(ContractModel)
                .where(ContractModel.status == status.value)
                .order_by(ContractModel.balance_usd.desc())
                .limit(limit)
            )
            result = await session.execute(stmt)
            return [self._model_to_contract(row) for row in result.scalars()]

    async def get_clone_families(
        self,
        *,
        min_size: int = 2,
        limit: int = 50,
    ) -> list[CloneFamily]:
        """Group discovered contracts by identical runtime bytecode hash."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = (
                select(ContractModel)
                .where(
                    ContractModel.code_hash.is_not(None),
                    ContractModel.code_hash != "",
                    ContractModel.status != ContractStatus.SKIP.value,
                )
                .order_by(ContractModel.code_hash.asc(), ContractModel.balance_usd.desc())
            )
            result = await session.execute(stmt)

            grouped: dict[str, list[ContractTarget]] = {}
            for row in result.scalars():
                contract = self._model_to_contract(row)
                if contract.code_hash:
                    grouped.setdefault(contract.code_hash, []).append(contract)

            families = [
                CloneFamily(
                    bytecodeHash=code_hash,
                    members=members,
                    chains=sorted({member.chain for member in members}, key=lambda chain: chain.value),
                    totalValueUsd=sum(member.balance_usd for member in members),
                    proxyCount=sum(1 for member in members if member.is_proxy),
                    representativeAddress=members[0].address,
                )
                for code_hash, members in grouped.items()
                if len(members) >= min_size
            ]
            families.sort(key=lambda family: family.total_value_usd, reverse=True)
            return families[:limit]

    async def update_contract_status(
        self, address: str, chain: Chain, status: ContractStatus
    ) -> None:
        """Update contract status."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = select(ContractModel).where(
                ContractModel.address == address.lower(),
                ContractModel.chain == chain.value,
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            if row:
                row.status = status.value
                row.updated_at = datetime.now(UTC).isoformat()
                await session.commit()

    async def save_audit_result(
        self,
        address: str,
        chain: Chain,
        result: str,  # "clean" | "vulnerable" | "error"
        findings: list[Any],
    ) -> None:
        """Save audit result and update contract status."""
        session_factory = await self._init()
        async with session_factory() as session:
            audit = AuditModel(
                address=address.lower(),
                chain=chain.value,
                result=result,
                findings_count=len(findings),
                findings_json=json.dumps(findings),
                audited_at=datetime.now(UTC).isoformat(),
            )
            session.add(audit)
            await session.commit()

        # Update contract status
        new_status = (
            ContractStatus.VULNERABLE
            if result == "vulnerable"
            else ContractStatus.AUDITED
        )
        await self.update_contract_status(address, chain, new_status)

    # ============================================
    # Proxy Operations
    # ============================================

    async def get_proxy_implementation(self, address: str, chain: Chain) -> str | None:
        """Get cached proxy implementation address."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = select(ProxyImplementationModel.implementation).where(
                ProxyImplementationModel.address == address.lower(),
                ProxyImplementationModel.chain == chain.value,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def save_proxy_implementation(
        self, address: str, chain: Chain, implementation: str
    ) -> None:
        """Save proxy implementation address."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = sqlite_insert(ProxyImplementationModel).values(
                address=address.lower(),
                chain=chain.value,
                implementation=implementation.lower(),
                checked_at=datetime.now(UTC).isoformat(),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["address", "chain"],
                set_={
                    "implementation": stmt.excluded.implementation,
                    "checked_at": stmt.excluded.checked_at,
                },
            )
            await session.execute(stmt)
            await session.commit()

    # ============================================
    # Statistics
    # ============================================

    async def get_stats(self) -> DbStats:
        """Get database statistics."""
        session_factory = await self._init()
        async with session_factory() as session:
            # Total contracts
            total = (
                await session.execute(select(func.count()).select_from(ContractModel))
            ).scalar() or 0

            # By status
            by_status_result = await session.execute(
                select(ContractModel.status, func.count()).group_by(
                    ContractModel.status
                )
            )
            by_status = {row[0]: row[1] for row in by_status_result}

            # By chain
            by_chain_result = await session.execute(
                select(ContractModel.chain, func.count()).group_by(ContractModel.chain)
            )
            by_chain = {row[0]: row[1] for row in by_chain_result}

            # Total value
            total_value = (
                await session.execute(
                    select(func.sum(ContractModel.balance_usd)).where(
                        ContractModel.status != "skip"
                    )
                )
            ).scalar() or 0

            return DbStats(
                total=total,
                byStatus=by_status,
                byChain=by_chain,
                totalValueUsd=total_value,
            )

    # ============================================
    # Queue Operations
    # ============================================

    async def add_to_queue(
        self,
        address: str,
        chain: Chain,
        balance_usd: float = 0,
        priority: int = 0,
    ) -> None:
        """Add contract to audit queue."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = sqlite_insert(QueueModel).values(
                address=address.lower(),
                chain=chain.value,
                balance_usd=balance_usd,
                priority=priority,
                status="pending",
                added_at=datetime.now(UTC).isoformat(),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["address", "chain"],
                set_={
                    "balance_usd": stmt.excluded.balance_usd,
                    "priority": stmt.excluded.priority,
                    "status": case(
                        (QueueModel.status == "done", "done"),
                        else_="pending",
                    ),
                },
            )
            await session.execute(stmt)
            await session.commit()

    async def get_queue_item(self, address: str, chain: str) -> QueueItem | None:
        """Get queue item by address and chain."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = select(QueueModel).where(
                QueueModel.address == address.lower(),
                QueueModel.chain == chain,
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            return self._model_to_queue_item(row) if row else None

    async def get_next_from_queue(self) -> QueueItem | None:
        """Get next pending item from queue (highest priority first)."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = (
                select(QueueModel)
                .where(QueueModel.status == "pending")
                .order_by(QueueModel.priority.desc(), QueueModel.added_at.asc())
                .limit(1)
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()

            if not row:
                return None

            # Mark as processing
            row.status = "processing"
            row.started_at = datetime.now(UTC).isoformat()
            await session.commit()

            return QueueItem(
                address=row.address,
                chain=row.chain,
                balance_usd=row.balance_usd,
                priority=row.priority,
                status=QueueStatus.PROCESSING,
                added_at=datetime.fromisoformat(row.added_at) if row.added_at else None,
                started_at=datetime.now(UTC),
            )

    async def mark_queue_processed(self, address: str, chain: str, result: str) -> None:
        """Mark queue item as completed."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = select(QueueModel).where(
                QueueModel.address == address.lower(),
                QueueModel.chain == chain,
            )
            res = await session.execute(stmt)
            row = res.scalar_one_or_none()
            if row:
                row.status = "done"
                row.processed_at = datetime.now(UTC).isoformat()
                row.result = result[:10000]  # Limit result size
                await session.commit()

    async def mark_queue_failed(self, address: str, chain: str, error: str) -> None:
        """Mark queue item as failed."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = select(QueueModel).where(
                QueueModel.address == address.lower(),
                QueueModel.chain == chain,
            )
            res = await session.execute(stmt)
            row = res.scalar_one_or_none()
            if row:
                row.status = "failed"
                row.processed_at = datetime.now(UTC).isoformat()
                row.error = error[:5000]  # Limit error size
                await session.commit()

    async def get_queue(self, limit: int = 100) -> list[QueueItem]:
        """Get queue items sorted by priority."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = (
                select(QueueModel)
                .order_by(
                    case(
                        (QueueModel.status == "processing", 0),
                        (QueueModel.status == "pending", 1),
                        (QueueModel.status == "failed", 2),
                        else_=3,
                    ),
                    QueueModel.priority.desc(),
                    QueueModel.added_at.asc(),
                )
                .limit(limit)
            )
            result = await session.execute(stmt)
            return [self._model_to_queue_item(row) for row in result.scalars()]

    async def get_queue_by_status(
        self, status: QueueStatus, limit: int = 100
    ) -> list[QueueItem]:
        """Get queue items by status."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = (
                select(QueueModel)
                .where(QueueModel.status == status.value)
                .order_by(QueueModel.priority.desc(), QueueModel.added_at.asc())
                .limit(limit)
            )
            result = await session.execute(stmt)
            return [self._model_to_queue_item(row) for row in result.scalars()]

    async def get_queue_stats(self) -> QueueStats:
        """Get queue statistics."""
        session_factory = await self._init()
        async with session_factory() as session:
            total = (
                await session.execute(select(func.count()).select_from(QueueModel))
            ).scalar() or 0

            pending = (
                await session.execute(
                    select(func.count())
                    .select_from(QueueModel)
                    .where(QueueModel.status == "pending")
                )
            ).scalar() or 0

            processing = (
                await session.execute(
                    select(func.count())
                    .select_from(QueueModel)
                    .where(QueueModel.status == "processing")
                )
            ).scalar() or 0

            done = (
                await session.execute(
                    select(func.count())
                    .select_from(QueueModel)
                    .where(QueueModel.status == "done")
                )
            ).scalar() or 0

            failed = (
                await session.execute(
                    select(func.count())
                    .select_from(QueueModel)
                    .where(QueueModel.status == "failed")
                )
            ).scalar() or 0

            total_value = (
                await session.execute(
                    select(func.coalesce(func.sum(QueueModel.balance_usd), 0)).where(
                        QueueModel.status == "pending"
                    )
                )
            ).scalar() or 0

            by_chain_result = await session.execute(
                select(QueueModel.chain, func.count()).group_by(QueueModel.chain)
            )
            by_chain = {row[0].upper(): row[1] for row in by_chain_result}

            completed_total = done + failed
            success_rate = (
                round((done / completed_total) * 100) if completed_total > 0 else 0
            )

            return QueueStats(
                total=total,
                pending=pending,
                processing=processing,
                done=done,
                failed=failed,
                totalValue=total_value,
                byChain=by_chain,
                successRate=success_rate,
            )

    async def remove_from_queue(self, address: str, chain: str) -> None:
        """Remove item from queue."""
        session_factory = await self._init()
        async with session_factory() as session:
            stmt = select(QueueModel).where(
                QueueModel.address == address.lower(),
                QueueModel.chain == chain,
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            if row:
                await session.delete(row)
                await session.commit()

    async def clear_queue(self) -> None:
        """Clear entire queue."""
        session_factory = await self._init()
        async with session_factory() as session:
            result = await session.execute(select(QueueModel))
            for row in result.scalars():
                await session.delete(row)
            await session.commit()

    # ============================================
    # Helpers
    # ============================================

    def _model_to_contract(self, row: ContractModel) -> ContractTarget:
        """Convert ORM model to Pydantic ContractTarget."""
        return ContractTarget(
            address=row.address,
            chain=Chain(row.chain),
            balanceUsd=row.balance_usd,
            balanceNative=row.balance_native,
            age=row.age,
            verified=row.verified == 1,
            isProxy=row.is_proxy == 1,
            status=ContractStatus(row.status),
            codeHash=row.code_hash,
            foundAt=datetime.fromisoformat(row.found_at),
            updatedAt=(
                datetime.fromisoformat(row.updated_at) if row.updated_at else None
            ),
        )

    def _model_to_queue_item(self, row: QueueModel) -> QueueItem:
        """Convert ORM model to Pydantic QueueItem."""
        return QueueItem(
            address=row.address,
            chain=row.chain,
            balance_usd=row.balance_usd,
            priority=row.priority,
            status=QueueStatus(row.status),
            added_at=datetime.fromisoformat(row.added_at) if row.added_at else None,
            started_at=(
                datetime.fromisoformat(row.started_at) if row.started_at else None
            ),
            processed_at=(
                datetime.fromisoformat(row.processed_at) if row.processed_at else None
            ),
            result=row.result,
            error=row.error,
        )


# ============================================
# Sync Database (wraps AsyncDatabase)
# ============================================


class Database:
    """Synchronous database wrapper delegating to AsyncDatabase."""

    def __init__(self, db_path: Path | str | None = None):
        self._async_db = AsyncDatabase(db_path)

    def _run(self, coro):
        """Run async coroutine synchronously."""
        return asyncio.run(coro)

    def close(self) -> None:
        """Close database connection."""
        self._run(self._async_db.close())

    # Contract operations
    def upsert_contract(self, contract: ContractTarget) -> None:
        """Insert or update a contract."""
        self._run(self._async_db.upsert_contract(contract))

    def get_contract(self, address: str, chain: Chain) -> ContractTarget | None:
        """Get a single contract by address and chain."""
        return self._run(self._async_db.get_contract(address, chain))

    def get_contracts_for_audit(self, limit: int = 10) -> list[ContractTarget]:
        """Get contracts eligible for audit."""
        return self._run(self._async_db.get_contracts_for_audit(limit))

    def get_contracts_by_status(
        self, status: ContractStatus, limit: int = 100
    ) -> list[ContractTarget]:
        """Get contracts by status."""
        return self._run(self._async_db.get_contracts_by_status(status, limit))

    def get_clone_families(self, min_size: int = 2, limit: int = 50) -> list[CloneFamily]:
        """Group discovered contracts by identical runtime bytecode hash."""
        return self._run(self._async_db.get_clone_families(min_size=min_size, limit=limit))

    def update_contract_status(
        self, address: str, chain: Chain, status: ContractStatus
    ) -> None:
        """Update contract status."""
        self._run(self._async_db.update_contract_status(address, chain, status))

    def save_audit_result(
        self,
        address: str,
        chain: Chain,
        result: str,
        findings: list[Any],
    ) -> None:
        """Save audit result and update contract status."""
        self._run(self._async_db.save_audit_result(address, chain, result, findings))

    # Proxy operations
    def get_proxy_implementation(self, address: str, chain: Chain) -> str | None:
        """Get cached proxy implementation address."""
        return self._run(self._async_db.get_proxy_implementation(address, chain))

    def save_proxy_implementation(
        self, address: str, chain: Chain, implementation: str
    ) -> None:
        """Save proxy implementation address."""
        self._run(
            self._async_db.save_proxy_implementation(address, chain, implementation)
        )

    # Statistics
    def get_stats(self) -> DbStats:
        """Get database statistics."""
        return self._run(self._async_db.get_stats())

    # Queue operations
    def add_to_queue(
        self,
        address: str,
        chain: Chain,
        balance_usd: float = 0,
        priority: int = 0,
    ) -> None:
        """Add contract to audit queue."""
        self._run(self._async_db.add_to_queue(address, chain, balance_usd, priority))

    def get_queue_item(self, address: str, chain: str) -> QueueItem | None:
        """Get queue item by address and chain."""
        return self._run(self._async_db.get_queue_item(address, chain))

    def get_next_from_queue(self) -> QueueItem | None:
        """Get next pending item from queue."""
        return self._run(self._async_db.get_next_from_queue())

    def mark_queue_processed(self, address: str, chain: str, result: str) -> None:
        """Mark queue item as completed."""
        self._run(self._async_db.mark_queue_processed(address, chain, result))

    def mark_queue_failed(self, address: str, chain: str, error: str) -> None:
        """Mark queue item as failed."""
        self._run(self._async_db.mark_queue_failed(address, chain, error))

    def get_queue(self, limit: int = 100) -> list[QueueItem]:
        """Get queue items sorted by priority."""
        return self._run(self._async_db.get_queue(limit))

    def get_queue_by_status(
        self, status: QueueStatus, limit: int = 100
    ) -> list[QueueItem]:
        """Get queue items by status."""
        return self._run(self._async_db.get_queue_by_status(status, limit))

    def get_queue_stats(self) -> QueueStats:
        """Get queue statistics."""
        return self._run(self._async_db.get_queue_stats())

    def remove_from_queue(self, address: str, chain: str) -> None:
        """Remove item from queue."""
        self._run(self._async_db.remove_from_queue(address, chain))

    def clear_queue(self) -> None:
        """Clear entire queue."""
        self._run(self._async_db.clear_queue())


# ============================================
# Context Managers
# ============================================


@contextmanager
def get_db(db_path: Path | str | None = None):
    """Context manager for sync database access."""
    db = Database(db_path)
    try:
        yield db
    finally:
        db.close()


@asynccontextmanager
async def get_async_db(db_path: Path | str | None = None):
    """Context manager for async database access."""
    db = AsyncDatabase(db_path)
    try:
        await db.connect()
        yield db
    finally:
        await db.close()


# ============================================
# Module-level convenience functions
# ============================================

_db: Database | None = None


def get_default_db() -> Database:
    """Get or create the default database instance."""
    global _db
    if _db is None:
        _db = Database()
    return _db


def close_default_db() -> None:
    """Close the default database instance."""
    global _db
    if _db is not None:
        _db.close()
        _db = None
