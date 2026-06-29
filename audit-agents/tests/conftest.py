"""Pytest fixtures for audit-agents tests."""

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.db import AsyncDatabase, Database
from src.models import (
    Chain,
    ContractStatus,
    ContractTarget,
    FindingSource,
    QueueItem,
    QueueStatus,
    Severity,
    VulnerabilityFinding,
    VulnerabilityLocation,
    VulnerabilityType,
)


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Create a temporary database path."""
    return tmp_path / "test.db"


@pytest.fixture
def db(temp_db_path: Path) -> Database:
    """Create a temporary database for testing."""
    database = Database(temp_db_path)
    yield database
    database.close()


@pytest.fixture
async def async_db(temp_db_path: Path) -> AsyncDatabase:
    """Create a temporary async database for testing."""
    database = AsyncDatabase(temp_db_path)
    await database.connect()
    yield database
    await database.close()


@pytest.fixture
def sample_contract() -> ContractTarget:
    """Create a sample contract for testing."""
    return ContractTarget(
        address="0x742d35cc6634c0532925a3b844bc454e4438f44e",
        chain=Chain.ETH,
        balance_usd=150000.0,
        balance_native="50000000000000000000",  # 50 ETH in wei
        age=800,  # days
        verified=False,
        is_proxy=False,
        status=ContractStatus.NEW,
        code_hash="0xabc123",
        found_at=datetime.now(UTC),
    )


@pytest.fixture
def sample_proxy_contract() -> ContractTarget:
    """Create a sample proxy contract for testing."""
    return ContractTarget(
        address="0x1234567890abcdef1234567890abcdef12345678",
        chain=Chain.ETH,
        balance_usd=500000.0,
        balance_native="200000000000000000000",  # 200 ETH in wei
        age=1000,
        verified=True,  # Proxy is verified but implementation may not be
        is_proxy=True,
        status=ContractStatus.NEW,
        found_at=datetime.now(UTC),
    )


@pytest.fixture
def sample_vulnerability() -> VulnerabilityFinding:
    """Create a sample vulnerability finding for testing."""
    return VulnerabilityFinding(
        id="vuln-001",
        type=VulnerabilityType.REENTRANCY,
        severity=Severity.HIGH,
        confidence=0.85,
        title="Reentrancy in withdraw function",
        description="The withdraw function is vulnerable to reentrancy attack.",
        location=VulnerabilityLocation(
            function="withdraw",
            selector="0x3ccfd60b",
        ),
        impact="Attacker can drain contract funds",
        exploit_scenario="1. Call withdraw\n2. In fallback, call withdraw again",
        source=FindingSource.STATIC,
        verified=False,
    )


@pytest.fixture
def sample_queue_item() -> QueueItem:
    """Create a sample queue item for testing."""
    return QueueItem(
        address="0xabcdef1234567890abcdef1234567890abcdef12",
        chain="eth",
        balance_usd=200000.0,
        priority=5,
        status=QueueStatus.PENDING,
        added_at=datetime.now(UTC),
    )
