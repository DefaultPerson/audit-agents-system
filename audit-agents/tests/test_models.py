"""Tests for Pydantic models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.models import (
    AuditReport,
    AuditResult,
    Chain,
    ChainConfig,
    ContractStatus,
    ContractTarget,
    FindingsCount,
    FindingSource,
    ProxyType,
    QueueItem,
    QueueStatus,
    ResolvedContract,
    Severity,
    VulnerabilityFinding,
    VulnerabilityLocation,
    VulnerabilityType,
)


class TestContractTarget:
    """Tests for ContractTarget model."""

    def test_valid_contract(self, sample_contract: ContractTarget):
        """Test creating a valid contract."""
        assert sample_contract.address == "0x742d35cc6634c0532925a3b844bc454e4438f44e"
        assert sample_contract.chain == Chain.ETH
        assert sample_contract.balance_usd == 150000.0
        assert sample_contract.status == ContractStatus.NEW
        assert sample_contract.is_proxy is False

    def test_address_lowercase(self):
        """Test that addresses are lowercased."""
        contract = ContractTarget(
            address="0x742D35CC6634C0532925A3B844BC454E4438F44E",
            chain=Chain.ETH,
            balance_usd=100000.0,
            balance_native="1000000000000000000",
            age=730,
            verified=False,
            status=ContractStatus.NEW,
            found_at=datetime.now(UTC),
        )
        assert contract.address == "0x742d35cc6634c0532925a3b844bc454e4438f44e"

    def test_invalid_address(self):
        """Test that invalid addresses are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ContractTarget(
                address="invalid",
                chain=Chain.ETH,
                balance_usd=100000.0,
                balance_native="1000000000000000000",
                age=730,
                verified=False,
                status=ContractStatus.NEW,
                found_at=datetime.now(UTC),
            )
        assert "address" in str(exc_info.value)

    def test_alias_serialization(self, sample_contract: ContractTarget):
        """Test that aliases work for JSON serialization."""
        data = sample_contract.model_dump(by_alias=True)
        assert "balanceUsd" in data
        assert "balanceNative" in data
        assert "isProxy" in data
        assert "codeHash" in data
        assert "foundAt" in data

    def test_from_camel_case(self):
        """Test creating from camelCase data."""
        data = {
            "address": "0x742d35cc6634c0532925a3b844bc454e4438f44e",
            "chain": "eth",
            "balanceUsd": 150000.0,
            "balanceNative": "50000000000000000000",
            "age": 800,
            "verified": False,
            "isProxy": True,
            "status": "new",
            "foundAt": "2024-01-15T10:00:00Z",
        }
        contract = ContractTarget.model_validate(data)
        assert contract.is_proxy is True
        assert contract.balance_usd == 150000.0


class TestResolvedContract:
    """Tests for ResolvedContract model."""

    def test_valid_resolved_contract(self):
        """Test creating a resolved contract."""
        contract = ResolvedContract(
            original_address="0x1234567890abcdef1234567890abcdef12345678",
            resolved_address="0xabcdef1234567890abcdef1234567890abcdef12",
            chain=Chain.ETH,
            is_proxy=True,
            proxy_type=ProxyType.EIP1967,
            selectors=["0xa9059cbb", "0x095ea7b3"],
        )
        assert contract.is_proxy is True
        assert contract.proxy_type == ProxyType.EIP1967
        assert len(contract.selectors) == 2


class TestVulnerabilityFinding:
    """Tests for VulnerabilityFinding model."""

    def test_valid_finding(self, sample_vulnerability: VulnerabilityFinding):
        """Test creating a valid vulnerability finding."""
        assert sample_vulnerability.type == VulnerabilityType.REENTRANCY
        assert sample_vulnerability.severity == Severity.HIGH
        assert sample_vulnerability.confidence == 0.85
        assert sample_vulnerability.verified is False

    def test_confidence_bounds(self):
        """Test that confidence must be between 0 and 1."""
        with pytest.raises(ValidationError):
            VulnerabilityFinding(
                id="test",
                type=VulnerabilityType.REENTRANCY,
                severity=Severity.HIGH,
                confidence=1.5,  # Invalid
                title="Test",
                description="Test",
                location=VulnerabilityLocation(),
                impact="Test",
                source=FindingSource.STATIC,
            )

    def test_all_vulnerability_types(self):
        """Test all vulnerability types are valid."""
        for vuln_type in VulnerabilityType:
            finding = VulnerabilityFinding(
                id=f"test-{vuln_type.value}",
                type=vuln_type,
                severity=Severity.MEDIUM,
                confidence=0.5,
                title="Test",
                description="Test",
                location=VulnerabilityLocation(),
                impact="Test",
                source=FindingSource.STATIC,
            )
            assert finding.type == vuln_type


class TestAuditReport:
    """Tests for AuditReport model."""

    def test_valid_report(self, sample_vulnerability: VulnerabilityFinding):
        """Test creating a valid audit report."""
        report = AuditReport(
            address="0x742d35cc6634c0532925a3b844bc454e4438f44e",
            chain=Chain.ETH,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            findings=[sample_vulnerability],
            findings_count=FindingsCount(high=1),
            status=AuditResult.VULNERABLE,
            rag_context_used=True,
        )
        assert report.status == AuditResult.VULNERABLE
        assert len(report.findings) == 1
        assert report.findings_count.high == 1


class TestQueueItem:
    """Tests for QueueItem model."""

    def test_valid_queue_item(self, sample_queue_item: QueueItem):
        """Test creating a valid queue item."""
        assert sample_queue_item.status == QueueStatus.PENDING
        assert sample_queue_item.priority == 5

    def test_queue_status_values(self):
        """Test all queue status values."""
        for status in QueueStatus:
            item = QueueItem(
                address="0x742d35cc6634c0532925a3b844bc454e4438f44e",
                chain="eth",
                status=status,
            )
            assert item.status == status


class TestChainConfig:
    """Tests for ChainConfig model."""

    def test_valid_chain_config(self):
        """Test creating a valid chain config."""
        config = ChainConfig(
            name="Ethereum",
            chain_id=1,
            rpc_url="https://eth.drpc.org",
            explorer_url="https://etherscan.io",
            explorer_api_url="https://api.etherscan.io/api",
            native_currency="ETH",
        )
        assert config.chain_id == 1
        assert config.native_decimals == 18  # Default value


class TestEnums:
    """Tests for enum types."""

    def test_chain_values(self):
        """Test Chain enum values."""
        assert Chain.ETH.value == "eth"
        assert Chain.BSC.value == "bsc"
        assert Chain.BASE.value == "base"

    def test_severity_ordering(self):
        """Test severity values."""
        severities = [s.value for s in Severity]
        assert "critical" in severities
        assert "high" in severities
        assert "medium" in severities
        assert "low" in severities
        assert "info" in severities

    def test_proxy_types(self):
        """Test proxy type enum."""
        assert ProxyType.EIP1967.value == "eip1967"
        assert ProxyType.EIP1167.value == "eip1167"
        assert ProxyType.DIAMOND.value == "diamond"
        assert ProxyType.NONE.value == "none"
