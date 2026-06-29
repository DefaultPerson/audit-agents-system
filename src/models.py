"""
Pydantic models for audit-agents pipeline.
Migrated from backend/src/types.ts (Zod schemas).
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ============================================
# Enums
# ============================================


class ContractStatus(str, Enum):
    """Contract statuses in pipeline."""

    NEW = "new"  # Found, not yet processed
    QUEUED = "queued"  # In audit queue
    AUDITED = "audited"  # Audit complete, clean
    VULNERABLE = "vulnerable"  # Vulnerability found
    SKIP = "skip"  # Skip (honeypot, known protocol)


class PipelineStage(str, Enum):
    """Pipeline stages."""

    DISCOVERY = "discovery"
    TRIAGE = "triage"
    RESOLVE = "resolve"
    DECOMPILE = "decompile"
    ANALYZE = "analyze"
    VERIFY = "verify"
    REPORT = "report"
    MONITOR = "monitor"


class Chain(str, Enum):
    """Supported chains."""

    ETH = "eth"
    BSC = "bsc"
    BASE = "base"
    POLYGON = "polygon"
    ARBITRUM = "arbitrum"


class ProxyType(str, Enum):
    """Proxy contract types."""

    EIP1967 = "eip1967"
    EIP1167 = "eip1167"
    DIAMOND = "diamond"
    GNOSIS_SAFE = "gnosis_safe"
    CUSTOM = "custom"
    NONE = "none"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    """Vulnerability types."""

    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    INTEGER_OVERFLOW = "integer_overflow"
    UNCHECKED_CALL = "unchecked_call"
    DELEGATE_CALL = "delegate_call"
    FRONT_RUNNING = "front_running"
    DOS = "dos"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FLASH_LOAN = "flash_loan"
    OTHER = "other"


class SkipReason(str, Enum):
    """Reasons for skipping a contract during triage."""

    NO_CODE = "no_code"  # EOA or empty contract
    VERIFIED = "verified"  # Source code verified on explorer
    LOW_BALANCE = "low_balance"  # Below minimum balance threshold


class FindingSource(str, Enum):
    """Source of vulnerability finding."""

    STATIC = "static"
    RAG = "rag"
    COMBINED = "combined"


class AuditResult(str, Enum):
    """Audit result status."""

    CLEAN = "clean"
    VULNERABLE = "vulnerable"
    ERROR = "error"


class LogStatus(str, Enum):
    """Pipeline log entry status."""

    FOUND = "found"
    PASS = "pass"
    SKIP = "skip"
    FINDING = "finding"
    ERROR = "error"
    COMPLETE = "complete"


class QueueStatus(str, Enum):
    """Queue item status."""

    PENDING = "pending"
    PROCESSING = "processing"
    DONE = "done"
    FAILED = "failed"


# ============================================
# Core Models
# ============================================


class ContractTarget(BaseModel):
    """Contract target from discovery."""

    address: str = Field(..., pattern=r"^0x[a-fA-F0-9]{40}$")
    chain: Chain
    balance_usd: float = Field(alias="balanceUsd")
    balance_native: str = Field(alias="balanceNative")  # wei as string
    age: int  # days since deployment
    verified: bool
    is_proxy: bool = Field(default=False, alias="isProxy")
    status: ContractStatus
    code_hash: str | None = Field(default=None, alias="codeHash")
    found_at: datetime = Field(alias="foundAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")

    model_config = {"populate_by_name": True}

    @field_validator("address", mode="before")
    @classmethod
    def lowercase_address(cls, v: str) -> str:
        return v.lower()


class CloneFamily(BaseModel):
    """Contracts grouped by identical runtime bytecode hash."""

    bytecode_hash: str = Field(alias="bytecodeHash")
    members: list[ContractTarget]
    chains: list[Chain]
    total_value_usd: float = Field(alias="totalValueUsd")
    proxy_count: int = Field(alias="proxyCount")
    representative_address: str = Field(alias="representativeAddress")

    model_config = {"populate_by_name": True}


class TriageResult(BaseModel):
    """Triage stage result."""

    address: str
    chain: Chain
    passed: bool = Field(alias="pass")
    skip_reason: SkipReason | None = Field(default=None, alias="skipReason")
    is_proxy: bool = Field(alias="isProxy")
    proxy_implementation: str | None = Field(default=None, alias="proxyImplementation")
    code_hash: str = Field(alias="codeHash")
    code_size: int = Field(alias="codeSize")
    balance_usd: float = Field(default=0, alias="balanceUsd")
    confidence: float = Field(ge=0, le=1)

    model_config = {"populate_by_name": True}


class ResolvedContract(BaseModel):
    """Resolved contract (after proxy resolution)."""

    original_address: str = Field(alias="originalAddress")
    resolved_address: str = Field(alias="resolvedAddress")
    chain: Chain
    is_proxy: bool = Field(alias="isProxy")
    proxy_type: ProxyType | None = Field(default=None, alias="proxyType")
    abi: list[Any] | None = None
    selectors: list[str] | None = None

    model_config = {"populate_by_name": True}


class DecompiledFunction(BaseModel):
    """Single decompiled function."""

    selector: str
    signature: str | None = None
    name: str | None = None
    decompiled: str


class DecompiledContract(BaseModel):
    """Decompiled contract."""

    address: str
    chain: Chain
    functions: list[DecompiledFunction]
    storage_layout: dict[str, str] | None = Field(default=None, alias="storageLayout")
    decompiled_at: datetime = Field(alias="decompiledAt")

    model_config = {"populate_by_name": True}


class VulnerabilityLocation(BaseModel):
    """Location of vulnerability in code."""

    function: str | None = None
    selector: str | None = None
    line: int | None = None


class VulnerabilityFinding(BaseModel):
    """Vulnerability finding."""

    id: str
    type: VulnerabilityType
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    title: str
    description: str
    location: VulnerabilityLocation
    impact: str
    exploit_scenario: str | None = Field(default=None, alias="exploitScenario")
    estimated_profit: float | None = Field(default=None, alias="estimatedProfit")  # USD
    source: FindingSource
    verified: bool = False
    poc_code: str | None = Field(default=None, alias="pocCode")

    model_config = {"populate_by_name": True}


class FindingsCount(BaseModel):
    """Count of findings by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class AuditReport(BaseModel):
    """Audit report."""

    address: str
    chain: Chain
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime = Field(alias="completedAt")
    findings: list[VulnerabilityFinding]
    findings_count: FindingsCount = Field(alias="findingsCount")
    total_profit_usd: float | None = Field(default=None, alias="totalProfitUsd")
    status: AuditResult
    error_message: str | None = Field(default=None, alias="errorMessage")
    rag_context_used: bool = Field(alias="ragContextUsed")

    model_config = {"populate_by_name": True}


class PipelineLogEntry(BaseModel):
    """Pipeline log entry."""

    ts: datetime
    address: str
    chain: Chain
    stage: PipelineStage
    status: LogStatus
    reason: str | None = None
    severity: Severity | None = None
    balance_usd: float | None = Field(default=None, alias="balanceUsd")
    duration: int | None = None  # ms

    model_config = {"populate_by_name": True}


# ============================================
# RAG Models
# ============================================


class ExploitDocument(BaseModel):
    """RAG exploit document."""

    id: str
    name: str
    date: str
    chain: str
    loss_usd: float | None = Field(default=None, alias="lossUsd")
    attack_type: str = Field(alias="attackType")
    root_cause: str = Field(alias="rootCause")
    summary: str
    attack_flow: str = Field(alias="attackFlow")
    poc_code: str = Field(alias="pocCode")
    file_path: str = Field(alias="filePath")

    model_config = {"populate_by_name": True}


# ============================================
# Config Models
# ============================================


class ChainConfig(BaseModel):
    """Chain configuration."""

    name: str
    chain_id: int = Field(alias="chainId")
    rpc_url: str = Field(alias="rpcUrl")
    explorer_url: str = Field(alias="explorerUrl")
    explorer_api_url: str = Field(alias="explorerApiUrl")
    explorer_api_key: str | None = Field(default=None, alias="explorerApiKey")
    native_currency: str = Field(alias="nativeCurrency")
    native_decimals: int = Field(default=18, alias="nativeDecimals")

    model_config = {"populate_by_name": True}


# ============================================
# Pre-Audit Models
# ============================================


class PreAuditMetadata(BaseModel):
    """Pre-audit metadata."""

    bytecode_size: int = Field(alias="bytecodeSize")
    triage_duration: int = Field(alias="triageDuration")
    resolve_duration: int = Field(alias="resolveDuration")
    decompile_duration: int = Field(alias="decompileDuration")

    model_config = {"populate_by_name": True}


class PreAuditResult(BaseModel):
    """Pre-audit result (TRIAGE -> RESOLVE -> DECOMPILE without Claude)."""

    address: str
    chain: Chain
    passed: bool
    skip_reason: str | None = Field(default=None, alias="skipReason")
    resolved_address: str = Field(alias="resolvedAddress")
    is_proxy: bool = Field(alias="isProxy")
    proxy_type: ProxyType | None = Field(default=None, alias="proxyType")
    decompile_dir: str = Field(alias="decompileDir")
    dedaub_file: str | None = Field(default=None, alias="dedaubFile")
    balance_usd: float = Field(alias="balanceUsd")
    metadata: PreAuditMetadata

    model_config = {"populate_by_name": True}


# ============================================
# Parallel Audit Models
# ============================================


class InstanceResult(BaseModel):
    """Single Claude instance result from parallel audit."""

    instance_id: int = Field(alias="instanceId")
    success: bool
    report_path: str | None = Field(default=None, alias="reportPath")
    transcript_path: str | None = Field(default=None, alias="transcriptPath")
    output: str | None = None
    error: str | None = None
    duration: int | None = None

    model_config = {"populate_by_name": True}


class ParallelAuditResult(BaseModel):
    """Parallel audit result (multiple Claude instances)."""

    all_failed: bool = Field(alias="allFailed")
    report_paths: list[str] = Field(alias="reportPaths")
    transcript_paths: list[str] = Field(alias="transcriptPaths")
    instance_results: list[InstanceResult] = Field(alias="instanceResults")
    success_count: int = Field(alias="successCount")
    fail_count: int = Field(alias="failCount")

    model_config = {"populate_by_name": True}


class VerifyResult(BaseModel):
    """Unified verify result."""

    findings: list[VulnerabilityFinding]
    verified: list[VulnerabilityFinding]
    unverified: list[VulnerabilityFinding]
    poc_paths: list[str] = Field(alias="pocPaths")
    consolidated_count: int = Field(alias="consolidatedCount")  # Deduplicated findings
    verified_count: int = Field(alias="verifiedCount")

    model_config = {"populate_by_name": True}


# ============================================
# Queue Models
# ============================================


class QueueItem(BaseModel):
    """Queue item for autonomous daemon."""

    address: str
    chain: str
    balance_usd: float | None = None
    priority: int = 0
    status: QueueStatus = QueueStatus.PENDING
    added_at: datetime | None = None
    started_at: datetime | None = None
    processed_at: datetime | None = None
    result: str | None = None
    error: str | None = None


class QueueStats(BaseModel):
    """Queue statistics."""

    total: int
    pending: int
    processing: int
    done: int
    failed: int
    total_value: float = Field(alias="totalValue")
    by_chain: dict[str, int] = Field(alias="byChain")
    success_rate: int = Field(alias="successRate")

    model_config = {"populate_by_name": True}


class DbStats(BaseModel):
    """Database statistics."""

    total: int
    by_status: dict[str, int] = Field(alias="byStatus")
    by_chain: dict[str, int] = Field(alias="byChain")
    total_value_usd: float = Field(alias="totalValueUsd")

    model_config = {"populate_by_name": True}
