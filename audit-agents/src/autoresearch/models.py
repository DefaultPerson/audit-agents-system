"""Models for evidence-gated autoresearch state."""

from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ..models import Chain, ProxyType


class SpecialistDomain(str, Enum):
    """Bounded audit domains used as goals, not permanent autonomous agents."""

    AUTH_UPGRADEABILITY = "auth_upgradeability"
    PROXY_STORAGE_DELEGATECALL = "proxy_storage_delegatecall"
    ACCOUNTING_SHARE_MATH = "accounting_share_math"
    ORACLE_PRICE_LIQUIDITY = "oracle_price_liquidity"
    STATE_MACHINE_LIFECYCLE = "state_machine_lifecycle"
    EXTERNAL_CALLS_REENTRANCY = "external_calls_reentrancy"


class ValidationMethod(str, Enum):
    """Supported validation backends for a consensus hypothesis."""

    FOUNDRY_FORK = "foundry_fork"
    ITYFUZZ = "ityfuzz"
    SYMBOLIC = "symbolic"
    PROPERTY = "property"
    ECONOMIC = "economic"
    MANUAL = "manual"


class ValidatorKind(str, Enum):
    """Concrete validator implementation."""

    ECONOMIC = "economic"
    FOUNDRY = "foundry"
    ITYFUZZ = "ityfuzz"
    PROPERTY = "property"
    SYMBOLIC = "symbolic"


class ValidationStatus(str, Enum):
    """Outcome of running a validator against a verification package."""

    SKIPPED = "skipped"
    ERROR = "error"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    VALIDATED = "validated"


class HypothesisStatus(str, Enum):
    """Lifecycle for a hypothesis inside the research loop."""

    PROPOSED = "proposed"
    REJECTED = "rejected"
    CONSENSUS = "consensus"
    VALIDATED = "validated"
    INVALIDATED = "invalidated"


class MaterialRef(BaseModel):
    """A file or generated artifact available to the loop."""

    kind: str
    path: str
    description: str | None = None


class SnapshotContext(BaseModel):
    """First-class snapshot facts attached to an artifact bundle."""

    deployer_address: str | None = Field(default=None, alias="deployerAddress")
    labels: list[str] = Field(default_factory=list)
    proxy_admin_evidence: list[dict[str, Any]] = Field(
        default_factory=list, alias="proxyAdminEvidence"
    )
    storage_samples: list[dict[str, Any]] = Field(default_factory=list, alias="storageSamples")
    storage_layout: dict[str, Any] | None = Field(default=None, alias="storageLayout")
    recent_transactions: list[dict[str, Any]] = Field(
        default_factory=list, alias="recentTransactions"
    )
    recent_events: list[dict[str, Any]] = Field(default_factory=list, alias="recentEvents")
    recent_traces: list[dict[str, Any]] = Field(default_factory=list, alias="recentTraces")
    native_balances: list[dict[str, Any]] = Field(default_factory=list, alias="nativeBalances")
    token_balances: list[dict[str, Any]] = Field(default_factory=list, alias="tokenBalances")
    observed_selectors: list[str] = Field(default_factory=list, alias="observedSelectors")

    model_config = {"populate_by_name": True}

    @field_validator("deployer_address", mode="before")
    @classmethod
    def lowercase_optional_address(cls, value: str | None) -> str | None:
        return value.lower() if value else None

    @field_validator("observed_selectors", mode="before")
    @classmethod
    def normalize_observed_selectors(cls, values: list[str] | None) -> list[str]:
        if not values:
            return []
        return sorted({value.lower() for value in values if value})


class ArtifactBundle(BaseModel):
    """Immutable input bundle for one target at one snapshot."""

    schema_version: str = Field(default="evm-artifact-bundle/v1", alias="schemaVersion")
    chain: Chain
    chain_id: int = Field(alias="chainId")
    snapshot_block: int | None = Field(default=None, alias="snapshotBlock")
    target_address: str = Field(alias="targetAddress")
    resolved_address: str = Field(alias="resolvedAddress")
    is_proxy: bool = Field(alias="isProxy")
    proxy_type: ProxyType | None = Field(default=None, alias="proxyType")
    runtime_bytecode_hash: str = Field(alias="runtimeBytecodeHash")
    runtime_bytecode_size: int = Field(alias="runtimeBytecodeSize")
    selectors: list[str] = Field(default_factory=list)
    snapshot_context: SnapshotContext = Field(default_factory=SnapshotContext, alias="snapshotContext")
    materials: list[MaterialRef] = Field(default_factory=list)
    tool_versions: dict[str, str] = Field(default_factory=dict, alias="toolVersions")
    tool_errors: dict[str, str] = Field(default_factory=dict, alias="toolErrors")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}

    @field_validator("target_address", "resolved_address", mode="before")
    @classmethod
    def lowercase_address(cls, value: str) -> str:
        return value.lower()

    @field_validator("selectors", mode="before")
    @classmethod
    def normalize_selectors(cls, values: list[str] | None) -> list[str]:
        if not values:
            return []
        return sorted({value.lower() for value in values if value})


class AuditGoal(BaseModel):
    """Bounded work item generated from an artifact bundle."""

    id: str
    domain: SpecialistDomain
    objective: str
    selectors: list[str] = Field(default_factory=list)
    rationale: str
    iteration_budget: int = Field(default=1, alias="iterationBudget")

    model_config = {"populate_by_name": True}


class AttackHypothesis(BaseModel):
    """Candidate vulnerability hypothesis before validation."""

    id: str
    goal_id: str = Field(alias="goalId")
    domain: SpecialistDomain
    title: str
    affected_selectors: list[str] = Field(default_factory=list, alias="affectedSelectors")
    preconditions: list[str] = Field(default_factory=list)
    expected_impact: str = Field(alias="expectedImpact")
    evidence_refs: list[str] = Field(default_factory=list, alias="evidenceRefs")
    validation_methods: list[ValidationMethod] = Field(
        default_factory=list, alias="validationMethods"
    )
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    reject_reason: str | None = Field(default=None, alias="rejectReason")

    model_config = {"populate_by_name": True}


class ConsensusDecision(BaseModel):
    """Skeptic decision for one hypothesis."""

    hypothesis_id: str = Field(alias="hypothesisId")
    accepted: bool
    reason: str
    missing_facts: list[str] = Field(default_factory=list, alias="missingFacts")
    cheap_checks: list[str] = Field(default_factory=list, alias="cheapChecks")

    model_config = {"populate_by_name": True}


class LoopReceipt(BaseModel):
    """Per-iteration receipt persisted for resume/debugging."""

    iteration: int
    goal_id: str = Field(alias="goalId")
    researcher_summary: str = Field(alias="researcherSummary")
    skeptic_summary: str = Field(alias="skepticSummary")
    decision: ConsensusDecision
    requested_context: list[str] = Field(default_factory=list, alias="requestedContext")

    model_config = {"populate_by_name": True}


class LoopScratchpad(BaseModel):
    """Pi.dev-style disk-backed scratchpad summary."""

    worked: list[str] = Field(default_factory=list)
    failed: list[str] = Field(default_factory=list)
    next: list[str] = Field(default_factory=list)
    blocked: list[str] = Field(default_factory=list)


class StuckSignal(BaseModel):
    """Repeated failure signal that should trigger parent replanning."""

    key: str
    count: int
    receipt_iterations: list[int] = Field(alias="receiptIterations")
    suggested_action: str = Field(alias="suggestedAction")

    model_config = {"populate_by_name": True}


class ResearchLoopState(BaseModel):
    """Disk-backed state for one autoresearch run."""

    target_address: str = Field(alias="targetAddress")
    chain: Chain
    artifact_path: str = Field(alias="artifactPath")
    iteration_budget: int = Field(alias="iterationBudget")
    researcher_model: str | None = Field(default=None, alias="researcherModel")
    skeptic_model: str | None = Field(default=None, alias="skepticModel")
    stop_reason: str = Field(alias="stopReason")
    cost_budget_usd: float | None = Field(default=None, alias="costBudgetUsd")
    time_budget_seconds: int | None = Field(default=None, alias="timeBudgetSeconds")
    goals: list[AuditGoal]
    hypotheses: list[AttackHypothesis] = Field(default_factory=list)
    receipts: list[LoopReceipt] = Field(default_factory=list)
    scratchpad: LoopScratchpad = Field(default_factory=LoopScratchpad)
    stuck_signals: list[StuckSignal] = Field(default_factory=list, alias="stuckSignals")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="updatedAt")

    model_config = {"populate_by_name": True}

    @property
    def consensus_hypotheses(self) -> list[AttackHypothesis]:
        """Hypotheses that passed the consensus gate."""
        return [h for h in self.hypotheses if h.status == HypothesisStatus.CONSENSUS]

    @property
    def rejected_hypotheses(self) -> list[AttackHypothesis]:
        """Hypotheses rejected before validation."""
        return [h for h in self.hypotheses if h.status == HypothesisStatus.REJECTED]

    @property
    def rejected_receipts(self) -> list[LoopReceipt]:
        """Receipts rejected by the skeptic gate, including no-signal goals."""
        return [receipt for receipt in self.receipts if not receipt.decision.accepted]


class VerificationPackage(BaseModel):
    """Files generated for validating exactly one consensus hypothesis."""

    hypothesis_id: str = Field(alias="hypothesisId")
    artifact_path: str = Field(alias="artifactPath")
    package_dir: str = Field(alias="packageDir")
    validation_methods: list[ValidationMethod] = Field(alias="validationMethods")
    foundry_test_path: str | None = Field(default=None, alias="foundryTestPath")
    ityfuzz_plan_path: str | None = Field(default=None, alias="ityfuzzPlanPath")
    ityfuzz_script_path: str | None = Field(default=None, alias="ityfuzzScriptPath")
    evidence_manifest_path: str = Field(alias="evidenceManifestPath")
    instructions_path: str = Field(alias="instructionsPath")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}

    @field_validator(
        "package_dir",
        "artifact_path",
        "foundry_test_path",
        "ityfuzz_plan_path",
        "ityfuzz_script_path",
        "evidence_manifest_path",
        "instructions_path",
    )
    @classmethod
    def normalize_paths(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return str(Path(value))


class ValidationResult(BaseModel):
    """Validator result for exactly one verification package."""

    hypothesis_id: str = Field(alias="hypothesisId")
    package_dir: str = Field(alias="packageDir")
    validator: ValidatorKind
    status: ValidationStatus
    impact_demonstrated: bool = Field(alias="impactDemonstrated")
    reason: str
    command: list[str] = Field(default_factory=list)
    output_path: str | None = Field(default=None, alias="outputPath")
    duration_ms: int = Field(default=0, alias="durationMs")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}


class RejectedHypothesisSummary(BaseModel):
    """Machine-readable memory for a hypothesis or goal rejected before validation."""

    goal_id: str = Field(alias="goalId")
    hypothesis_id: str = Field(alias="hypothesisId")
    reason: str
    missing_facts: list[str] = Field(default_factory=list, alias="missingFacts")
    requested_context: list[str] = Field(default_factory=list, alias="requestedContext")

    model_config = {"populate_by_name": True}


class AutoresearchInternalReport(BaseModel):
    """Internal report for one autoresearch run."""

    target_address: str = Field(alias="targetAddress")
    chain: Chain
    snapshot_block: int | None = Field(default=None, alias="snapshotBlock")
    artifact_path: str = Field(alias="artifactPath")
    state_path: str = Field(alias="statePath")
    researcher_model: str | None = Field(default=None, alias="researcherModel")
    skeptic_model: str | None = Field(default=None, alias="skepticModel")
    consensus_count: int = Field(alias="consensusCount")
    rejected_count: int = Field(alias="rejectedCount")
    verification_packages: list[str] = Field(default_factory=list, alias="verificationPackages")
    validation_results: list[ValidationResult] = Field(
        default_factory=list, alias="validationResults"
    )
    rejected_hypotheses: list[RejectedHypothesisSummary] = Field(
        default_factory=list, alias="rejectedHypotheses"
    )
    validated_findings_count: int = Field(default=0, alias="validatedFindingsCount")
    disclosure_allowed: bool = Field(default=False, alias="disclosureAllowed")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}
