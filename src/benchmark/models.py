"""Models for benchmark corpus and scoring."""

from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ..autoresearch import AutoresearchInternalReport, ValidationStatus
from ..models import Chain, ProxyType


class BenchmarkCaseKind(str, Enum):
    """Benchmark case category."""

    KNOWN_EXPLOIT = "known_exploit"
    BENIGN_TRAP = "benign_trap"
    EDGE_CASE = "edge_case"


class BenchmarkCase(BaseModel):
    """One target in the benchmark corpus."""

    id: str
    kind: BenchmarkCaseKind
    chain: Chain
    target_address: str = Field(alias="targetAddress")
    snapshot_block: int | None = Field(default=None, alias="snapshotBlock")
    resolved_address: str | None = Field(default=None, alias="resolvedAddress")
    bytecode_path: str | None = Field(default=None, alias="bytecodePath")
    decompile_dir: str | None = Field(default=None, alias="decompileDir")
    dedaub_file: str | None = Field(default=None, alias="dedaubFile")
    selectors: list[str] = Field(default_factory=list)
    is_proxy: bool = Field(default=False, alias="isProxy")
    proxy_type: ProxyType | None = Field(default=None, alias="proxyType")
    metadata: dict[str, Any] = Field(default_factory=dict)
    expected_class: str | None = Field(default=None, alias="expectedClass")
    notes: str | None = None

    model_config = {"populate_by_name": True}

    @field_validator("target_address", mode="before")
    @classmethod
    def lowercase_address(cls, value: str) -> str:
        return value.lower()

    @field_validator("resolved_address", mode="before")
    @classmethod
    def lowercase_optional_address(cls, value: str | None) -> str | None:
        return value.lower() if value else None

    @field_validator("selectors", mode="before")
    @classmethod
    def normalize_selectors(cls, values: list[str] | None) -> list[str]:
        if not values:
            return []
        return sorted({value.lower() for value in values if value})

    def resolve_paths(self, base_dir: str | Path) -> "BenchmarkCase":
        """Resolve local fixture paths relative to the corpus file."""
        base = Path(base_dir)

        def resolve(value: str | None) -> str | None:
            if value is None:
                return None
            path = Path(value)
            return str(path if path.is_absolute() else base / path)

        return self.model_copy(
            update={
                "bytecode_path": resolve(self.bytecode_path),
                "decompile_dir": resolve(self.decompile_dir),
                "dedaub_file": resolve(self.dedaub_file),
            }
        )


class BenchmarkCorpus(BaseModel):
    """Benchmark corpus manifest."""

    schema_version: str = Field(default="evm-benchmark-corpus/v1", alias="schemaVersion")
    name: str
    cases: list[BenchmarkCase]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}


class BenchmarkScore(BaseModel):
    """Scored result for one benchmark case."""

    case_id: str = Field(alias="caseId")
    kind: BenchmarkCaseKind
    report_path: str = Field(alias="reportPath")
    consensus_count: int = Field(alias="consensusCount")
    rejected_count: int = Field(alias="rejectedCount")
    validation_count: int = Field(alias="validationCount")
    validated_findings_count: int = Field(alias="validatedFindingsCount")
    passed: bool
    reason: str

    model_config = {"populate_by_name": True}


class BenchmarkSummary(BaseModel):
    """Aggregate benchmark score."""

    corpus_name: str = Field(alias="corpusName")
    total_cases: int = Field(alias="totalCases")
    scored_cases: int = Field(alias="scoredCases")
    known_exploit_hits: int = Field(alias="knownExploitHits")
    known_exploit_total: int = Field(alias="knownExploitTotal")
    benign_false_positives: int = Field(alias="benignFalsePositives")
    benign_total: int = Field(alias="benignTotal")
    edge_case_validated: int = Field(alias="edgeCaseValidated")
    missing_case_ids: list[str] = Field(default_factory=list, alias="missingCaseIds")
    scores: list[BenchmarkScore]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}

    @property
    def known_exploit_recall(self) -> float:
        """Recall on known exploit cases."""
        if self.known_exploit_total == 0:
            return 0.0
        return self.known_exploit_hits / self.known_exploit_total

    @property
    def benign_false_positive_rate(self) -> float:
        """False-positive rate on benign traps."""
        if self.benign_total == 0:
            return 0.0
        return self.benign_false_positives / self.benign_total


def score_case(
    case: BenchmarkCase, report: AutoresearchInternalReport, report_path: str
) -> BenchmarkScore:
    """Score one case against one internal report."""
    validated = sum(
        1
        for result in report.validation_results
        if result.status == ValidationStatus.VALIDATED and result.impact_demonstrated
    )
    validation_count = len(report.validation_results)
    attempted = any(
        result.status != ValidationStatus.SKIPPED for result in report.validation_results
    )

    if case.kind == BenchmarkCaseKind.KNOWN_EXPLOIT:
        passed = validated > 0
        reason = "validated finding found" if passed else "no validated finding"
    elif case.kind == BenchmarkCaseKind.BENIGN_TRAP:
        passed = validated == 0
        reason = "no validated finding" if passed else "false positive validated finding"
    else:
        passed = attempted
        reason = "non-skipped validator result" if passed else "no validator attempted"

    return BenchmarkScore(
        caseId=case.id,
        kind=case.kind,
        reportPath=report_path,
        consensusCount=report.consensus_count,
        rejectedCount=report.rejected_count,
        validationCount=validation_count,
        validatedFindingsCount=validated,
        passed=passed,
        reason=reason,
    )
