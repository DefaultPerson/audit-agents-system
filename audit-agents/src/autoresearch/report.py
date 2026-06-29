"""Internal report writer for autoresearch runs."""

import json
from pathlib import Path

from .models import (
    AutoresearchInternalReport,
    LoopReceipt,
    RejectedHypothesisSummary,
    ValidationResult,
    ValidationStatus,
)


def _markdown(report: AutoresearchInternalReport) -> str:
    validated = [
        result
        for result in report.validation_results
        if result.status == ValidationStatus.VALIDATED and result.impact_demonstrated
    ]
    validation_lines = "\n".join(
        f"- `{result.hypothesis_id}`: `{result.status.value}` - {result.reason}"
        for result in report.validation_results
    )
    if not validation_lines:
        validation_lines = "- no validation results"

    rejected_lines = "\n".join(
        f"- `{item.hypothesis_id}` in `{item.goal_id}`: {item.reason}"
        for item in report.rejected_hypotheses
    )
    if not rejected_lines:
        rejected_lines = "- no rejected hypotheses"

    return f"""# Internal autoresearch report

## Target

- Chain: `{report.chain.value}`
- Target: `{report.target_address}`
- Snapshot block: `{report.snapshot_block or "not recorded"}`
- Artifact: `{report.artifact_path}`
- Loop state: `{report.state_path}`
- Researcher model: `{report.researcher_model or "not recorded"}`
- Skeptic model: `{report.skeptic_model or "not recorded"}`

## Summary

- Consensus hypotheses: {report.consensus_count}
- Rejected hypotheses: {report.rejected_count}
- Verification packages: {len(report.verification_packages)}
- Validated findings: {len(validated)}
- Disclosure allowed: {str(report.disclosure_allowed).lower()}

## Validation Results

{validation_lines}

## Rejected Hypotheses

{rejected_lines}

## Rule

This is an internal report. Do not contact contract owners or publish findings
until validated evidence is manually reviewed and disclosure is explicitly
approved.
"""


def write_internal_report(
    *,
    target_address: str,
    chain: str,
    snapshot_block: int | None,
    artifact_path: str | Path,
    state_path: str | Path,
    researcher_model: str | None,
    skeptic_model: str | None,
    consensus_count: int,
    rejected_count: int,
    verification_package_paths: list[Path],
    validation_results: list[ValidationResult],
    rejected_receipts: list[LoopReceipt] | None = None,
    output_dir: str | Path,
) -> tuple[AutoresearchInternalReport, Path, Path]:
    """Write machine-readable and markdown internal reports."""
    from ..models import Chain

    validated_count = sum(
        1
        for result in validation_results
        if result.status == ValidationStatus.VALIDATED and result.impact_demonstrated
    )
    rejected_hypotheses = [
        RejectedHypothesisSummary(
            goalId=receipt.goal_id,
            hypothesisId=receipt.decision.hypothesis_id,
            reason=receipt.decision.reason,
            missingFacts=receipt.decision.missing_facts,
            requestedContext=receipt.requested_context,
        )
        for receipt in rejected_receipts or []
    ]
    report = AutoresearchInternalReport(
        targetAddress=target_address,
        chain=Chain(chain),
        snapshotBlock=snapshot_block,
        artifactPath=str(artifact_path),
        statePath=str(state_path),
        researcherModel=researcher_model,
        skepticModel=skeptic_model,
        consensusCount=consensus_count,
        rejectedCount=rejected_count,
        verificationPackages=[str(path) for path in verification_package_paths],
        validationResults=validation_results,
        rejectedHypotheses=rejected_hypotheses,
        validatedFindingsCount=validated_count,
        disclosureAllowed=False,
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    json_path = output_path / "internal_report.json"
    md_path = output_path / "internal_report.md"

    json_path.write_text(
        json.dumps(report.model_dump(by_alias=True, mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(_markdown(report), encoding="utf-8")
    return report, json_path, md_path
