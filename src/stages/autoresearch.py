"""Evidence-gated autoresearch stage.

This stage is intentionally internal-report only. It writes artifact bundles,
loop state and verification packages, but it does not notify owners and does
not promote hypotheses to findings without validator evidence.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..autoresearch import (
    AttackHypothesis,
    MaterialRef,
    OpenAICompatibleConfig,
    SnapshotContext,
    build_artifact_bundle,
    build_cheap_fact_index,
    materialize_cheap_tool_artifacts,
    run_offline_research_loop,
    validate_package,
    write_artifact_bundle,
    write_cheap_fact_index,
    write_cheap_tool_artifacts,
    write_internal_report,
    write_opcode_listing,
    write_rejected_memory,
    write_verification_package,
)
from ..autoresearch.model_runner import generate_model_hypotheses
from ..config import get_audit_dir, get_chain_config
from ..models import Chain, ResolvedContract


def _load_tool_json(tool_dir: Path, filename: str) -> dict[str, Any]:
    path = tool_dir / filename
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _snapshot_context_from_tool_artifacts(
    tool_dir: Path,
    *,
    observed_selectors: list[str],
) -> SnapshotContext:
    storage_reads = _load_tool_json(tool_dir, "storage_reads.json")
    storage_diffs = _load_tool_json(tool_dir, "storage_diffs.json")
    native_balances = _load_tool_json(tool_dir, "native_balances.json")
    token_balances = _load_tool_json(tool_dir, "token_balances.json")
    recent_logs = _load_tool_json(tool_dir, "recent_logs.json")
    recent_traces = _load_tool_json(tool_dir, "recent_traces.json")

    storage_samples = list(storage_reads.get("reads") or [])
    storage_samples.extend(storage_diffs.get("diffs") or [])
    proxy_admin_evidence = [
        item
        for item in storage_reads.get("reads", [])
        if isinstance(item, dict) and str(item.get("label", "")).startswith("eip1967.")
    ]
    recent_transactions = []
    seen_txs: set[str] = set()
    for log in recent_logs.get("logs", []):
        if not isinstance(log, dict):
            continue
        tx_hash = log.get("transactionHash")
        if not isinstance(tx_hash, str) or tx_hash in seen_txs:
            continue
        seen_txs.add(tx_hash)
        recent_transactions.append(
            {
                "transactionHash": tx_hash,
                "blockNumber": log.get("blockNumber"),
                "evidenceRef": log.get("evidenceRef"),
            }
        )

    return SnapshotContext(
        proxyAdminEvidence=proxy_admin_evidence,
        storageSamples=storage_samples,
        recentTransactions=recent_transactions,
        recentEvents=list(recent_logs.get("logs") or []),
        recentTraces=list(recent_traces.get("traces") or []),
        nativeBalances=list(native_balances.get("reads") or []),
        tokenBalances=list(token_balances.get("reads") or []),
        observedSelectors=observed_selectors,
    )


@dataclass(frozen=True)
class AutoresearchStageResult:
    """Paths and counts produced by one autoresearch stage run."""

    artifact_path: Path
    tool_manifest_path: Path
    state_path: Path
    rejected_memory_path: Path
    verification_package_paths: list[Path]
    validation_result_paths: list[Path]
    internal_report_path: Path
    internal_report_md_path: Path
    model_hypotheses_path: Path | None
    model_transcript_path: Path | None
    consensus_count: int
    rejected_count: int
    validated_count: int


async def run_autoresearch_stage(
    *,
    address: str,
    chain: Chain,
    resolved: ResolvedContract,
    bytecode_hex: str,
    decompile_dir: str | Path | None,
    dedaub_file: str | Path | None,
    iteration_budget: int,
    snapshot_block: int | None = None,
    run_validators: bool = True,
    proposed_hypotheses: list[AttackHypothesis] | None = None,
    researcher_model: str | None = None,
    skeptic_model: str | None = None,
    materialize_tools: bool = True,
    audit_dir: str | Path | None = None,
    cost_budget_usd: float | None = None,
    time_budget_seconds: int | None = None,
    model_handoff_config: OpenAICompatibleConfig | None = None,
) -> AutoresearchStageResult:
    """Build artifact bundle, run bounded loop and write verification packages."""
    chain_config = get_chain_config(chain.value)
    audit_dir = Path(audit_dir) if audit_dir else get_audit_dir(chain.value, address)
    artifacts_dir = audit_dir / "artifacts"
    loop_dir = audit_dir / "autoresearch"
    verification_dir = audit_dir / "verification"
    report_dir = audit_dir / "reports"

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    runtime_bytecode_path = artifacts_dir / "runtime_bytecode.hex"
    runtime_bytecode_path.write_text(
        bytecode_hex.lower().removeprefix("0x") + "\n",
        encoding="utf-8",
    )
    opcode_listing_path = write_opcode_listing(
        bytecode_hex,
        artifacts_dir / "runtime_opcodes.txt",
    )

    bundle = build_artifact_bundle(
        chain=chain,
        chain_id=chain_config.chain_id,
        snapshot_block=snapshot_block,
        target_address=address,
        resolved_address=resolved.resolved_address,
        bytecode_hex=bytecode_hex,
        is_proxy=resolved.is_proxy,
        proxy_type=resolved.proxy_type,
        selectors=resolved.selectors or [],
        decompile_dir=decompile_dir,
        dedaub_file=dedaub_file,
        runtime_bytecode_path=runtime_bytecode_path,
        opcode_listing_path=opcode_listing_path,
        tool_versions={"artifact_builder": "v1"},
    )

    artifact_path = write_artifact_bundle(bundle, artifacts_dir / "artifact_bundle.json")
    cheap_tools_dir = artifacts_dir / "cheap_tools"
    tool_manifest_path = write_cheap_tool_artifacts(bundle, cheap_tools_dir)
    if materialize_tools:
        tool_manifest_path = await materialize_cheap_tool_artifacts(
            bundle,
            cheap_tools_dir,
            rpc_url=chain_config.rpc_url,
        )
    bundle.materials.append(
        MaterialRef(
            kind="cheap_tool_artifacts",
            path=str(cheap_tools_dir),
            description="Selector, storage, balance, call, log, trace and RAG tool artifacts.",
        )
    )
    bundle.snapshot_context = _snapshot_context_from_tool_artifacts(
        cheap_tools_dir,
        observed_selectors=bundle.selectors,
    )
    artifact_path = write_artifact_bundle(bundle, artifacts_dir / "artifact_bundle.json")
    write_cheap_fact_index(
        bundle,
        artifacts_dir / "cheap_facts.json",
        materialized_tool_dir=cheap_tools_dir,
    )
    known_facts = build_cheap_fact_index(bundle, materialized_tool_dir=cheap_tools_dir)
    model_hypotheses_path: Path | None = None
    model_transcript_path: Path | None = None
    if proposed_hypotheses is None and model_handoff_config is not None:
        handoff = await generate_model_hypotheses(
            bundle=bundle,
            cheap_facts=sorted(known_facts),
            output_dir=loop_dir / "model_handoff",
            config=model_handoff_config,
        )
        proposed_hypotheses = handoff.hypotheses
        researcher_model = handoff.researcher_model
        skeptic_model = handoff.skeptic_model
        model_hypotheses_path = handoff.hypotheses_path
        model_transcript_path = handoff.transcript_path
    state = run_offline_research_loop(
        bundle,
        artifact_path=artifact_path,
        iteration_budget=iteration_budget,
        proposed_hypotheses=proposed_hypotheses,
        researcher_model=researcher_model,
        skeptic_model=skeptic_model,
        known_facts=known_facts,
        cost_budget_usd=cost_budget_usd,
        time_budget_seconds=time_budget_seconds,
    )

    loop_dir.mkdir(parents=True, exist_ok=True)
    state_path = loop_dir / "loop_state.json"
    state_path.write_text(
        state.model_dump_json(by_alias=True, indent=2) + "\n",
        encoding="utf-8",
    )
    rejected_memory_path = write_rejected_memory(state, loop_dir / "rejected_hypotheses.jsonl")

    packages = [
        write_verification_package(
            bundle=bundle,
            hypothesis=hypothesis,
            artifact_path=artifact_path,
            output_dir=verification_dir,
        )
        for hypothesis in state.consensus_hypotheses
    ]

    validation_results = []
    validation_result_paths: list[Path] = []
    if run_validators:
        for package in packages:
            package_results = await validate_package(package, cwd=audit_dir)
            validation_results.extend(package_results)
            result_path = Path(package.package_dir) / "validation_results.json"
            result_path.write_text(
                "[\n"
                + ",\n".join(
                    result.model_dump_json(by_alias=True, indent=2) for result in package_results
                )
                + "\n]\n",
                encoding="utf-8",
            )
            validation_result_paths.append(result_path)

    report, report_json_path, report_md_path = write_internal_report(
        target_address=address,
        chain=chain.value,
        snapshot_block=snapshot_block,
        artifact_path=artifact_path,
        state_path=state_path,
        researcher_model=state.researcher_model,
        skeptic_model=state.skeptic_model,
        consensus_count=len(state.consensus_hypotheses),
        rejected_count=len(state.rejected_hypotheses),
        verification_package_paths=[Path(package.package_dir) for package in packages],
        validation_results=validation_results,
        rejected_receipts=state.rejected_receipts,
        output_dir=report_dir,
    )

    return AutoresearchStageResult(
        artifact_path=artifact_path,
        tool_manifest_path=tool_manifest_path,
        state_path=state_path,
        rejected_memory_path=rejected_memory_path,
        verification_package_paths=[Path(package.package_dir) for package in packages],
        validation_result_paths=validation_result_paths,
        internal_report_path=report_json_path,
        internal_report_md_path=report_md_path,
        model_hypotheses_path=model_hypotheses_path,
        model_transcript_path=model_transcript_path,
        consensus_count=len(state.consensus_hypotheses),
        rejected_count=len(state.rejected_receipts),
        validated_count=report.validated_findings_count,
    )
