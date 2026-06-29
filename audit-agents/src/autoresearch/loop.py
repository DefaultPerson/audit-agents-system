"""Goal planning and consensus-gated offline loop scaffolding."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import (
    ArtifactBundle,
    AttackHypothesis,
    AuditGoal,
    ConsensusDecision,
    HypothesisStatus,
    LoopReceipt,
    LoopScratchpad,
    ResearchLoopState,
    SpecialistDomain,
    StuckSignal,
    ValidationMethod,
)
from .tools import build_cheap_fact_index

DOMAIN_OBJECTIVES: dict[SpecialistDomain, str] = {
    SpecialistDomain.AUTH_UPGRADEABILITY: (
        "Check whether privileged or upgrade paths are reachable without the expected "
        "authorization preconditions."
    ),
    SpecialistDomain.PROXY_STORAGE_DELEGATECALL: (
        "Check proxy, storage slot, delegatecall and implementation assumptions at the snapshot."
    ),
    SpecialistDomain.ACCOUNTING_SHARE_MATH: (
        "Check accounting, share math, rounding and supply/balance invariant assumptions."
    ),
    SpecialistDomain.ORACLE_PRICE_LIQUIDITY: (
        "Check oracle, price, liquidity and manipulation-cost assumptions."
    ),
    SpecialistDomain.STATE_MACHINE_LIFECYCLE: (
        "Check pause, initialization, lifecycle and state-machine transition assumptions."
    ),
    SpecialistDomain.EXTERNAL_CALLS_REENTRANCY: (
        "Check external calls, callbacks and reentrancy-sensitive paths."
    ),
}

UPGRADE_SELECTORS = {"0x3659cfe6", "0x4f1ef286"}
OWNERSHIP_SELECTORS = {"0x8da5cb5b", "0xf2fde38b", "0x715018a6"}
ORACLE_HINT_SELECTORS = {"0x50d25bcd", "0xfeaf968c", "0x9a6fc8f5"}
ERC4626_HINT_SELECTORS = {"0x6e553f65", "0xba087652", "0xb460af94", "0x2e1a7d4d"}
EXTERNAL_VALUE_SELECTORS = {"0x3ccfd60b", "0x2e1a7d4d", "0xa9059cbb"}


def plan_goals(bundle: ArtifactBundle, iteration_budget: int) -> list[AuditGoal]:
    """Create bounded specialist goals from an artifact bundle."""
    domains = list(SpecialistDomain)
    per_goal_budget = max(1, iteration_budget // len(domains))

    return [
        AuditGoal(
            id=f"goal-{index + 1:02d}-{domain.value}",
            domain=domain,
            objective=DOMAIN_OBJECTIVES[domain],
            selectors=bundle.selectors[:20],
            rationale=(
                "Generated from immutable artifact bundle; decompiler names are hints, "
                "selectors/storage/fork behavior are facts."
            ),
            iterationBudget=per_goal_budget,
        )
        for index, domain in enumerate(domains)
    ]


def passes_consensus_gate(
    hypothesis: AttackHypothesis,
    known_facts: set[str] | None = None,
) -> ConsensusDecision:
    """Check whether a hypothesis is concrete enough to build validation code."""
    missing: list[str] = []

    if not hypothesis.affected_selectors:
        missing.append("affected selector or fallback path")
    if not hypothesis.preconditions:
        missing.append("explicit preconditions")
    if not hypothesis.expected_impact:
        missing.append("expected impact")
    if not hypothesis.validation_methods:
        missing.append("validation method")
    if not hypothesis.evidence_refs:
        missing.append("supporting cheap fact")
    elif known_facts is not None:
        unknown_refs = sorted(set(hypothesis.evidence_refs) - known_facts)
        unknown_selectors = sorted(
            selector
            for selector in hypothesis.affected_selectors
            if selector.startswith("0x") and f"selector:{selector.lower()}" not in known_facts
        )
        if unknown_refs or unknown_selectors:
            missing.append("all supporting cheap facts present in artifact")

    accepted = not missing
    return ConsensusDecision(
        hypothesisId=hypothesis.id,
        accepted=accepted,
        reason=(
            "Consensus gate passed; build a verification package."
            if accepted
            else f"Consensus gate rejected; missing required facts: {', '.join(missing)}."
        ),
        missingFacts=missing,
        cheapChecks=[
            "selector lookup",
            "raw storage read",
            "cast call at pinned block",
            "recent trace/event read",
        ],
    )


def _selector_refs(bundle: ArtifactBundle, selectors: set[str]) -> list[str]:
    return [f"selector:{selector}" for selector in bundle.selectors if selector in selectors]


def _propose_hypothesis(goal: AuditGoal, bundle: ArtifactBundle) -> AttackHypothesis | None:
    """Generate a conservative, validation-only hypothesis from cheap signals."""
    selectors = set(bundle.selectors)

    if goal.domain == SpecialistDomain.AUTH_UPGRADEABILITY:
        matched = selectors & (UPGRADE_SELECTORS | OWNERSHIP_SELECTORS)
        if matched:
            return AttackHypothesis(
                id=f"hyp-{goal.id}",
                goalId=goal.id,
                domain=goal.domain,
                title="Privileged selector requires access-control validation",
                affectedSelectors=sorted(matched),
                preconditions=[
                    "privileged selector is reachable at the snapshot",
                    "authorization storage and caller assumptions are unknown",
                ],
                expectedImpact="Unauthorized upgrade or ownership change if access control is bypassable.",
                evidenceRefs=_selector_refs(bundle, matched),
                validationMethods=[ValidationMethod.FOUNDRY_FORK, ValidationMethod.SYMBOLIC],
            )

    if goal.domain == SpecialistDomain.ORACLE_PRICE_LIQUIDITY:
        matched = selectors & ORACLE_HINT_SELECTORS
        if matched:
            return AttackHypothesis(
                id=f"hyp-{goal.id}",
                goalId=goal.id,
                domain=goal.domain,
                title="Oracle or price path requires manipulation-cost validation",
                affectedSelectors=sorted(matched),
                preconditions=[
                    "price-like selector is reachable",
                    "liquidity and oracle update path must be measured on fork",
                ],
                expectedImpact="Incorrect valuation if price source can be manipulated profitably.",
                evidenceRefs=_selector_refs(bundle, matched),
                validationMethods=[ValidationMethod.FOUNDRY_FORK, ValidationMethod.ECONOMIC],
            )

    if goal.domain == SpecialistDomain.ACCOUNTING_SHARE_MATH:
        matched = selectors & ERC4626_HINT_SELECTORS
        if matched:
            return AttackHypothesis(
                id=f"hyp-{goal.id}",
                goalId=goal.id,
                domain=goal.domain,
                title="Share/accounting path requires invariant validation",
                affectedSelectors=sorted(matched),
                preconditions=[
                    "share/accounting selector is reachable",
                    "rounding and donation behavior must be checked on fork",
                ],
                expectedImpact="Incorrect shares or asset accounting if invariant is breakable.",
                evidenceRefs=_selector_refs(bundle, matched),
                validationMethods=[ValidationMethod.FOUNDRY_FORK, ValidationMethod.PROPERTY],
            )

    if goal.domain == SpecialistDomain.EXTERNAL_CALLS_REENTRANCY:
        matched = selectors & EXTERNAL_VALUE_SELECTORS
        if matched:
            return AttackHypothesis(
                id=f"hyp-{goal.id}",
                goalId=goal.id,
                domain=goal.domain,
                title="Value-moving path requires callback/reentrancy validation",
                affectedSelectors=sorted(matched),
                preconditions=[
                    "value-moving selector is reachable",
                    "external call ordering and state updates must be checked",
                ],
                expectedImpact="Funds or accounting loss if callback can violate state assumptions.",
                evidenceRefs=_selector_refs(bundle, matched),
                validationMethods=[ValidationMethod.FOUNDRY_FORK, ValidationMethod.ITYFUZZ],
            )

    return None


def load_hypotheses_file(path: str | Path) -> list[AttackHypothesis]:
    """Load externally proposed hypotheses from a JSON file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    raw_hypotheses: Any = data.get("hypotheses", []) if isinstance(data, dict) else data

    if not isinstance(raw_hypotheses, list):
        raise ValueError("Hypotheses file must contain a list or {'hypotheses': [...]}.")

    return [AttackHypothesis.model_validate(item) for item in raw_hypotheses]


def _gate_hypothesis(
    hypothesis: AttackHypothesis,
    known_facts: set[str] | None,
) -> tuple[AttackHypothesis, ConsensusDecision]:
    decision = passes_consensus_gate(hypothesis, known_facts)
    updated = hypothesis.model_copy(deep=True)
    updated.status = HypothesisStatus.CONSENSUS if decision.accepted else HypothesisStatus.REJECTED
    updated.reject_reason = None if decision.accepted else decision.reason
    return updated, decision


def _receipt_for_decision(
    *,
    iteration: int,
    goal_id: str,
    researcher_summary: str,
    decision: ConsensusDecision,
) -> LoopReceipt:
    return LoopReceipt(
        iteration=iteration,
        goalId=goal_id,
        researcherSummary=researcher_summary,
        skepticSummary=decision.reason,
        decision=decision,
        requestedContext=[] if decision.accepted else decision.cheap_checks,
    )


def _scratchpad_from_receipts(
    hypotheses: list[AttackHypothesis],
    receipts: list[LoopReceipt],
) -> LoopScratchpad:
    worked = [
        f"{hypothesis.id}: {hypothesis.title}"
        for hypothesis in hypotheses
        if hypothesis.status == HypothesisStatus.CONSENSUS
    ]
    failed = [
        f"{receipt.decision.hypothesis_id}: {receipt.decision.reason}"
        for receipt in receipts
        if not receipt.decision.accepted
    ]
    requested_context = {
        item
        for receipt in receipts
        if not receipt.decision.accepted
        for item in receipt.requested_context
    }
    blocked = sorted(
        {
            fact
            for receipt in receipts
            if not receipt.decision.accepted
            for fact in receipt.decision.missing_facts
        }
    )
    next_steps = sorted(requested_context) or [
        "build verification package for consensus hypotheses"
    ]
    return LoopScratchpad(
        worked=worked,
        failed=failed,
        next=next_steps,
        blocked=blocked,
    )


def _stuck_signals_from_receipts(
    receipts: list[LoopReceipt],
    *,
    threshold: int = 2,
) -> list[StuckSignal]:
    by_missing_fact: dict[str, list[int]] = {}
    for receipt in receipts:
        if receipt.decision.accepted:
            continue
        for missing_fact in receipt.decision.missing_facts:
            by_missing_fact.setdefault(missing_fact, []).append(receipt.iteration)

    return [
        StuckSignal(
            key=missing_fact,
            count=len(iterations),
            receiptIterations=iterations,
            suggestedAction=(
                "Request targeted cheap context or narrow the audit goal before more model debate."
            ),
        )
        for missing_fact, iterations in sorted(by_missing_fact.items())
        if len(iterations) >= threshold
    ]


def _build_state(
    *,
    bundle: ArtifactBundle,
    artifact_path: str | Path,
    iteration_budget: int,
    researcher_model: str | None,
    skeptic_model: str | None,
    goals: list[AuditGoal],
    hypotheses: list[AttackHypothesis],
    receipts: list[LoopReceipt],
    stop_reason: str,
    cost_budget_usd: float | None,
    time_budget_seconds: int | None,
) -> ResearchLoopState:
    now = datetime.now(UTC)
    return ResearchLoopState(
        targetAddress=bundle.target_address,
        chain=bundle.chain,
        artifactPath=str(artifact_path),
        iterationBudget=iteration_budget,
        researcherModel=researcher_model,
        skepticModel=skeptic_model,
        stopReason=stop_reason,
        costBudgetUsd=cost_budget_usd,
        timeBudgetSeconds=time_budget_seconds,
        goals=goals,
        hypotheses=hypotheses,
        receipts=receipts,
        scratchpad=_scratchpad_from_receipts(hypotheses, receipts),
        stuckSignals=_stuck_signals_from_receipts(receipts),
        createdAt=now,
        updatedAt=now,
    )


def run_offline_research_loop(
    bundle: ArtifactBundle,
    *,
    artifact_path: str | Path,
    iteration_budget: int,
    proposed_hypotheses: list[AttackHypothesis] | None = None,
    researcher_model: str | None = None,
    skeptic_model: str | None = None,
    known_facts: set[str] | None = None,
    cost_budget_usd: float | None = None,
    time_budget_seconds: int | None = None,
) -> ResearchLoopState:
    """
    Run an offline, deterministic loop scaffold.

    This does not claim vulnerabilities. It only converts cheap artifact signals into
    validation candidates and rejected receipts that a Pi.dev/model loop can replace.
    """
    goals = plan_goals(bundle, iteration_budget)
    known_facts = known_facts or build_cheap_fact_index(bundle)
    hypotheses: list[AttackHypothesis] = []
    receipts: list[LoopReceipt] = []

    if proposed_hypotheses is not None:
        for iteration, hypothesis in enumerate(proposed_hypotheses[:iteration_budget], start=1):
            gated, decision = _gate_hypothesis(hypothesis, known_facts)
            hypotheses.append(gated)
            receipts.append(
                _receipt_for_decision(
                    iteration=iteration,
                    goal_id=gated.goal_id,
                    researcher_summary=gated.title,
                    decision=decision,
                )
            )

        return _build_state(
            bundle=bundle,
            artifact_path=artifact_path,
            iteration_budget=iteration_budget,
            researcher_model=researcher_model,
            skeptic_model=skeptic_model,
            goals=goals,
            hypotheses=hypotheses,
            receipts=receipts,
            stop_reason="iteration_budget_reached",
            cost_budget_usd=cost_budget_usd,
            time_budget_seconds=time_budget_seconds,
        )

    for iteration, goal in enumerate(goals[:iteration_budget], start=1):
        hypothesis = _propose_hypothesis(goal, bundle)

        if hypothesis is None:
            decision = ConsensusDecision(
                hypothesisId=f"none-{goal.id}",
                accepted=False,
                reason="No cheap signal found for this bounded goal.",
                missingFacts=["target-specific signal"],
                cheapChecks=["selector lookup", "decompiler slice search", "recent trace read"],
            )
            receipts.append(
                LoopReceipt(
                    iteration=iteration,
                    goalId=goal.id,
                    researcherSummary="No concrete hypothesis proposed from current artifact.",
                    skepticSummary="Rejected because there is no selector/storage/trace support.",
                    decision=decision,
                    requestedContext=decision.cheap_checks,
                )
            )
            continue

        hypothesis, decision = _gate_hypothesis(hypothesis, known_facts)

        hypotheses.append(hypothesis)
        receipts.append(
            _receipt_for_decision(
                iteration=iteration,
                goal_id=goal.id,
                researcher_summary=hypothesis.title,
                decision=decision,
            )
        )

    return _build_state(
        bundle=bundle,
        artifact_path=artifact_path,
        iteration_budget=iteration_budget,
        researcher_model=researcher_model,
        skeptic_model=skeptic_model,
        goals=goals,
        hypotheses=hypotheses,
        receipts=receipts,
        stop_reason=(
            "consensus_ready" if any(receipt.decision.accepted for receipt in receipts)
            else "low_signal_no_consensus"
        ),
        cost_budget_usd=cost_budget_usd,
        time_budget_seconds=time_budget_seconds,
    )
