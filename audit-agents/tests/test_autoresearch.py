"""Tests for evidence-gated autoresearch primitives."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.autoresearch import (
    HypothesisStatus,
    OpenAICompatibleConfig,
    SpecialistDomain,
    ValidationMethod,
    ValidationStatus,
    build_artifact_bundle,
    build_cheap_fact_index,
    build_cheap_tool_manifest,
    collect_materialized_facts,
    load_artifact_bundle,
    load_hypotheses_file,
    load_rejected_memory,
    materialize_cheap_tool_artifacts,
    opcode_listing,
    passes_consensus_gate,
    plan_goals,
    run_offline_research_loop,
    validate_economic_package,
    validate_foundry_package,
    validate_ityfuzz_package,
    validate_package,
    validate_property_package,
    validate_symbolic_package,
    write_artifact_bundle,
    write_rejected_memory,
    write_verification_package,
)
from src.autoresearch.models import AttackHypothesis
from src.models import Chain, ProxyType, ResolvedContract
from src.stages.autoresearch import run_autoresearch_stage


def _sample_bundle():
    return build_artifact_bundle(
        chain=Chain.ETH,
        chain_id=1,
        target_address="0x742D35CC6634C0532925A3B844BC454E4438F44E",
        resolved_address="0x742D35CC6634C0532925A3B844BC454E4438F44E",
        bytecode_hex="0x6001600055",
        is_proxy=True,
        proxy_type=ProxyType.EIP1967,
        selectors=["0x3659CFE6", "0x8DA5CB5B"],
        snapshot_block=123,
        decompile_dir="audits/eth_target/decompile",
        dedaub_file="audits/eth_target/decompile/Contract.sol",
    )


def test_artifact_bundle_round_trip(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    path = write_artifact_bundle(bundle, tmp_path / "artifact_bundle.json")

    loaded = load_artifact_bundle(path)

    assert loaded.target_address == "0x742d35cc6634c0532925a3b844bc454e4438f44e"
    assert loaded.runtime_bytecode_hash.startswith("0x")
    assert loaded.runtime_bytecode_size == 5
    assert loaded.selectors == ["0x3659cfe6", "0x8da5cb5b"]
    assert loaded.materials[0].kind == "decompile_dir"


def test_opcode_listing_is_deterministic() -> None:
    listing = opcode_listing("0x6001600055")

    assert listing.splitlines() == [
        "pc opcode argument",
        "0x0000 PUSH1 0x01",
        "0x0002 PUSH1 0x00",
        "0x0004 SSTORE",
    ]


def test_plan_goals_creates_specialist_domains() -> None:
    goals = plan_goals(_sample_bundle(), iteration_budget=12)

    assert len(goals) == len(SpecialistDomain)
    assert {goal.domain for goal in goals} == set(SpecialistDomain)
    assert all(goal.iteration_budget == 2 for goal in goals)


def test_consensus_gate_rejects_missing_facts() -> None:
    hypothesis = AttackHypothesis(
        id="hyp-empty",
        goalId="goal-1",
        domain=SpecialistDomain.AUTH_UPGRADEABILITY,
        title="Too vague",
        expectedImpact="",
    )

    decision = passes_consensus_gate(hypothesis)

    assert decision.accepted is False
    assert "affected selector or fallback path" in decision.missing_facts
    assert "validation method" in decision.missing_facts


def test_offline_loop_promotes_only_consensus_candidates(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")

    state = run_offline_research_loop(
        bundle,
        artifact_path=artifact_path,
        iteration_budget=6,
    )

    assert state.hypotheses
    assert state.consensus_hypotheses
    assert all(h.status == HypothesisStatus.CONSENSUS for h in state.consensus_hypotheses)
    assert len(state.receipts) == 6
    assert state.scratchpad.worked
    assert "selector lookup" in state.scratchpad.next
    assert state.stop_reason == "consensus_ready"


def test_external_hypotheses_file_is_gated(tmp_path: Path) -> None:
    path = tmp_path / "hypotheses.json"
    path.write_text(
        json.dumps(
            {
                "hypotheses": [
                    {
                        "id": "hyp-valid",
                        "goalId": "goal-auth",
                        "domain": "auth_upgradeability",
                        "title": "Upgrade selector might be callable",
                        "affectedSelectors": ["0x3659cfe6"],
                        "preconditions": ["upgrade selector is reachable"],
                        "expectedImpact": "Unauthorized upgrade if auth is bypassable.",
                        "evidenceRefs": ["selector:0x3659cfe6"],
                        "validationMethods": ["foundry_fork"],
                    },
                    {
                        "id": "hyp-vague",
                        "goalId": "goal-auth",
                        "domain": "auth_upgradeability",
                        "title": "Something is suspicious",
                        "expectedImpact": "",
                    },
                    {
                        "id": "hyp-fake-evidence",
                        "goalId": "goal-auth",
                        "domain": "auth_upgradeability",
                        "title": "References a selector outside the artifact",
                        "affectedSelectors": ["0xffffffff"],
                        "preconditions": ["selector is claimed reachable"],
                        "expectedImpact": "Unauthorized upgrade if auth is bypassable.",
                        "evidenceRefs": ["selector:0xffffffff"],
                        "validationMethods": ["foundry_fork"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    hypotheses = load_hypotheses_file(path)
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")

    state = run_offline_research_loop(
        bundle,
        artifact_path=artifact_path,
        iteration_budget=10,
        proposed_hypotheses=hypotheses,
    )

    assert len(state.hypotheses) == 3
    assert state.hypotheses[0].status == HypothesisStatus.CONSENSUS
    assert state.hypotheses[1].status == HypothesisStatus.REJECTED
    assert state.hypotheses[1].reject_reason
    assert state.hypotheses[2].status == HypothesisStatus.REJECTED
    assert "artifact" in (state.hypotheses[2].reject_reason or "")
    assert state.scratchpad.worked == ["hyp-valid: Upgrade selector might be callable"]
    assert len(state.scratchpad.failed) == 2
    assert "expected impact" in state.scratchpad.blocked
    assert state.stuck_signals == []


def test_loop_state_records_scratchpad_and_stuck_signals(tmp_path: Path) -> None:
    bundle = build_artifact_bundle(
        chain=Chain.ETH,
        chain_id=1,
        target_address="0x742d35cc6634c0532925a3b844bc454e4438f44e",
        resolved_address="0x742d35cc6634c0532925a3b844bc454e4438f44e",
        bytecode_hex="0x6001600055",
        is_proxy=False,
        proxy_type=ProxyType.NONE,
        selectors=[],
        snapshot_block=123,
    )
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")

    state = run_offline_research_loop(
        bundle,
        artifact_path=artifact_path,
        iteration_budget=3,
        cost_budget_usd=1.5,
        time_budget_seconds=60,
    )

    assert state.scratchpad.worked == []
    assert len(state.scratchpad.failed) == 3
    assert state.scratchpad.blocked == ["target-specific signal"]
    assert state.stop_reason == "low_signal_no_consensus"
    assert state.cost_budget_usd == 1.5
    assert state.time_budget_seconds == 60
    assert state.stuck_signals
    assert state.stuck_signals[0].key == "target-specific signal"
    assert state.stuck_signals[0].receipt_iterations == [1, 2, 3]


def test_write_verification_package(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")
    hypothesis = AttackHypothesis(
        id="hyp-upgrade",
        goalId="goal-auth",
        domain=SpecialistDomain.AUTH_UPGRADEABILITY,
        title="Privileged selector requires access-control validation",
        affectedSelectors=["0x3659cfe6"],
        preconditions=["upgrade selector is reachable"],
        expectedImpact="Unauthorized upgrade if access control is bypassable.",
        evidenceRefs=["selector:0x3659cfe6"],
        validationMethods=[ValidationMethod.FOUNDRY_FORK],
        status=HypothesisStatus.CONSENSUS,
    )

    package = write_verification_package(
        bundle=bundle,
        hypothesis=hypothesis,
        artifact_path=artifact_path,
        output_dir=tmp_path / "verification",
    )

    package_dir = Path(package.package_dir)
    assert package_dir.exists()
    foundry_test = Path(package.foundry_test_path or "").read_text()
    assert foundry_test.count("A passing empty test") == 1
    assert "forge-std" not in foundry_test
    assert 'vm.createSelectFork(vm.envString("ETH_RPC_URL"), 123);' in foundry_test
    assert package.evidence_manifest_path
    evidence_manifest = json.loads(Path(package.evidence_manifest_path).read_text())
    assert evidence_manifest["status"] == "planned"
    assert {item["role"] for item in evidence_manifest["files"]} >= {
        "foundry_test",
        "hypothesis",
        "instructions",
        "worker_receipt",
    }
    worker_receipt = json.loads((package_dir / "worker_receipt.json").read_text())
    assert worker_receipt["workerScope"] == "one_consensus_hypothesis"
    assert worker_receipt["promotionRule"].startswith("Worker output is not validation evidence")
    data = json.loads((package_dir / "hypothesis.json").read_text())
    assert data["status"] == "consensus"


@pytest.mark.asyncio
async def test_validate_foundry_package_skips_scaffold(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")
    hypothesis = AttackHypothesis(
        id="hyp-upgrade",
        goalId="goal-auth",
        domain=SpecialistDomain.AUTH_UPGRADEABILITY,
        title="Privileged selector requires access-control validation",
        affectedSelectors=["0x3659cfe6"],
        preconditions=["upgrade selector is reachable"],
        expectedImpact="Unauthorized upgrade if access control is bypassable.",
        evidenceRefs=["selector:0x3659cfe6"],
        validationMethods=[ValidationMethod.FOUNDRY_FORK],
        status=HypothesisStatus.CONSENSUS,
    )
    package = write_verification_package(
        bundle=bundle,
        hypothesis=hypothesis,
        artifact_path=artifact_path,
        output_dir=tmp_path / "verification",
    )

    result = await validate_foundry_package(package, cwd=tmp_path)

    assert result.status == ValidationStatus.SKIPPED
    assert result.impact_demonstrated is False
    assert "scaffold" in result.reason.lower()


@pytest.mark.asyncio
async def test_validate_package_records_unsupported_methods(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")
    hypothesis = AttackHypothesis(
        id="hyp-oracle",
        goalId="goal-oracle",
        domain=SpecialistDomain.ORACLE_PRICE_LIQUIDITY,
        title="Oracle path needs economic validation",
        affectedSelectors=["0x50d25bcd"],
        preconditions=["oracle selector is reachable"],
        expectedImpact="Price manipulation may be profitable.",
        evidenceRefs=["selector:0x50d25bcd"],
        validationMethods=[ValidationMethod.FOUNDRY_FORK, ValidationMethod.ECONOMIC],
        status=HypothesisStatus.CONSENSUS,
    )
    package = write_verification_package(
        bundle=bundle,
        hypothesis=hypothesis,
        artifact_path=artifact_path,
        output_dir=tmp_path / "verification",
    )

    results = await validate_package(package, cwd=tmp_path)

    assert [result.validator.value for result in results] == ["foundry", "economic"]
    assert [result.status for result in results] == [
        ValidationStatus.SKIPPED,
        ValidationStatus.SKIPPED,
    ]
    assert results[1].output_path
    assert Path(results[1].output_path).name == "economic_validation_plan.json"


def test_validate_economic_package_writes_requirements(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")
    hypothesis = AttackHypothesis(
        id="hyp-economic",
        goalId="goal-oracle",
        domain=SpecialistDomain.ORACLE_PRICE_LIQUIDITY,
        title="Economic exploit needs profit validation",
        affectedSelectors=["0x50d25bcd"],
        preconditions=["oracle path is reachable"],
        expectedImpact="Attacker may extract positive profit after gas.",
        evidenceRefs=["selector:0x50d25bcd"],
        validationMethods=[ValidationMethod.ECONOMIC],
        status=HypothesisStatus.CONSENSUS,
    )
    package = write_verification_package(
        bundle=bundle,
        hypothesis=hypothesis,
        artifact_path=artifact_path,
        output_dir=tmp_path / "verification",
    )

    result = validate_economic_package(package)

    assert result.validator.value == "economic"
    assert result.status == ValidationStatus.SKIPPED
    assert result.impact_demonstrated is False
    assert result.output_path
    plan = json.loads(Path(result.output_path).read_text())
    assert "profit_after_gas" in plan["requiredChecks"]
    assert "positive expected profit" in plan["promotionRule"]


def test_validate_economic_package_runs_optional_script_with_evidence(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")
    hypothesis = AttackHypothesis(
        id="hyp-economic-script",
        goalId="goal-oracle",
        domain=SpecialistDomain.ORACLE_PRICE_LIQUIDITY,
        title="Economic exploit has executable profit proof",
        affectedSelectors=["0x50d25bcd"],
        preconditions=["oracle path is reachable"],
        expectedImpact="Attacker extracts positive profit after gas.",
        evidenceRefs=["selector:0x50d25bcd"],
        validationMethods=[ValidationMethod.ECONOMIC],
        status=HypothesisStatus.CONSENSUS,
    )
    package = write_verification_package(
        bundle=bundle,
        hypothesis=hypothesis,
        artifact_path=artifact_path,
        output_dir=tmp_path / "verification",
    )
    script_path = Path(package.package_dir) / "economic_validator.sh"
    script_path.write_text(
        "#!/usr/bin/env bash\n"
        "echo 'profit after gas: 1.23 ETH'\n"
        "echo 'VALIDATED_EVIDENCE: true'\n",
        encoding="utf-8",
    )

    result = validate_economic_package(package)

    assert result.validator.value == "economic"
    assert result.status == ValidationStatus.VALIDATED
    assert result.impact_demonstrated is True
    assert result.command == ["bash", "economic_validator.sh"]
    assert result.output_path
    assert "profit after gas" in Path(result.output_path).read_text()


def test_validate_symbolic_and_property_packages_write_requirements(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")
    hypothesis = AttackHypothesis(
        id="hyp-stateful",
        goalId="goal-state",
        domain=SpecialistDomain.STATE_MACHINE_LIFECYCLE,
        title="State machine needs bounded validation",
        affectedSelectors=["0x3659cfe6"],
        preconditions=["state transition is reachable"],
        expectedImpact="Invalid transition may lock funds.",
        evidenceRefs=["selector:0x3659cfe6"],
        validationMethods=[ValidationMethod.SYMBOLIC, ValidationMethod.PROPERTY],
        status=HypothesisStatus.CONSENSUS,
    )
    package = write_verification_package(
        bundle=bundle,
        hypothesis=hypothesis,
        artifact_path=artifact_path,
        output_dir=tmp_path / "verification",
    )

    symbolic = validate_symbolic_package(package)
    prop = validate_property_package(package)

    assert symbolic.validator.value == "symbolic"
    assert prop.validator.value == "property"
    assert symbolic.status == ValidationStatus.SKIPPED
    assert prop.status == ValidationStatus.SKIPPED
    symbolic_plan = json.loads(Path(symbolic.output_path or "").read_text())
    property_plan = json.loads(Path(prop.output_path or "").read_text())
    assert "concrete_counterexample_transaction_sequence" in symbolic_plan["requiredChecks"]
    assert "shrunk_counterexample" in property_plan["requiredChecks"]


def test_validate_symbolic_package_script_without_marker_is_inconclusive(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")
    hypothesis = AttackHypothesis(
        id="hyp-symbolic-script",
        goalId="goal-state",
        domain=SpecialistDomain.STATE_MACHINE_LIFECYCLE,
        title="Symbolic check needs concrete replay",
        affectedSelectors=["0x3659cfe6"],
        preconditions=["state transition is reachable"],
        expectedImpact="Invalid transition may lock funds.",
        evidenceRefs=["selector:0x3659cfe6"],
        validationMethods=[ValidationMethod.SYMBOLIC],
        status=HypothesisStatus.CONSENSUS,
    )
    package = write_verification_package(
        bundle=bundle,
        hypothesis=hypothesis,
        artifact_path=artifact_path,
        output_dir=tmp_path / "verification",
    )
    script_path = Path(package.package_dir) / "symbolic_validator.sh"
    script_path.write_text("#!/usr/bin/env bash\necho 'counterexample candidate only'\n", encoding="utf-8")

    result = validate_symbolic_package(package)

    assert result.validator.value == "symbolic"
    assert result.status == ValidationStatus.INCONCLUSIVE
    assert result.impact_demonstrated is False
    assert result.output_path
    assert "counterexample candidate only" in Path(result.output_path).read_text()


def test_validate_property_package_script_failure_is_failed(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")
    hypothesis = AttackHypothesis(
        id="hyp-property-script",
        goalId="goal-state",
        domain=SpecialistDomain.STATE_MACHINE_LIFECYCLE,
        title="Property check has failing harness",
        affectedSelectors=["0x3659cfe6"],
        preconditions=["state transition is reachable"],
        expectedImpact="Invalid transition may lock funds.",
        evidenceRefs=["selector:0x3659cfe6"],
        validationMethods=[ValidationMethod.PROPERTY],
        status=HypothesisStatus.CONSENSUS,
    )
    package = write_verification_package(
        bundle=bundle,
        hypothesis=hypothesis,
        artifact_path=artifact_path,
        output_dir=tmp_path / "verification",
    )
    script_path = Path(package.package_dir) / "property_validator.sh"
    script_path.write_text("#!/usr/bin/env bash\necho 'harness failed'\nexit 2\n", encoding="utf-8")

    result = validate_property_package(package)

    assert result.validator.value == "property"
    assert result.status == ValidationStatus.FAILED
    assert result.impact_demonstrated is False
    assert result.output_path
    assert "harness failed" in Path(result.output_path).read_text()


@pytest.mark.asyncio
async def test_validate_ityfuzz_package_skips_scaffold(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")
    hypothesis = AttackHypothesis(
        id="hyp-reentrant",
        goalId="goal-reentrancy",
        domain=SpecialistDomain.EXTERNAL_CALLS_REENTRANCY,
        title="Value-moving path requires bytecode fuzzing",
        affectedSelectors=["0x3659cfe6"],
        preconditions=["selector is reachable"],
        expectedImpact="Callback may break accounting.",
        evidenceRefs=["selector:0x3659cfe6"],
        validationMethods=[ValidationMethod.ITYFUZZ],
        status=HypothesisStatus.CONSENSUS,
    )
    package = write_verification_package(
        bundle=bundle,
        hypothesis=hypothesis,
        artifact_path=artifact_path,
        output_dir=tmp_path / "verification",
    )

    result = await validate_ityfuzz_package(package, cwd=tmp_path)

    assert result.validator.value == "ityfuzz"
    assert result.status == ValidationStatus.SKIPPED
    assert "scaffold" in result.reason.lower()


def test_rejected_memory_persists_no_signal_receipts(tmp_path: Path) -> None:
    bundle = build_artifact_bundle(
        chain=Chain.ETH,
        chain_id=1,
        target_address="0x742d35cc6634c0532925a3b844bc454e4438f44e",
        resolved_address="0x742d35cc6634c0532925a3b844bc454e4438f44e",
        bytecode_hex="0x6001600055",
        is_proxy=False,
        proxy_type=ProxyType.NONE,
        selectors=[],
        snapshot_block=123,
    )
    artifact_path = write_artifact_bundle(bundle, tmp_path / "artifact.json")
    state = run_offline_research_loop(bundle, artifact_path=artifact_path, iteration_budget=2)
    memory_path = write_rejected_memory(state, tmp_path / "rejected_hypotheses.jsonl")

    records = load_rejected_memory(memory_path)

    assert len(records) == 2
    assert records[0].hypothesis_id.startswith("none-")
    assert "target-specific signal" in records[0].missing_facts


def test_cheap_tool_manifest_exposes_planned_storage_trace_tools() -> None:
    manifest = build_cheap_tool_manifest(_sample_bundle())

    assert manifest["snapshotBlock"] == 123
    tool_names = {tool["name"] for tool in manifest["tools"]}
    assert {
        "selector_lookup",
        "static_reachability",
        "raw_storage_read",
        "storage_diff_around_tx",
        "recent_trace_read",
        "cast_call",
        "native_balance_scan",
        "token_balance_candidates",
        "rag_exploit_search",
    } <= tool_names


def test_materialized_facts_extend_consensus_gate(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    tool_dir = tmp_path / "cheap_tools"
    tool_dir.mkdir()
    (tool_dir / "storage_reads.json").write_text(
        json.dumps(
            {
                "reads": [
                    {
                        "label": "eip1967.implementation",
                        "slot": "0x01",
                        "value": "0x02",
                        "evidenceRef": "storage:eip1967.implementation",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    hypothesis = AttackHypothesis(
        id="hyp-storage",
        goalId="goal-storage",
        domain=SpecialistDomain.PROXY_STORAGE_DELEGATECALL,
        title="Implementation slot needs validation",
        affectedSelectors=["0x3659cfe6"],
        preconditions=["implementation slot is non-zero"],
        expectedImpact="Delegatecall target mismatch may break proxy assumptions.",
        evidenceRefs=["selector:0x3659cfe6", "storage:eip1967.implementation"],
        validationMethods=[ValidationMethod.FOUNDRY_FORK],
    )

    planned_only = build_cheap_fact_index(bundle)
    materialized = build_cheap_fact_index(bundle, materialized_tool_dir=tool_dir)

    assert "storage:eip1967.implementation" not in planned_only
    assert "storage:eip1967.implementation" in collect_materialized_facts(tool_dir)
    assert passes_consensus_gate(hypothesis, planned_only).accepted is False
    assert passes_consensus_gate(hypothesis, materialized).accepted is True


@pytest.mark.asyncio
async def test_materialize_cheap_tool_artifacts_writes_rpc_outputs(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    mock_w3 = MagicMock()
    mock_w3.to_checksum_address.side_effect = lambda value: value

    async def fake_get_storage_at(_address, slot, block_identifier=None):
        impl_slot = int("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
        if slot == impl_slot and block_identifier == 122:
            return bytes.fromhex("00" * 32)
        if slot == impl_slot:
            return bytes.fromhex("00" * 31 + "01")
        return bytes.fromhex("00" * 32)

    mock_w3.eth.get_storage_at = AsyncMock(side_effect=fake_get_storage_at)
    mock_w3.eth.get_balance = AsyncMock(return_value=123)
    mock_w3.eth.call = AsyncMock(return_value=bytes.fromhex("00" * 32))
    mock_w3.eth.get_logs = AsyncMock(
        return_value=[
            {
                "transactionHash": bytes.fromhex("11" * 32),
                "blockHash": bytes.fromhex("22" * 32),
                "blockNumber": 123,
                "logIndex": 7,
                "topics": [bytes.fromhex("33" * 32)],
                "data": b"",
            }
        ]
    )
    mock_w3.provider.make_request = AsyncMock(
        return_value={
            "result": {
                "type": "CALL",
                "from": "0x" + "aa" * 20,
                "to": "0x" + "bb" * 20,
            }
        }
    )
    rag_hit = SimpleNamespace(
        id="exploit-1",
        name="Proxy storage collision",
        chain="eth",
        attack_type="access_control",
        root_cause="proxy storage collision",
        summary="Attacker changed implementation slot.",
        score=0.9,
        match_type="hybrid",
        file_path="exploits/proxy.md",
    )

    with (
        patch("src.autoresearch.tools.AsyncWeb3") as mock_web3,
        patch("src.rag.search.hybrid_search", new=AsyncMock(return_value=[rag_hit])),
    ):
        mock_web3.AsyncHTTPProvider.return_value = object()
        mock_web3.return_value = mock_w3

        manifest_path = await materialize_cheap_tool_artifacts(
            bundle,
            tmp_path / "cheap_tools",
            rpc_url="https://rpc.invalid",
        )

    tool_dir = tmp_path / "cheap_tools"
    assert manifest_path.exists()
    assert json.loads((tool_dir / "storage_reads.json").read_text())["status"] == "observed"
    storage_diffs = json.loads((tool_dir / "storage_diffs.json").read_text())
    assert storage_diffs["diffs"][0]["evidenceRef"].startswith("storage_diff:")
    assert json.loads((tool_dir / "native_balances.json").read_text())["reads"][0][
        "balanceWei"
    ] == "123"
    assert json.loads((tool_dir / "cast_calls.json").read_text())["calls"][0][
        "evidenceRef"
    ].startswith("call:")
    assert json.loads((tool_dir / "token_balances.json").read_text())["reads"][0][
        "evidenceRef"
    ].startswith("balance:token:")
    assert json.loads((tool_dir / "recent_traces.json").read_text())["traces"][0][
        "evidenceRef"
    ].startswith("trace:")
    assert json.loads((tool_dir / "rag_hits.json").read_text())["hits"][0]["evidenceRef"].startswith(
        "rag:"
    )
    refs = collect_materialized_facts(tool_dir)
    assert "storage:eip1967.implementation" in refs
    assert "balance:native:target" in refs
    assert "storage_diff:" in next(ref for ref in refs if ref.startswith("storage_diff:"))
    assert "rag:" in next(ref for ref in refs if ref.startswith("rag:"))
    assert "trace:0x" in next(ref for ref in refs if ref.startswith("trace:"))
    assert "balance:token:" in next(ref for ref in refs if ref.startswith("balance:token:"))
    assert "log:0x" in next(ref for ref in refs if ref.startswith("log:"))


@pytest.mark.asyncio
async def test_run_autoresearch_stage_writes_artifacts(tmp_path: Path) -> None:
    resolved = ResolvedContract(
        originalAddress="0x742d35cc6634c0532925a3b844bc454e4438f44e",
        resolvedAddress="0x742d35cc6634c0532925a3b844bc454e4438f44e",
        chain=Chain.ETH,
        isProxy=False,
        proxyType=ProxyType.NONE,
        selectors=["0x3659cfe6"],
    )

    with patch("src.stages.autoresearch.get_audit_dir", return_value=tmp_path):
        result = await run_autoresearch_stage(
            address="0x742d35cc6634c0532925a3b844bc454e4438f44e",
            chain=Chain.ETH,
            resolved=resolved,
            bytecode_hex="0x6001600055",
            decompile_dir=tmp_path / "decompiled",
            dedaub_file=tmp_path / "decompiled" / "Contract.sol",
            iteration_budget=6,
            snapshot_block=123,
            researcher_model="model-a",
            skeptic_model="model-b",
            proposed_hypotheses=[
                AttackHypothesis(
                    id="hyp-external",
                    goalId="goal-auth",
                    domain=SpecialistDomain.AUTH_UPGRADEABILITY,
                    title="External model candidate",
                    affectedSelectors=["0x3659cfe6"],
                    preconditions=["selector is reachable"],
                    expectedImpact="Unauthorized upgrade if auth is bypassable.",
                    evidenceRefs=["selector:0x3659cfe6"],
                    validationMethods=[ValidationMethod.FOUNDRY_FORK],
                ),
                AttackHypothesis(
                    id="hyp-vague",
                    goalId="goal-auth",
                    domain=SpecialistDomain.AUTH_UPGRADEABILITY,
                    title="Vague candidate",
                    expectedImpact="",
                ),
            ],
            materialize_tools=False,
        )

    assert result.artifact_path.exists()
    assert result.tool_manifest_path.exists()
    assert result.rejected_memory_path.exists()
    assert (tmp_path / "artifacts" / "runtime_bytecode.hex").read_text().strip() == "6001600055"
    assert (tmp_path / "artifacts" / "runtime_opcodes.txt").read_text().splitlines()[-1] == (
        "0x0004 SSTORE"
    )
    cheap_facts = json.loads((tmp_path / "artifacts" / "cheap_facts.json").read_text())
    assert "selector:0x3659cfe6" in cheap_facts
    tool_manifest = json.loads(result.tool_manifest_path.read_text())
    assert {tool["name"] for tool in tool_manifest["tools"]} >= {
        "raw_storage_read",
        "recent_trace_read",
        "storage_diff_around_tx",
        "rag_exploit_search",
    }
    cheap_tool_dir = tmp_path / "artifacts" / "cheap_tools"
    assert (cheap_tool_dir / "static_reachability.json").exists()
    assert (cheap_tool_dir / "storage_diff_plan.json").exists()
    assert (cheap_tool_dir / "rag_search_plan.json").exists()
    artifact = json.loads(result.artifact_path.read_text())
    assert any(material["kind"] == "runtime_bytecode" for material in artifact["materials"])
    assert any(material["kind"] == "opcode_listing" for material in artifact["materials"])
    assert any(material["kind"] == "cheap_tool_artifacts" for material in artifact["materials"])
    assert artifact["snapshotContext"]["observedSelectors"] == ["0x3659cfe6"]
    assert result.state_path.exists()
    state = json.loads(result.state_path.read_text())
    assert state["researcherModel"] == "model-a"
    assert state["skepticModel"] == "model-b"
    assert state["stopReason"] == "iteration_budget_reached"
    assert state["scratchpad"]["worked"] == ["hyp-external: External model candidate"]
    assert state["scratchpad"]["blocked"]
    assert result.internal_report_path.exists()
    assert result.internal_report_path.name == "internal_report.json"
    assert result.internal_report_md_path.name == "internal_report.md"
    assert result.consensus_count == 1
    assert result.rejected_count == 1
    assert result.validated_count == 0
    assert result.verification_package_paths
    assert result.validation_result_paths
    assert result.validation_result_paths[0].name == "validation_results.json"
    report = json.loads((tmp_path / "reports" / "internal_report.json").read_text())
    assert report["snapshotBlock"] == 123
    assert report["researcherModel"] == "model-a"
    assert report["skepticModel"] == "model-b"
    assert report["rejectedHypotheses"][0]["hypothesisId"] == "hyp-vague"
    assert "expected impact" in report["rejectedHypotheses"][0]["missingFacts"]


@pytest.mark.asyncio
async def test_run_autoresearch_stage_can_generate_model_hypotheses(tmp_path: Path) -> None:
    resolved = ResolvedContract(
        originalAddress="0x742d35cc6634c0532925a3b844bc454e4438f44e",
        resolvedAddress="0x742d35cc6634c0532925a3b844bc454e4438f44e",
        chain=Chain.ETH,
        isProxy=False,
        proxyType=ProxyType.NONE,
        selectors=["0x3659cfe6"],
    )
    model_hypothesis = AttackHypothesis(
        id="hyp-model",
        goalId="goal-auth",
        domain=SpecialistDomain.AUTH_UPGRADEABILITY,
        title="Model generated upgrade hypothesis",
        affectedSelectors=["0x3659cfe6"],
        preconditions=["selector is reachable"],
        expectedImpact="Unauthorized upgrade if auth is bypassable.",
        evidenceRefs=["selector:0x3659cfe6"],
        validationMethods=[ValidationMethod.FOUNDRY_FORK],
    )

    async def fake_generate_model_hypotheses(**kwargs):
        output_dir = Path(kwargs["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        hypotheses_path = output_dir / "hypotheses.json"
        transcript_path = output_dir / "model_transcript.json"
        hypotheses_path.write_text('{"hypotheses":[]}\n', encoding="utf-8")
        transcript_path.write_text("{}\n", encoding="utf-8")
        return SimpleNamespace(
            hypotheses=[model_hypothesis],
            hypotheses_path=hypotheses_path,
            transcript_path=transcript_path,
            researcher_model="model-a",
            skeptic_model="model-b",
        )

    with patch(
        "src.stages.autoresearch.generate_model_hypotheses",
        new=fake_generate_model_hypotheses,
    ):
        result = await run_autoresearch_stage(
            address="0x742d35cc6634c0532925a3b844bc454e4438f44e",
            chain=Chain.ETH,
            resolved=resolved,
            bytecode_hex="0x6001600055",
            decompile_dir=None,
            dedaub_file=None,
            iteration_budget=2,
            run_validators=False,
            materialize_tools=False,
            audit_dir=tmp_path,
            model_handoff_config=OpenAICompatibleConfig(
                base_url="https://models.example/v1",
                api_key="test",
                researcher_model="model-a",
                skeptic_model="model-b",
            ),
        )

    assert result.model_hypotheses_path and result.model_hypotheses_path.exists()
    assert result.model_transcript_path and result.model_transcript_path.exists()
    state = json.loads(result.state_path.read_text())
    assert state["researcherModel"] == "model-a"
    assert state["skepticModel"] == "model-b"
    assert state["scratchpad"]["worked"] == ["hyp-model: Model generated upgrade hypothesis"]
