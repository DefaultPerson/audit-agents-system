"""Tests for benchmark corpus scoring."""

import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from src.benchmark import (
    build_benchmark_run_plan,
    execute_benchmark_run_plan,
    load_corpus,
    parse_model_pairs,
    score_internal_reports,
    write_benchmark_run_execution,
    write_benchmark_run_plan,
    write_benchmark_summary,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_seed_benchmark_corpus_loads() -> None:
    corpus = load_corpus(REPO_ROOT / "docs" / "benchmark-corpus.json")

    assert corpus.name == "evm-closed-source-seed-candidates"
    assert len(corpus.cases) >= 10
    assert {case.kind.value for case in corpus.cases} == {
        "known_exploit",
        "benign_trap",
        "edge_case",
    }


def _write_report(
    path: Path,
    *,
    address: str,
    validated_count: int,
    snapshot_block: int | None = None,
) -> Path:
    validation_results = [
        {
            "hypothesisId": "hyp-validated",
            "packageDir": "verification/hyp",
            "validator": "foundry",
            "status": "validated",
            "impactDemonstrated": True,
            "reason": "validated evidence",
            "command": [],
            "durationMs": 1,
            "createdAt": "2026-05-18T00:00:00Z",
        }
        for _ in range(validated_count)
    ]
    path.write_text(
        json.dumps(
            {
                "targetAddress": address,
                "chain": "eth",
                "snapshotBlock": snapshot_block,
                "artifactPath": "artifact.json",
                "statePath": "loop_state.json",
                "consensusCount": 1,
                "rejectedCount": 0,
                "verificationPackages": ["verification/hyp"],
                "validationResults": validation_results,
                "validatedFindingsCount": validated_count,
                "disclosureAllowed": False,
                "createdAt": "2026-05-18T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return path


def test_score_internal_reports(tmp_path: Path) -> None:
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(
        json.dumps(
            {
                "name": "test-corpus",
                "cases": [
                    {
                        "id": "known-1",
                        "kind": "known_exploit",
                        "chain": "eth",
                        "targetAddress": "0x0000000000000000000000000000000000000001",
                        "snapshotBlock": 100,
                    },
                    {
                        "id": "benign-1",
                        "kind": "benign_trap",
                        "chain": "eth",
                        "targetAddress": "0x0000000000000000000000000000000000000002",
                    },
                    {
                        "id": "edge-unscored",
                        "kind": "edge_case",
                        "chain": "eth",
                        "targetAddress": "0x0000000000000000000000000000000000000003",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    known_report = _write_report(
        tmp_path / "known_report.json",
        address="0x0000000000000000000000000000000000000001",
        validated_count=1,
        snapshot_block=100,
    )
    benign_report = _write_report(
        tmp_path / "benign_report.json",
        address="0x0000000000000000000000000000000000000002",
        validated_count=0,
    )

    corpus = load_corpus(corpus_path)
    summary = score_internal_reports(corpus, [known_report, benign_report])

    assert summary.scored_cases == 2
    assert summary.known_exploit_hits == 1
    assert summary.benign_false_positives == 0
    assert summary.known_exploit_recall == 1.0
    assert summary.benign_false_positive_rate == 0.0
    assert summary.missing_case_ids == ["edge-unscored"]


def test_score_ignores_stale_validated_count_without_evidence(tmp_path: Path) -> None:
    corpus = load_corpus(
        _write_one_case_corpus(
            tmp_path / "corpus.json",
            kind="known_exploit",
            address="0x0000000000000000000000000000000000000001",
        )
    )
    stale_report = _write_report(
        tmp_path / "stale_report.json",
        address="0x0000000000000000000000000000000000000001",
        validated_count=0,
    )
    data = json.loads(stale_report.read_text())
    data["validatedFindingsCount"] = 1
    stale_report.write_text(json.dumps(data), encoding="utf-8")

    summary = score_internal_reports(corpus, [stale_report])

    assert summary.known_exploit_hits == 0
    assert summary.scores[0].validated_findings_count == 0


def test_score_requires_snapshot_match(tmp_path: Path) -> None:
    corpus = load_corpus(
        _write_one_case_corpus(
            tmp_path / "corpus.json",
            kind="known_exploit",
            address="0x0000000000000000000000000000000000000001",
            snapshot_block=100,
        )
    )
    wrong_block_report = _write_report(
        tmp_path / "wrong_block_report.json",
        address="0x0000000000000000000000000000000000000001",
        validated_count=1,
        snapshot_block=101,
    )

    summary = score_internal_reports(corpus, [wrong_block_report])

    assert summary.scored_cases == 0
    assert summary.missing_case_ids == ["case-1"]


def test_write_benchmark_summary(tmp_path: Path) -> None:
    corpus = load_corpus(_write_corpus(tmp_path / "corpus.json"))
    summary = score_internal_reports(corpus, [])

    output_path = write_benchmark_summary(summary, tmp_path / "summary.json")

    assert output_path.exists()
    assert json.loads(output_path.read_text())["corpusName"] == "empty-corpus"


def test_benchmark_run_plan_builds_corpus_by_model_pair_commands(tmp_path: Path) -> None:
    bytecode_path = tmp_path / "runtime.hex"
    bytecode_path.write_text("0x6001600055\n", encoding="utf-8")
    decompile_dir = tmp_path / "decompiled"
    decompile_dir.mkdir()
    dedaub_file = decompile_dir / "dedaub.sol"
    dedaub_file.write_text("contract C {}\n", encoding="utf-8")
    corpus = load_corpus(
        _write_one_case_corpus(
            tmp_path / "corpus.json",
            kind="known_exploit",
            address="0x0000000000000000000000000000000000000001",
            snapshot_block=100,
            bytecode_path="runtime.hex",
            decompile_dir="decompiled",
            dedaub_file="decompiled/dedaub.sol",
            selectors=["0x3659cfe6"],
            resolved_address="0x0000000000000000000000000000000000000002",
            is_proxy=True,
            proxy_type="eip1967",
        )
    )
    pairs = parse_model_pairs(["pair-a=researcher-a:skeptic-a", "scout"])

    plan = build_benchmark_run_plan(
        corpus,
        output_dir=tmp_path / "runs",
        model_pairs=pairs,
        iterations=2,
        skip_dedaub=True,
        validate=False,
        materialize_tools=False,
        cost_budget_usd=2.5,
        time_budget_seconds=300,
    )
    plan_path = write_benchmark_run_plan(plan, tmp_path / "plan.json")

    assert plan_path.exists()
    assert len(plan.items) == 2
    assert plan.items[0].command[:4] == [sys.executable, "-m", "cli.main", "autoresearch"]
    assert "0x0000000000000000000000000000000000000001" in plan.items[0].command
    assert "--block" in plan.items[0].command
    assert "--bytecode-file" in plan.items[0].command
    assert str(bytecode_path) in plan.items[0].command
    assert "--decompile-dir" in plan.items[0].command
    assert str(decompile_dir) in plan.items[0].command
    assert "--dedaub-file" in plan.items[0].command
    assert str(dedaub_file) in plan.items[0].command
    assert "--resolved-address" in plan.items[0].command
    assert "0x0000000000000000000000000000000000000002" in plan.items[0].command
    assert "--selectors" in plan.items[0].command
    assert "0x3659cfe6" in plan.items[0].command
    assert "--is-proxy" in plan.items[0].command
    assert "--proxy-type" in plan.items[0].command
    assert "eip1967" in plan.items[0].command
    assert "--skip-dedaub" in plan.items[0].command
    assert "--no-validate" in plan.items[0].command
    assert "--no-materialize-tools" in plan.items[0].command
    assert "--cost-budget-usd" in plan.items[0].command
    assert "--time-budget-seconds" in plan.items[0].command
    assert plan.model_pairs[1].researcher_model == "scout"
    assert plan.model_pairs[1].skeptic_model == "scout"


def test_execute_benchmark_run_plan_writes_receipts(tmp_path: Path) -> None:
    corpus = load_corpus(
        _write_one_case_corpus(
            tmp_path / "corpus.json",
            kind="known_exploit",
            address="0x0000000000000000000000000000000000000001",
        )
    )
    plan = build_benchmark_run_plan(
        corpus,
        output_dir=tmp_path / "runs",
        model_pairs=parse_model_pairs(["offline"]),
        iterations=1,
    )

    def fake_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=(
                'prefix\n{"internalReportPath": "reports/internal_report.json", '
                '"estimatedCostUsd": 0.25}\n'
            ),
            stderr="",
        )

    execution = execute_benchmark_run_plan(
        plan,
        receipts_dir=tmp_path / "receipts",
        runner=fake_runner,
    )
    execution_path = write_benchmark_run_execution(execution, tmp_path / "execution.json")

    assert execution_path.exists()
    assert execution.report_paths == ["reports/internal_report.json"]
    assert execution.receipts[0].return_code == 0
    assert execution.receipts[0].estimated_cost_usd == 0.25
    assert execution.successful_runs == 1
    assert execution.failed_runs == 0
    assert execution.total_estimated_cost_usd == 0.25
    assert execution.average_estimated_cost_usd == 0.25
    assert execution.total_duration_ms >= 0
    assert Path(execution.receipts[0].stdout_path).exists()


def _write_corpus(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "name": "empty-corpus",
                "cases": [],
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_one_case_corpus(
    path: Path,
    *,
    kind: str,
    address: str,
    snapshot_block: int | None = None,
    bytecode_path: str | None = None,
    decompile_dir: str | None = None,
    dedaub_file: str | None = None,
    selectors: list[str] | None = None,
    resolved_address: str | None = None,
    is_proxy: bool = False,
    proxy_type: str | None = None,
) -> Path:
    case = {
        "id": "case-1",
        "kind": kind,
        "chain": "eth",
        "targetAddress": address,
        "snapshotBlock": snapshot_block,
    }
    if bytecode_path is not None:
        case["bytecodePath"] = bytecode_path
    if decompile_dir is not None:
        case["decompileDir"] = decompile_dir
    if dedaub_file is not None:
        case["dedaubFile"] = dedaub_file
    if selectors is not None:
        case["selectors"] = selectors
    if resolved_address is not None:
        case["resolvedAddress"] = resolved_address
    if is_proxy:
        case["isProxy"] = is_proxy
    if proxy_type is not None:
        case["proxyType"] = proxy_type
    path.write_text(
        json.dumps(
            {
                "name": "one-case-corpus",
                "cases": [case],
            }
        ),
        encoding="utf-8",
    )
    return path
