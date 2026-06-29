"""Benchmark run planning and execution harness."""

import json
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from .models import BenchmarkCase, BenchmarkCorpus


class BenchmarkModelPair(BaseModel):
    """Researcher/Skeptic model pair for benchmark runs."""

    id: str
    researcher_model: str = Field(alias="researcherModel")
    skeptic_model: str = Field(alias="skepticModel")

    model_config = {"populate_by_name": True}


class BenchmarkRunItem(BaseModel):
    """One corpus case executed with one model pair."""

    case_id: str = Field(alias="caseId")
    model_pair_id: str = Field(alias="modelPairId")
    chain: str
    target_address: str = Field(alias="targetAddress")
    snapshot_block: int | None = Field(default=None, alias="snapshotBlock")
    output_dir: str = Field(alias="outputDir")
    command: list[str]

    model_config = {"populate_by_name": True}


class BenchmarkRunPlan(BaseModel):
    """Machine-readable benchmark run plan."""

    schema_version: str = Field(default="evm-benchmark-run-plan/v1", alias="schemaVersion")
    corpus_name: str = Field(alias="corpusName")
    output_dir: str = Field(alias="outputDir")
    iterations: int
    skip_dedaub: bool = Field(alias="skipDedaub")
    run_validators: bool = Field(alias="validate")
    materialize_tools: bool = Field(alias="materializeTools")
    model_pairs: list[BenchmarkModelPair] = Field(alias="modelPairs")
    items: list[BenchmarkRunItem]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}


class BenchmarkRunReceipt(BaseModel):
    """Execution receipt for one benchmark run item."""

    case_id: str = Field(alias="caseId")
    model_pair_id: str = Field(alias="modelPairId")
    command: list[str]
    return_code: int = Field(alias="returnCode")
    duration_ms: int = Field(alias="durationMs")
    estimated_cost_usd: float | None = Field(default=None, alias="estimatedCostUsd")
    internal_report_path: str | None = Field(default=None, alias="internalReportPath")
    stdout_path: str = Field(alias="stdoutPath")
    stderr_path: str = Field(alias="stderrPath")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}


class BenchmarkRunExecution(BaseModel):
    """Execution summary for a benchmark plan."""

    schema_version: str = Field(default="evm-benchmark-run-execution/v1", alias="schemaVersion")
    plan_path: str | None = Field(default=None, alias="planPath")
    receipts: list[BenchmarkRunReceipt]
    report_paths: list[str] = Field(default_factory=list, alias="reportPaths")
    successful_runs: int = Field(default=0, alias="successfulRuns")
    failed_runs: int = Field(default=0, alias="failedRuns")
    total_duration_ms: int = Field(default=0, alias="totalDurationMs")
    average_duration_ms: float = Field(default=0.0, alias="averageDurationMs")
    total_estimated_cost_usd: float | None = Field(default=None, alias="totalEstimatedCostUsd")
    average_estimated_cost_usd: float | None = Field(default=None, alias="averageEstimatedCostUsd")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}


Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def parse_model_pair(value: str) -> BenchmarkModelPair:
    """Parse MODEL or ID=RESEARCHER:SKEPTIC into a benchmark model pair."""
    pair_id: str
    spec = value
    if "=" in value:
        pair_id, spec = value.split("=", 1)
    elif ":" in value:
        pair_id = value.replace(":", "__")
    else:
        pair_id = value

    if ":" in spec:
        researcher, skeptic = spec.split(":", 1)
    else:
        researcher = skeptic = spec
    return BenchmarkModelPair(
        id=pair_id.strip(),
        researcherModel=researcher.strip(),
        skepticModel=skeptic.strip(),
    )


def parse_model_pairs(values: Sequence[str]) -> list[BenchmarkModelPair]:
    """Parse model-pair CLI values."""
    return [parse_model_pair(value) for value in values]


def _case_output_dir(output_dir: Path, case: BenchmarkCase, pair: BenchmarkModelPair) -> Path:
    return output_dir / pair.id / case.id


def _command_for_item(
    case: BenchmarkCase,
    pair: BenchmarkModelPair,
    output_dir: Path,
    *,
    iterations: int,
    skip_dedaub: bool,
    validate: bool,
    materialize_tools: bool,
    cost_budget_usd: float | None,
    time_budget_seconds: int | None,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "cli.main",
        "autoresearch",
        case.target_address,
        "--chain",
        case.chain.value,
        "--iterations",
        str(iterations),
        "--researcher-model",
        pair.researcher_model,
        "--skeptic-model",
        pair.skeptic_model,
        "--output-dir",
        str(_case_output_dir(output_dir, case, pair)),
        "--json",
    ]
    if case.snapshot_block is not None:
        command.extend(["--block", str(case.snapshot_block)])
    if case.bytecode_path is not None:
        command.extend(["--bytecode-file", case.bytecode_path])
        if case.resolved_address is not None:
            command.extend(["--resolved-address", case.resolved_address])
        if case.selectors:
            command.extend(["--selectors", ",".join(case.selectors)])
        if case.is_proxy:
            command.append("--is-proxy")
        if case.proxy_type is not None:
            command.extend(["--proxy-type", case.proxy_type.value])
    if case.dedaub_file is not None:
        command.extend(["--dedaub-file", case.dedaub_file])
    if case.decompile_dir is not None:
        command.extend(["--decompile-dir", case.decompile_dir])
    if skip_dedaub:
        command.append("--skip-dedaub")
    if cost_budget_usd is not None:
        command.extend(["--cost-budget-usd", str(cost_budget_usd)])
    if time_budget_seconds is not None:
        command.extend(["--time-budget-seconds", str(time_budget_seconds)])
    command.append("--validate" if validate else "--no-validate")
    command.append("--materialize-tools" if materialize_tools else "--no-materialize-tools")
    return command


def build_benchmark_run_plan(
    corpus: BenchmarkCorpus,
    *,
    output_dir: str | Path,
    model_pairs: Sequence[BenchmarkModelPair],
    iterations: int,
    skip_dedaub: bool = True,
    validate: bool = False,
    materialize_tools: bool = False,
    cost_budget_usd: float | None = None,
    time_budget_seconds: int | None = None,
) -> BenchmarkRunPlan:
    """Build a corpus x model-pair run plan."""
    base_output_dir = Path(output_dir)
    items = [
        BenchmarkRunItem(
            caseId=case.id,
            modelPairId=pair.id,
            chain=case.chain.value,
            targetAddress=case.target_address,
            snapshotBlock=case.snapshot_block,
            outputDir=str(_case_output_dir(base_output_dir, case, pair)),
            command=_command_for_item(
                case,
                pair,
                base_output_dir,
                iterations=iterations,
                skip_dedaub=skip_dedaub,
                validate=validate,
                materialize_tools=materialize_tools,
                cost_budget_usd=cost_budget_usd,
                time_budget_seconds=time_budget_seconds,
            ),
        )
        for pair in model_pairs
        for case in corpus.cases
    ]
    return BenchmarkRunPlan(
        corpusName=corpus.name,
        outputDir=str(base_output_dir),
        iterations=iterations,
        skipDedaub=skip_dedaub,
        validate=validate,
        materializeTools=materialize_tools,
        modelPairs=list(model_pairs),
        items=items,
    )


def write_benchmark_run_plan(plan: BenchmarkRunPlan, output_path: str | Path) -> Path:
    """Write benchmark run plan JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(plan.model_dump_json(by_alias=True, indent=2) + "\n", encoding="utf-8")
    return path


def load_benchmark_run_plan(path: str | Path) -> BenchmarkRunPlan:
    """Load benchmark run plan JSON."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return BenchmarkRunPlan.model_validate(data)


def _default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, check=False, text=True)


def _extract_json_payload(stdout: str) -> dict[str, object]:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return {}


def _extract_internal_report_path(payload: dict[str, object]) -> str | None:
    value = payload.get("internalReportPath")
    return value if isinstance(value, str) else None


def _extract_estimated_cost_usd(payload: dict[str, object]) -> float | None:
    value = payload.get("estimatedCostUsd")
    if isinstance(value, int | float):
        return float(value)
    return None


def _execution_summary(
    receipts: list[BenchmarkRunReceipt],
) -> tuple[int, int, int, float, float | None, float | None]:
    successful_runs = sum(1 for receipt in receipts if receipt.return_code == 0)
    failed_runs = len(receipts) - successful_runs
    total_duration_ms = sum(receipt.duration_ms for receipt in receipts)
    costs = [
        receipt.estimated_cost_usd
        for receipt in receipts
        if receipt.estimated_cost_usd is not None
    ]
    total_estimated_cost = sum(costs) if costs else None
    return (
        successful_runs,
        failed_runs,
        total_duration_ms,
        total_duration_ms / len(receipts) if receipts else 0.0,
        total_estimated_cost,
        (
            total_estimated_cost / len(costs) if total_estimated_cost is not None else None
        ),
    )


def execute_benchmark_run_plan(
    plan: BenchmarkRunPlan,
    *,
    receipts_dir: str | Path | None = None,
    runner: Runner = _default_runner,
) -> BenchmarkRunExecution:
    """Execute a benchmark run plan and persist stdout/stderr receipts."""
    output_dir = Path(receipts_dir or Path(plan.output_dir) / "receipts")
    output_dir.mkdir(parents=True, exist_ok=True)
    receipts: list[BenchmarkRunReceipt] = []

    for item in plan.items:
        start = time.monotonic()
        completed = runner(item.command)
        duration_ms = int((time.monotonic() - start) * 1000)
        prefix = f"{item.model_pair_id}__{item.case_id}"
        stdout_path = output_dir / f"{prefix}.stdout.txt"
        stderr_path = output_dir / f"{prefix}.stderr.txt"
        stdout_path.write_text(completed.stdout or "", encoding="utf-8")
        stderr_path.write_text(completed.stderr or "", encoding="utf-8")
        payload = _extract_json_payload(completed.stdout or "")
        receipts.append(
            BenchmarkRunReceipt(
                caseId=item.case_id,
                modelPairId=item.model_pair_id,
                command=item.command,
                returnCode=completed.returncode,
                durationMs=duration_ms,
                estimatedCostUsd=_extract_estimated_cost_usd(payload),
                internalReportPath=_extract_internal_report_path(payload),
                stdoutPath=str(stdout_path),
                stderrPath=str(stderr_path),
            )
        )

    (
        successful_runs,
        failed_runs,
        total_duration_ms,
        average_duration_ms,
        total_estimated_cost_usd,
        average_estimated_cost_usd,
    ) = _execution_summary(receipts)
    return BenchmarkRunExecution(
        receipts=receipts,
        reportPaths=[
            receipt.internal_report_path
            for receipt in receipts
            if receipt.return_code == 0 and receipt.internal_report_path
        ],
        successfulRuns=successful_runs,
        failedRuns=failed_runs,
        totalDurationMs=total_duration_ms,
        averageDurationMs=average_duration_ms,
        totalEstimatedCostUsd=total_estimated_cost_usd,
        averageEstimatedCostUsd=average_estimated_cost_usd,
    )


def write_benchmark_run_execution(
    execution: BenchmarkRunExecution,
    output_path: str | Path,
) -> Path:
    """Write benchmark run execution summary JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        execution.model_dump_json(by_alias=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return path
