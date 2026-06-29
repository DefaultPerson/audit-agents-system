"""Benchmark corpus loading and report scoring."""

import json
from collections.abc import Sequence
from pathlib import Path

from ..autoresearch import AutoresearchInternalReport
from .models import (
    BenchmarkCase,
    BenchmarkCaseKind,
    BenchmarkCorpus,
    BenchmarkScore,
    BenchmarkSummary,
    score_case,
)


def load_corpus(path: str | Path) -> BenchmarkCorpus:
    """Load benchmark corpus JSON."""
    corpus_path = Path(path)
    data = json.loads(corpus_path.read_text(encoding="utf-8"))
    corpus = BenchmarkCorpus.model_validate(data)
    return corpus.model_copy(
        update={"cases": [case.resolve_paths(corpus_path.parent) for case in corpus.cases]}
    )


def _load_report(path: Path) -> AutoresearchInternalReport:
    data = json.loads(path.read_text(encoding="utf-8"))
    return AutoresearchInternalReport.model_validate(data)


def _case_key(chain: str, address: str, snapshot_block: int | None) -> tuple[str, str, int | None]:
    return (chain, address.lower(), snapshot_block)


def _case_by_target(corpus: BenchmarkCorpus) -> dict[tuple[str, str, int | None], BenchmarkCase]:
    return {
        _case_key(case.chain.value, case.target_address, case.snapshot_block): case
        for case in corpus.cases
    }


def score_internal_reports(
    corpus: BenchmarkCorpus,
    report_paths: Sequence[str | Path],
) -> BenchmarkSummary:
    """Score internal report JSON files against a benchmark corpus."""
    cases = _case_by_target(corpus)
    scores: list[BenchmarkScore] = []

    for report_path in report_paths:
        path = Path(report_path)
        report = _load_report(path)
        case = cases.get(
            _case_key(report.chain.value, report.target_address, report.snapshot_block)
        )
        if not case:
            continue
        scores.append(score_case(case, report, str(path)))

    known_total = sum(1 for case in corpus.cases if case.kind == BenchmarkCaseKind.KNOWN_EXPLOIT)
    benign_total = sum(1 for case in corpus.cases if case.kind == BenchmarkCaseKind.BENIGN_TRAP)
    scored_case_ids = {score.case_id for score in scores}

    return BenchmarkSummary(
        corpusName=corpus.name,
        totalCases=len(corpus.cases),
        scoredCases=len(scores),
        knownExploitHits=sum(
            1 for score in scores if score.kind == BenchmarkCaseKind.KNOWN_EXPLOIT and score.passed
        ),
        knownExploitTotal=known_total,
        benignFalsePositives=sum(
            1
            for score in scores
            if score.kind == BenchmarkCaseKind.BENIGN_TRAP and score.validated_findings_count > 0
        ),
        benignTotal=benign_total,
        edgeCaseValidated=sum(
            1 for score in scores if score.kind == BenchmarkCaseKind.EDGE_CASE and score.passed
        ),
        missingCaseIds=[case.id for case in corpus.cases if case.id not in scored_case_ids],
        scores=scores,
    )


def write_benchmark_summary(summary: BenchmarkSummary, output_path: str | Path) -> Path:
    """Write benchmark summary JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(summary.model_dump_json(by_alias=True, indent=2) + "\n", encoding="utf-8")
    return path
