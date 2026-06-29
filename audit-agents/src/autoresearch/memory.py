"""Rejected hypothesis memory persisted across autoresearch runs."""

import json
from pathlib import Path

from .models import RejectedHypothesisSummary, ResearchLoopState


def rejected_memory_from_state(state: ResearchLoopState) -> list[RejectedHypothesisSummary]:
    """Convert rejected receipts into stable memory records."""
    return [
        RejectedHypothesisSummary(
            goalId=receipt.goal_id,
            hypothesisId=receipt.decision.hypothesis_id,
            reason=receipt.decision.reason,
            missingFacts=receipt.decision.missing_facts,
            requestedContext=receipt.requested_context,
        )
        for receipt in state.rejected_receipts
    ]


def write_rejected_memory(state: ResearchLoopState, path: str | Path) -> Path:
    """Persist rejected memory as JSONL so future loops can avoid repeated dead ends."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    records = rejected_memory_from_state(state)
    output_path.write_text(
        "".join(record.model_dump_json(by_alias=True) + "\n" for record in records),
        encoding="utf-8",
    )
    return output_path


def load_rejected_memory(path: str | Path) -> list[RejectedHypothesisSummary]:
    """Load rejected memory from JSONL or a JSON array."""
    input_path = Path(path)
    if not input_path.exists():
        return []

    text = input_path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    if text.startswith("["):
        data = json.loads(text)
        return [RejectedHypothesisSummary.model_validate(item) for item in data]

    return [
        RejectedHypothesisSummary.model_validate(json.loads(line))
        for line in text.splitlines()
        if line.strip()
    ]
