"""
Pipeline logging and orchestration utilities.

Provides:
- Structured logging to pipeline.log (JSONL format)
- SSE event broadcasting infrastructure
- Pipeline stage tracking
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .config import AuditConfig
from .models import Chain, LogStatus, PipelineLogEntry, PipelineStage, Severity

log = logging.getLogger(__name__)

# Pipeline stages in order
PIPELINE_STAGES: list[PipelineStage] = [
    PipelineStage.DISCOVERY,
    PipelineStage.TRIAGE,
    PipelineStage.RESOLVE,
    PipelineStage.DECOMPILE,
    PipelineStage.ANALYZE,
    PipelineStage.VERIFY,
    PipelineStage.REPORT,
    PipelineStage.MONITOR,
]

# SSE clients registry
_sse_clients: dict[str, asyncio.Queue] = {}


def register_sse_client(client_id: str, queue: asyncio.Queue) -> None:
    """Register an SSE client for event broadcasting."""
    _sse_clients[client_id] = queue
    log.debug("SSE client registered: %s", client_id)


def unregister_sse_client(client_id: str) -> None:
    """Unregister an SSE client."""
    _sse_clients.pop(client_id, None)
    log.debug("SSE client unregistered: %s", client_id)


async def broadcast_sse(event_type: str, data: Any) -> None:
    """Broadcast event to all SSE clients."""
    if not _sse_clients:
        return

    data_str = json.dumps(data, default=str)
    event = {"event": event_type, "data": data_str}

    for client_id, queue in list(_sse_clients.items()):
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            log.debug("SSE client %s queue full, skipping", client_id)
        except Exception as e:
            log.debug("SSE client %s disconnected: %s", client_id, e)
            _sse_clients.pop(client_id, None)


def log_pipeline_event(event: PipelineLogEntry) -> None:
    """Log pipeline event to JSONL file."""
    log_path = AuditConfig.pipeline_log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log.debug(
        "Pipeline event: %s %s %s",
        event.address[:10],
        event.stage.value,
        event.status.value,
    )

    with open(log_path, "a") as f:
        f.write(event.model_dump_json(by_alias=True) + "\n")


async def log_and_broadcast(
    address: str,
    chain: Chain,
    stage: PipelineStage,
    status: LogStatus,
    message: str | None = None,
    severity: Severity | None = None,
    balance_usd: float | None = None,
    duration: int | None = None,
    verbose: bool = True,
) -> None:
    """Log pipeline event and broadcast to SSE clients."""
    event = PipelineLogEntry(
        ts=datetime.now(UTC),
        address=address,
        chain=chain,
        stage=stage,
        status=status,
        reason=message,
        severity=severity,
        balanceUsd=balance_usd,
        duration=duration,
    )

    # Log to file
    log_pipeline_event(event)

    # Broadcast to SSE clients
    await broadcast_sse("log", event.model_dump(by_alias=True, mode="json"))

    # Console output if verbose
    if verbose:
        emoji = {
            LogStatus.FOUND: "🔍",
            LogStatus.PASS: "✅",
            LogStatus.SKIP: "⏭️",
            LogStatus.FINDING: "🚨",
            LogStatus.ERROR: "❌",
            LogStatus.COMPLETE: "✓",
        }.get(status, "•")
        print(f"{emoji} [{stage.value}] {status.value}: {message or ''}")


def read_pipeline_log(
    address: str | None = None,
    limit: int = 100,
    status_filter: LogStatus | None = None,
) -> list[PipelineLogEntry]:
    """Read pipeline log entries."""
    log_path = AuditConfig.pipeline_log_path

    if not log_path.exists():
        return []

    entries = []
    with open(log_path) as f:
        for line in f:
            try:
                data = json.loads(line)
                entry = PipelineLogEntry.model_validate(data)

                # Apply filters
                if address and entry.address.lower() != address.lower():
                    continue
                if status_filter and entry.status != status_filter:
                    continue

                entries.append(entry)
            except json.JSONDecodeError as e:
                log.warning("Malformed pipeline log line: %s", str(e)[:100])
                continue
            except Exception as e:
                log.debug("Error parsing pipeline log entry: %s", e)
                continue

    # Return most recent entries
    return entries[-limit:]


def clear_pipeline_log() -> None:
    """Clear the pipeline log."""
    log_path = AuditConfig.pipeline_log_path
    if log_path.exists():
        log_path.unlink()


@dataclass
class PipelineProgress:
    """Track pipeline progress for a contract."""

    address: str
    chain: Chain
    current_stage: PipelineStage
    stages: dict[PipelineStage, str] = field(default_factory=dict)  # stage -> status
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    balance_usd: float | None = None

    def set_stage(self, stage: PipelineStage, status: str = "active") -> None:
        """Update stage status."""
        self.current_stage = stage

        # Mark previous stages as done
        for s in PIPELINE_STAGES:
            if s == stage:
                self.stages[s] = status
                break
            if s not in self.stages or self.stages[s] == "pending":
                self.stages[s] = "done"

    def to_dict(self) -> dict:
        """Convert to dictionary for SSE broadcast."""
        stage_index = PIPELINE_STAGES.index(self.current_stage)

        return {
            "address": self.address,
            "chain": self.chain.value,
            "balance_usd": self.balance_usd,
            "started_at": self.started_at.isoformat(),
            "stageInfo": {
                "stage": self.current_stage.value,
                "stages": [
                    {
                        "id": s.value,
                        "name": s.value.capitalize(),
                        "status": (
                            "done"
                            if i < stage_index
                            else "active" if i == stage_index else "pending"
                        ),
                        "timestamp": (
                            datetime.now(UTC).isoformat() if i <= stage_index else None
                        ),
                    }
                    for i, s in enumerate(PIPELINE_STAGES)
                ],
            },
        }


# Current processing state (for API/SSE)
_current_processing: PipelineProgress | None = None


def set_current_processing(progress: PipelineProgress | None) -> None:
    """Set the currently processing contract."""
    global _current_processing
    _current_processing = progress


def get_current_processing() -> PipelineProgress | None:
    """Get the currently processing contract."""
    return _current_processing


async def update_current_stage(
    address: str, chain: Chain, stage: PipelineStage
) -> None:
    """Update current stage and broadcast to SSE clients."""
    global _current_processing

    if _current_processing and _current_processing.address.lower() == address.lower():
        _current_processing.set_stage(stage)
        await broadcast_sse("current", _current_processing.to_dict())


class PipelineContext:
    """Context manager for pipeline execution."""

    def __init__(
        self,
        address: str,
        chain: Chain,
        balance_usd: float | None = None,
        verbose: bool = True,
    ):
        self.address = address.lower()
        self.chain = chain
        self.balance_usd = balance_usd
        self.verbose = verbose
        self.progress: PipelineProgress | None = None

    async def __aenter__(self) -> "PipelineContext":
        """Start pipeline execution."""
        self.progress = PipelineProgress(
            address=self.address,
            chain=self.chain,
            current_stage=PipelineStage.TRIAGE,
            balance_usd=self.balance_usd,
        )
        set_current_processing(self.progress)
        await broadcast_sse("current", self.progress.to_dict())
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """End pipeline execution."""
        set_current_processing(None)
        await broadcast_sse("current", None)

    async def set_stage(self, stage: PipelineStage) -> None:
        """Set current pipeline stage."""
        if self.progress:
            self.progress.set_stage(stage)
            await broadcast_sse("current", self.progress.to_dict())

    async def log(
        self,
        stage: PipelineStage,
        status: LogStatus,
        message: str | None = None,
        severity: Severity | None = None,
        duration: int | None = None,
    ) -> None:
        """Log pipeline event."""
        await log_and_broadcast(
            address=self.address,
            chain=self.chain,
            stage=stage,
            status=status,
            message=message,
            severity=severity,
            balance_usd=self.balance_usd,
            duration=duration,
            verbose=self.verbose,
        )
