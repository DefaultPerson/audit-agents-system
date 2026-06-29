"""Tests for pipeline utilities."""

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from src.models import Chain, LogStatus, PipelineLogEntry, PipelineStage
from src.pipeline import (
    PIPELINE_STAGES,
    PipelineContext,
    PipelineProgress,
    broadcast_sse,
    clear_pipeline_log,
    log_and_broadcast,
    log_pipeline_event,
    read_pipeline_log,
    register_sse_client,
    unregister_sse_client,
)


class TestSSEClientManagement:
    """Tests for SSE client registration."""

    def test_register_and_unregister(self) -> None:
        """Register and unregister SSE client."""
        queue: asyncio.Queue = asyncio.Queue()

        register_sse_client("test-client", queue)
        # Unregister should not raise
        unregister_sse_client("test-client")

        # Unregistering non-existent client should not raise
        unregister_sse_client("non-existent")


class TestBroadcastSSE:
    """Tests for SSE broadcasting."""

    @pytest.mark.asyncio
    async def test_broadcast_to_clients(self) -> None:
        """Broadcast event to registered clients."""
        queue: asyncio.Queue = asyncio.Queue()
        register_sse_client("test-client", queue)

        try:
            await broadcast_sse("test_event", {"key": "value"})

            # Check queue received event
            event = queue.get_nowait()
            assert event["event"] == "test_event"
            assert "value" in event["data"]
        finally:
            unregister_sse_client("test-client")

    @pytest.mark.asyncio
    async def test_broadcast_no_clients(self) -> None:
        """Broadcast with no clients does nothing."""
        # Should not raise
        await broadcast_sse("test_event", {"data": "test"})

    @pytest.mark.asyncio
    async def test_broadcast_full_queue(self) -> None:
        """Skip client with full queue."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=1)
        queue.put_nowait({"dummy": "event"})  # Fill queue

        register_sse_client("full-client", queue)

        try:
            # Should not raise, just skip
            await broadcast_sse("test_event", {"data": "test"})
        finally:
            unregister_sse_client("full-client")


class TestLogPipelineEvent:
    """Tests for pipeline event logging."""

    def test_log_event_creates_file(self, tmp_path: Path) -> None:
        """Log event creates JSONL file."""
        log_path = tmp_path / "pipeline.log"

        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = log_path

            event = PipelineLogEntry(
                ts=datetime.now(UTC),
                address="0xabc123def456789012345678901234567890abcd",
                chain=Chain.ETH,
                stage=PipelineStage.TRIAGE,
                status=LogStatus.FOUND,
                reason="Test event",
            )
            log_pipeline_event(event)

            assert log_path.exists()
            content = log_path.read_text()
            assert "0xabc123" in content

    def test_log_multiple_events(self, tmp_path: Path) -> None:
        """Multiple events appended to file."""
        log_path = tmp_path / "pipeline.log"

        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = log_path

            for i in range(3):
                event = PipelineLogEntry(
                    ts=datetime.now(UTC),
                    address=f"0x{i:040x}",
                    chain=Chain.ETH,
                    stage=PipelineStage.TRIAGE,
                    status=LogStatus.FOUND,
                )
                log_pipeline_event(event)

            lines = log_path.read_text().strip().split("\n")
            assert len(lines) == 3


class TestReadPipelineLog:
    """Tests for reading pipeline log."""

    def test_read_empty_log(self, tmp_path: Path) -> None:
        """Returns empty list for non-existent log."""
        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = tmp_path / "nonexistent.log"

            entries = read_pipeline_log()
            assert entries == []

    def test_read_with_address_filter(self, tmp_path: Path) -> None:
        """Filter entries by address."""
        log_path = tmp_path / "pipeline.log"

        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = log_path

            # Write test entries
            for addr in ["0x" + "a" * 40, "0x" + "b" * 40, "0x" + "a" * 40]:
                event = PipelineLogEntry(
                    ts=datetime.now(UTC),
                    address=addr,
                    chain=Chain.ETH,
                    stage=PipelineStage.TRIAGE,
                    status=LogStatus.FOUND,
                )
                log_pipeline_event(event)

            entries = read_pipeline_log(address="0x" + "a" * 40)
            assert len(entries) == 2
            assert all(e.address == "0x" + "a" * 40 for e in entries)

    def test_read_with_limit(self, tmp_path: Path) -> None:
        """Limit number of returned entries."""
        log_path = tmp_path / "pipeline.log"

        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = log_path

            for i in range(10):
                event = PipelineLogEntry(
                    ts=datetime.now(UTC),
                    address=f"0x{i:040x}",
                    chain=Chain.ETH,
                    stage=PipelineStage.TRIAGE,
                    status=LogStatus.FOUND,
                )
                log_pipeline_event(event)

            entries = read_pipeline_log(limit=5)
            assert len(entries) == 5

    def test_read_with_status_filter(self, tmp_path: Path) -> None:
        """Filter entries by status."""
        log_path = tmp_path / "pipeline.log"

        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = log_path

            for i, status in enumerate([LogStatus.FOUND, LogStatus.PASS, LogStatus.FOUND]):
                event = PipelineLogEntry(
                    ts=datetime.now(UTC),
                    address=f"0x{i:040x}",
                    chain=Chain.ETH,
                    stage=PipelineStage.TRIAGE,
                    status=status,
                )
                log_pipeline_event(event)

            entries = read_pipeline_log(status_filter=LogStatus.FOUND)
            assert len(entries) == 2
            assert all(e.status == LogStatus.FOUND for e in entries)

    def test_read_malformed_entries(self, tmp_path: Path) -> None:
        """Skip malformed entries gracefully."""
        log_path = tmp_path / "pipeline.log"

        # Write some valid and invalid lines
        with open(log_path, "w") as f:
            # Valid entry
            event = PipelineLogEntry(
                ts=datetime.now(UTC),
                address="0x" + "a" * 40,
                chain=Chain.ETH,
                stage=PipelineStage.TRIAGE,
                status=LogStatus.FOUND,
            )
            f.write(event.model_dump_json(by_alias=True) + "\n")
            # Malformed JSON
            f.write("not json at all\n")
            # Another valid entry
            event2 = PipelineLogEntry(
                ts=datetime.now(UTC),
                address="0x" + "b" * 40,
                chain=Chain.ETH,
                stage=PipelineStage.RESOLVE,
                status=LogStatus.PASS,
            )
            f.write(event2.model_dump_json(by_alias=True) + "\n")

        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = log_path

            entries = read_pipeline_log()
            # Should have 2 valid entries, skipping the malformed one
            assert len(entries) == 2


class TestClearPipelineLog:
    """Tests for clearing pipeline log."""

    def test_clear_existing_log(self, tmp_path: Path) -> None:
        """Clear existing log file."""
        log_path = tmp_path / "pipeline.log"
        log_path.write_text("some content")

        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = log_path

            clear_pipeline_log()

            assert not log_path.exists()

    def test_clear_nonexistent_log(self, tmp_path: Path) -> None:
        """Clear non-existent log does not raise."""
        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = tmp_path / "nonexistent.log"

            # Should not raise
            clear_pipeline_log()


class TestPipelineProgress:
    """Tests for PipelineProgress dataclass."""

    def test_initial_state(self) -> None:
        """Initial progress state."""
        progress = PipelineProgress(
            address="0xabc123",
            chain=Chain.ETH,
            current_stage=PipelineStage.TRIAGE,
        )
        assert progress.current_stage == PipelineStage.TRIAGE
        assert progress.stages == {}

    def test_set_stage_marks_previous_done(self) -> None:
        """Setting stage marks previous stages as done."""
        progress = PipelineProgress(
            address="0xabc123",
            chain=Chain.ETH,
            current_stage=PipelineStage.TRIAGE,
        )

        progress.set_stage(PipelineStage.DECOMPILE)

        assert progress.current_stage == PipelineStage.DECOMPILE
        # Previous stages should be "done"
        assert progress.stages.get(PipelineStage.DISCOVERY) == "done"
        assert progress.stages.get(PipelineStage.TRIAGE) == "done"
        assert progress.stages.get(PipelineStage.RESOLVE) == "done"
        assert progress.stages.get(PipelineStage.DECOMPILE) == "active"

    def test_to_dict(self) -> None:
        """Convert progress to dict for SSE."""
        progress = PipelineProgress(
            address="0xabc123",
            chain=Chain.ETH,
            current_stage=PipelineStage.ANALYZE,
            balance_usd=100000.0,
        )

        data = progress.to_dict()

        assert data["address"] == "0xabc123"
        assert data["chain"] == "eth"
        assert data["balance_usd"] == 100000.0
        assert "stageInfo" in data
        assert data["stageInfo"]["stage"] == "analyze"

    def test_to_dict_stages_structure(self) -> None:
        """to_dict produces correct stages structure."""
        progress = PipelineProgress(
            address="0xtest",
            chain=Chain.BSC,
            current_stage=PipelineStage.RESOLVE,
        )

        data = progress.to_dict()

        stages = data["stageInfo"]["stages"]
        assert len(stages) == len(PIPELINE_STAGES)

        # Check stage order and status
        stage_map = {s["id"]: s["status"] for s in stages}
        assert stage_map["discovery"] == "done"
        assert stage_map["triage"] == "done"
        assert stage_map["resolve"] == "active"
        assert stage_map["decompile"] == "pending"


class TestPipelineContext:
    """Tests for PipelineContext context manager."""

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        """Pipeline context manager lifecycle."""
        with patch("src.pipeline.broadcast_sse", new_callable=AsyncMock) as mock_broadcast:
            async with PipelineContext("0xabc123", Chain.ETH) as ctx:
                assert ctx.progress is not None
                assert ctx.address == "0xabc123"

            # Should broadcast None on exit
            mock_broadcast.assert_called()

    @pytest.mark.asyncio
    async def test_set_stage(self) -> None:
        """Set stage during pipeline execution."""
        with patch("src.pipeline.broadcast_sse", new_callable=AsyncMock):
            async with PipelineContext("0xabc123", Chain.ETH) as ctx:
                await ctx.set_stage(PipelineStage.RESOLVE)

                assert ctx.progress is not None
                assert ctx.progress.current_stage == PipelineStage.RESOLVE

    @pytest.mark.asyncio
    async def test_log_event(self) -> None:
        """Log event from context."""
        with (
            patch("src.pipeline.broadcast_sse", new_callable=AsyncMock),
            patch("src.pipeline.log_pipeline_event") as mock_log,
        ):
            async with PipelineContext("0xabc123", Chain.ETH, verbose=False) as ctx:
                await ctx.log(
                    PipelineStage.TRIAGE,
                    LogStatus.PASS,
                    "Test message",
                )

                mock_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_with_balance(self) -> None:
        """Context with balance_usd."""
        with patch("src.pipeline.broadcast_sse", new_callable=AsyncMock):
            async with PipelineContext(
                "0xabc123", Chain.ETH, balance_usd=50000.0
            ) as ctx:
                assert ctx.balance_usd == 50000.0
                assert ctx.progress is not None
                assert ctx.progress.balance_usd == 50000.0


class TestLogAndBroadcast:
    """Tests for log_and_broadcast function."""

    @pytest.mark.asyncio
    async def test_logs_and_broadcasts(self, tmp_path: Path) -> None:
        """Logs to file and broadcasts to SSE."""
        log_path = tmp_path / "pipeline.log"

        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = log_path

            with patch("src.pipeline.broadcast_sse", new_callable=AsyncMock) as mock_sse:
                await log_and_broadcast(
                    address="0x" + "a" * 40,
                    chain=Chain.ETH,
                    stage=PipelineStage.TRIAGE,
                    status=LogStatus.FOUND,
                    message="Test message",
                    verbose=False,
                )

                # File should have entry
                assert log_path.exists()

                # SSE should be called
                mock_sse.assert_called_once()

    @pytest.mark.asyncio
    async def test_verbose_output(self, tmp_path: Path, capsys) -> None:
        """Verbose mode prints to console."""
        log_path = tmp_path / "pipeline.log"

        with patch("src.pipeline.AuditConfig") as mock_config:
            mock_config.pipeline_log_path = log_path

            with patch("src.pipeline.broadcast_sse", new_callable=AsyncMock):
                await log_and_broadcast(
                    address="0x" + "a" * 40,
                    chain=Chain.ETH,
                    stage=PipelineStage.TRIAGE,
                    status=LogStatus.FOUND,
                    message="Verbose test",
                    verbose=True,
                )

                captured = capsys.readouterr()
                assert "triage" in captured.out.lower()
