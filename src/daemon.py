"""
Daemon - Autonomous queue processor and full audit pipeline orchestration.

Processes contracts from queue through full audit pipeline:
TRIAGE → RESOLVE → DECOMPILE → ANALYZE → VERIFY → REPORT
"""

import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from .db import AsyncDatabase
from .models import (
    AuditResult,
    Chain,
    LogStatus,
    PipelineStage,
    QueueItem,
    Severity,
    VulnerabilityFinding,
)
from .pipeline import (
    PipelineContext,
    broadcast_sse,
)
from .stages.decompile import decompile_contract
from .stages.parallel_audit import (
    PreAuditResult,
    aggregate_findings,
    run_parallel_audit,
)
from .stages.report import build_report, generate_initial_report
from .stages.resolve import get_bytecode, resolve_contract
from .stages.triage import triage_contract


class AuditDaemon:
    """Autonomous audit daemon that processes contracts from queue."""

    def __init__(
        self,
        db: AsyncDatabase | None = None,
        verbose: bool = True,
        use_rag: bool = True,
        skip_dedaub: bool = False,
    ):
        self.db = db
        self.verbose = verbose
        self.use_rag = use_rag
        self.skip_dedaub = skip_dedaub
        self._running = False
        self._current_address: str | None = None

    async def _get_db(self) -> AsyncDatabase:
        """Get or create database connection."""
        if self.db is None:
            self.db = AsyncDatabase()
            await self.db.connect()
        return self.db

    async def process_contract(
        self,
        address: str,
        chain: Chain,
        balance_usd: float = 0,
        block_number: int | None = None,
    ) -> tuple[AuditResult, list[VulnerabilityFinding], str | None]:
        """
        Process a single contract through full audit pipeline.

        Returns (result, findings, report_path).
        """
        address = address.lower()
        started_at = datetime.now(UTC).isoformat()
        self._current_address = address

        async with PipelineContext(address, chain, balance_usd, self.verbose) as ctx:
            findings: list[VulnerabilityFinding] = []
            rag_used = False
            error_message: str | None = None

            try:
                # ============================================
                # Stage 1: TRIAGE
                # ============================================
                await ctx.set_stage(PipelineStage.TRIAGE)
                await ctx.log(
                    PipelineStage.TRIAGE, LogStatus.FOUND, f"Starting triage: {address}"
                )

                triage_start = time.time()
                triage_result = await triage_contract(address, chain, balance_usd)
                triage_duration = int((time.time() - triage_start) * 1000)

                if not triage_result.passed:
                    await ctx.log(
                        PipelineStage.TRIAGE,
                        LogStatus.SKIP,
                        f"Skipped: {triage_result.skip_reason.value if triage_result.skip_reason else 'unknown'}",
                        duration=triage_duration,
                    )
                    return AuditResult.CLEAN, [], None

                await ctx.log(
                    PipelineStage.TRIAGE,
                    LogStatus.PASS,
                    f"Passed triage (proxy={triage_result.is_proxy}, size={triage_result.code_size})",
                    duration=triage_duration,
                )

                # ============================================
                # Stage 2: RESOLVE
                # ============================================
                await ctx.set_stage(PipelineStage.RESOLVE)

                resolve_start = time.time()
                resolved = await resolve_contract(address, chain)
                resolve_duration = int((time.time() - resolve_start) * 1000)

                if resolved.is_proxy:
                    await ctx.log(
                        PipelineStage.RESOLVE,
                        LogStatus.PASS,
                        f"Proxy detected: {resolved.proxy_type.value if resolved.proxy_type else 'unknown'} → {resolved.resolved_address}",
                        duration=resolve_duration,
                    )
                else:
                    await ctx.log(
                        PipelineStage.RESOLVE,
                        LogStatus.PASS,
                        f"Resolved: {len(resolved.selectors or [])} selectors",
                        duration=resolve_duration,
                    )

                # ============================================
                # Stage 3: DECOMPILE
                # ============================================
                await ctx.set_stage(PipelineStage.DECOMPILE)

                bytecode = await get_bytecode(resolved.resolved_address, chain)
                if not bytecode:
                    await ctx.log(
                        PipelineStage.DECOMPILE, LogStatus.ERROR, "No bytecode"
                    )
                    return AuditResult.ERROR, [], None

                decompile_start = time.time()
                success, decompile_dir, sol_file = await decompile_contract(
                    resolved.resolved_address,
                    chain,
                    bytecode.hex(),
                    skip_dedaub=self.skip_dedaub,
                )
                decompile_duration = int((time.time() - decompile_start) * 1000)

                if not success:
                    await ctx.log(
                        PipelineStage.DECOMPILE,
                        LogStatus.ERROR,
                        "Decompilation failed",
                        duration=decompile_duration,
                    )
                    error_message = "Decompilation failed"
                    return AuditResult.ERROR, [], None

                await ctx.log(
                    PipelineStage.DECOMPILE,
                    LogStatus.PASS,
                    f"Decompiled: {sol_file or 'gigahorse output'}",
                    duration=decompile_duration,
                )

                # ============================================
                # Stage 4: ANALYZE (Parallel - 3 instances)
                # ============================================
                await ctx.set_stage(PipelineStage.ANALYZE)

                # Build pre-audit result for parallel audit
                pre_audit = PreAuditResult(
                    address=address,
                    chain=chain.value,
                    balance_usd=balance_usd,
                    is_proxy=resolved.is_proxy,
                    proxy_type=(
                        resolved.proxy_type.value if resolved.proxy_type else None
                    ),
                    resolved_address=resolved.resolved_address,
                    decompile_dir=str(decompile_dir),
                    dedaub_file=str(sol_file) if sol_file else None,
                )

                analyze_start = time.time()
                parallel_result = await run_parallel_audit(
                    pre_audit,
                    max_retries=3,
                    verbose=self.verbose,
                    use_rag=self.use_rag,
                )
                analyze_duration = int((time.time() - analyze_start) * 1000)

                if parallel_result.all_failed:
                    await ctx.log(
                        PipelineStage.ANALYZE,
                        LogStatus.ERROR,
                        "All parallel instances failed",
                        duration=analyze_duration,
                    )
                    error_message = "All parallel audit instances failed"
                    return AuditResult.ERROR, [], None

                # Aggregate findings from all reports
                findings = aggregate_findings(parallel_result.report_paths)
                rag_used = self.use_rag  # RAG context embedded in prompt if enabled

                if findings:
                    severity_counts: dict[str, int] = {}
                    for f in findings:
                        sev = f.severity.value
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1

                    await ctx.log(
                        PipelineStage.ANALYZE,
                        LogStatus.FINDING,
                        f"Parallel audit: {parallel_result.success_count}/3 instances, {len(findings)} findings: {severity_counts}",
                        severity=findings[0].severity if findings else None,
                        duration=analyze_duration,
                    )
                else:
                    await ctx.log(
                        PipelineStage.ANALYZE,
                        LogStatus.PASS,
                        f"Parallel audit: {parallel_result.success_count}/3 instances, no vulnerabilities",
                        duration=analyze_duration,
                    )

                # ============================================
                # Stage 5: REPORT (Initial - PoC triggered by button)
                # ============================================
                # NOTE: VERIFY stage is now triggered by Telegram button click
                # See telegram_bot.py handle_poc_callback()
                await ctx.set_stage(PipelineStage.REPORT)

                # Read decompiled code for potential PoC generation (via button)
                decompiled_code = ""
                if sol_file and Path(sol_file).exists():
                    decompiled_code = Path(sol_file).read_text()

                critical_count = sum(
                    1 for f in findings if f.severity == Severity.CRITICAL
                )

                status = AuditResult.VULNERABLE if findings else AuditResult.CLEAN

                report = build_report(
                    address=address,
                    chain=chain,
                    started_at=started_at,
                    status=status,
                    findings=findings,
                    rag_context_used=rag_used,
                    error_message=error_message,
                )

                # Send initial report with PoC button if CRITICAL findings
                report_path, notified = await generate_initial_report(
                    report, decompiled_code
                )

                poc_note = ", PoC button available" if critical_count > 0 else ""
                await ctx.log(
                    PipelineStage.REPORT,
                    LogStatus.COMPLETE,
                    f"Report: {Path(report_path).name} (notified={notified}{poc_note})",
                )

                return status, findings, report_path

            except Exception as e:
                error_message = str(e)
                await ctx.log(
                    (
                        ctx.progress.current_stage
                        if ctx.progress
                        else PipelineStage.TRIAGE
                    ),
                    LogStatus.ERROR,
                    f"Pipeline error: {error_message[:200]}",
                )
                return AuditResult.ERROR, [], None

            finally:
                self._current_address = None

    async def process_queue_item(self, item: QueueItem) -> None:
        """Process a single queue item."""
        db = await self._get_db()

        try:
            chain = Chain(item.chain)
            result, findings, report_path = await self.process_contract(
                item.address, chain, item.balance_usd or 0
            )

            # Update queue status
            result_json = json.dumps(
                {
                    "status": result.value,
                    "findings_count": len(findings),
                    "report_path": report_path,
                }
            )
            await db.mark_queue_processed(item.address, item.chain, result_json)

            # Broadcast completion
            await broadcast_sse(
                "queue_done",
                {
                    "address": item.address,
                    "chain": item.chain,
                    "result": result.value,
                    "findings_count": len(findings),
                },
            )

        except Exception as e:
            await db.mark_queue_failed(item.address, item.chain, str(e)[:500])
            await broadcast_sse(
                "queue_error",
                {
                    "address": item.address,
                    "chain": item.chain,
                    "error": str(e)[:200],
                },
            )

    async def run_loop(self, poll_interval: float = 5.0) -> None:
        """Run continuous queue processing loop."""
        self._running = True
        db = await self._get_db()

        print(f"[Daemon] Started, polling every {poll_interval}s")

        while self._running:
            try:
                # Get next item from queue
                item = await db.get_next_from_queue()

                if item:
                    print(f"[Daemon] Processing: {item.address} ({item.chain})")
                    await broadcast_sse(
                        "queue_start",
                        {
                            "address": item.address,
                            "chain": item.chain,
                            "balance_usd": item.balance_usd,
                        },
                    )
                    await self.process_queue_item(item)
                else:
                    # No items in queue, wait
                    await asyncio.sleep(poll_interval)

            except asyncio.CancelledError:
                print("[Daemon] Cancelled")
                break
            except Exception as e:
                print(f"[Daemon] Error: {e}")
                await asyncio.sleep(poll_interval)

        print("[Daemon] Stopped")

    def stop(self) -> None:
        """Stop the daemon loop."""
        self._running = False

    @property
    def is_running(self) -> bool:
        """Check if daemon is running."""
        return self._running

    @property
    def current_address(self) -> str | None:
        """Get currently processing address."""
        return self._current_address


# Singleton daemon instance
_daemon: AuditDaemon | None = None


def get_daemon() -> AuditDaemon:
    """Get or create the daemon instance."""
    global _daemon
    if _daemon is None:
        _daemon = AuditDaemon()
    return _daemon


async def run_single_audit(
    address: str,
    chain: str,
    balance_usd: float = 0,
    use_rag: bool = True,
    skip_dedaub: bool = False,
    verbose: bool = True,
) -> tuple[AuditResult, list[VulnerabilityFinding], str | None]:
    """
    Run a single audit without queue.

    Convenience function for CLI and direct usage.
    """
    daemon = AuditDaemon(
        verbose=verbose,
        use_rag=use_rag,
        skip_dedaub=skip_dedaub,
    )
    return await daemon.process_contract(address, Chain(chain), balance_usd)
