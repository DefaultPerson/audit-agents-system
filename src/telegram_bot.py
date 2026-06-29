"""
Telegram Bot with interactive PoC verification buttons.

Uses python-telegram-bot library for:
- Polling mode for receiving updates
- InlineKeyboardMarkup for PoC verification buttons
- Callback handlers for button clicks
"""

import asyncio
import json
import logging
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, ContextTypes

from .config import TelegramConfig, get_chain_config, settings
from .models import AuditReport, Chain, Severity, VulnerabilityFinding

logger = logging.getLogger(__name__)


@dataclass
class PendingPoC:
    """Pending PoC verification request."""

    address: str
    chain: Chain
    findings: list[VulnerabilityFinding]
    decompiled_code: str
    report_path: str
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON storage."""
        return {
            "address": self.address,
            "chain": self.chain.value,
            "findings": [f.model_dump(mode="json") for f in self.findings],
            "decompiled_code": self.decompiled_code,
            "report_path": self.report_path,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PendingPoC":
        """Deserialize from dict."""
        return cls(
            address=data["address"],
            chain=Chain(data["chain"]),
            findings=[VulnerabilityFinding.model_validate(f) for f in data["findings"]],
            decompiled_code=data["decompiled_code"],
            report_path=data["report_path"],
            created_at=datetime.fromisoformat(data["created_at"]),
        )


def _load_pending_poc() -> dict[str, PendingPoC]:
    """Load pending PoC from file storage."""
    path = TelegramConfig.pending_poc_file
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        return {k: PendingPoC.from_dict(v) for k, v in data.items()}
    except Exception as e:
        logger.error(f"Failed to load pending_poc: {e}")
        return {}


def _save_pending_poc(pending: dict[str, PendingPoC]) -> None:
    """Save pending PoC to file storage."""
    path = TelegramConfig.pending_poc_file
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = {k: v.to_dict() for k, v in pending.items()}
        path.write_text(json.dumps(data, indent=2))
    except Exception as e:
        logger.error(f"Failed to save pending_poc: {e}")


# Global bot application instance
_app: Application | None = None


def _make_callback_key(chat_id: int, message_id: int) -> str:
    """Create unique key for pending PoC storage."""
    return f"{chat_id}:{message_id}"


def _has_critical_findings(findings: list[VulnerabilityFinding]) -> bool:
    """Check if there are CRITICAL findings that can be verified."""
    return any(
        f.severity == Severity.CRITICAL and f.confidence >= 0.6
        for f in findings
    )


async def send_initial_report(
    report: AuditReport,
    report_path: str,
    decompiled_code: str,
) -> tuple[bool, int | None]:
    """
    Send initial audit report with optional 'Run PoC' button.

    Args:
        report: Audit report object
        report_path: Path to markdown report file
        decompiled_code: Decompiled contract code for PoC generation

    Returns:
        (success, message_id) - message_id is needed for callback tracking
    """
    # NOTE: Requires the user's OWN Telegram bot token/chat ID; this tool is
    # for testnet/authorized targets only and ships no credentials.
    bot_token = settings.telegram_bot_token
    chat_id = settings.telegram_chat_id

    if not bot_token or not chat_id:
        logger.warning("Telegram not configured, skipping notification")
        return False, None

    # Build caption
    chain_config = get_chain_config(report.chain.value)
    lines = [
        "🚨 *VULNERABILITY FOUND*" if report.findings else "✅ *AUDIT COMPLETE*",
        "",
        f"Address: `{report.address}`",
        f"Chain: {chain_config.name}",
    ]

    if report.findings_count.critical > 0:
        lines.append(f"🔴 Critical: {report.findings_count.critical}")
    if report.findings_count.high > 0:
        lines.append(f"🟠 High: {report.findings_count.high}")
    if report.findings_count.medium > 0:
        lines.append(f"🟡 Medium: {report.findings_count.medium}")
    if report.findings_count.low > 0:
        lines.append(f"🔵 Low: {report.findings_count.low}")

    if report.total_profit_usd:
        lines.append(f"💰 Est. Profit: ${report.total_profit_usd:,.0f}")

    # Add top findings
    top_findings = report.findings[:3]
    if top_findings:
        lines.append("")
        lines.append("*Top findings:*")
        for f in top_findings:
            sev = f.severity.value.upper()[:4]
            title = f.title[:40]
            lines.append(f"• [{sev}] {title}")

    caption = "\n".join(lines)[:1000]

    # Build keyboard with PoC button if applicable
    keyboard = None
    has_critical = _has_critical_findings(report.findings)
    if has_critical:
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("🧪 Run PoC Verification", callback_data="run_poc")]
        ])

    try:
        from telegram import Bot

        bot = Bot(token=bot_token)

        # Send document with caption
        file_path = Path(report_path)
        if file_path.exists():
            file_bytes = await asyncio.to_thread(file_path.read_bytes)
            message = await bot.send_document(
                chat_id=chat_id,
                document=file_bytes,
                filename=file_path.name,
                caption=caption,
                parse_mode="Markdown",
                reply_markup=keyboard,
            )
        else:
            # Fallback to text message if no file
            message = await bot.send_message(
                chat_id=chat_id,
                text=caption,
                parse_mode="Markdown",
                reply_markup=keyboard,
            )

        # Store pending PoC data if button was added (file-based for cross-process sharing)
        if has_critical and message:
            key = _make_callback_key(int(chat_id), message.message_id)
            pending = _load_pending_poc()
            pending[key] = PendingPoC(
                address=report.address,
                chain=report.chain,
                findings=report.findings,
                decompiled_code=decompiled_code,
                report_path=report_path,
                created_at=datetime.now(UTC),
            )
            _save_pending_poc(pending)
            logger.info(f"Stored pending PoC: {key}")

        return True, message.message_id if message else None

    except Exception as e:
        logger.error(f"Failed to send initial report: {e}")
        return False, None


async def send_final_report(
    address: str,
    chain: Chain,
    findings: list[VulnerabilityFinding],
    report_path: str | None = None,
    reply_to_message_id: int | None = None,
) -> bool:
    """
    Send final report after PoC verification.

    Args:
        address: Contract address
        chain: Chain enum
        findings: Updated findings with verified status
        report_path: Path to final report file (optional)
    """
    bot_token = settings.telegram_bot_token
    chat_id = settings.telegram_chat_id

    if not bot_token or not chat_id:
        return False

    verified = [f for f in findings if f.verified]
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    failed = [f for f in critical if not f.verified]

    chain_config = get_chain_config(chain.value)
    short_addr = f"{address[:6]}...{address[-4:]}"

    lines = [
        "✅ *PoC Verification Complete*",
        "",
        f"Contract: `{short_addr}`",
        f"Chain: {chain_config.name}",
        "",
        f"Results: *{len(verified)}/{len(critical)}* exploitable",
    ]

    if verified:
        lines.append("")
        lines.append("✅ *Verified Exploits:*")
        for f in verified[:5]:
            title = f.title[:45] if len(f.title) > 45 else f.title
            lines.append(f"• {title}")

    if failed and len(failed) <= 5:
        lines.append("")
        lines.append("❌ *Not Exploitable:*")
        for f in failed:
            title = f.title[:45] if len(f.title) > 45 else f.title
            lines.append(f"• {title}")
    elif failed:
        lines.append("")
        lines.append(f"❌ *Not Exploitable:* {len(failed)} findings")

    text = "\n".join(lines)

    try:
        from telegram import Bot

        bot = Bot(token=bot_token)

        # Send final report file if available
        if report_path and (file_path := Path(report_path)).exists():
            file_bytes = await asyncio.to_thread(file_path.read_bytes)
            await bot.send_document(
                chat_id=chat_id,
                document=file_bytes,
                filename=file_path.name,
                caption=text,
                parse_mode="Markdown",
                reply_to_message_id=reply_to_message_id,
            )
        else:
            await bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode="Markdown",
                reply_to_message_id=reply_to_message_id,
            )

        return True

    except Exception as e:
        logger.error(f"Failed to send final report: {e}")
        return False


async def handle_poc_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle 'Run PoC Verification' button click.

    1. Block duplicate clicks by removing button immediately
    2. Retrieve stored data
    3. Run verify stage
    4. Send final report
    """
    query = update.callback_query
    if not query or not query.message:
        return

    await query.answer()

    if update.effective_chat is None:
        return
    chat_id = update.effective_chat.id
    message_id = query.message.message_id
    key = _make_callback_key(chat_id, message_id)

    # Load from file storage (shared with pipeline process)
    pending = _load_pending_poc()

    # Check if already processed or expired
    if key not in pending:
        logger.warning(f"PoC request not found or expired: {key}")
        with suppress(Exception):
            await query.edit_message_reply_markup(reply_markup=None)
        return

    # Block duplicate clicks - remove button immediately
    try:
        await query.edit_message_reply_markup(reply_markup=None)
    except Exception as e:
        logger.warning(f"Failed to remove button: {e}")

    # Get stored data and remove from file
    data = pending.pop(key)
    _save_pending_poc(pending)
    logger.info(f"Processing PoC for {data.address}")

    # Send "in progress" message
    progress_msg = await context.bot.send_message(
        chat_id=chat_id,
        text=f"🧪 *PoC Verification in Progress...*\n\nTesting {sum(1 for f in data.findings if f.severity == Severity.CRITICAL and f.confidence >= 0.6)} CRITICAL findings...",
        parse_mode="Markdown",
    )

    try:
        # Import verify stage
        from .stages.verify import run_verify

        # Run PoC verification
        updated_findings = await run_verify(
            data.address,
            data.chain,
            data.findings,
            data.decompiled_code,
        )

        # Generate final report
        from .models import AuditResult
        from .stages.report import build_report, save_report

        status = AuditResult.VULNERABLE if any(f.verified for f in updated_findings) else AuditResult.CLEAN

        final_report = build_report(
            address=data.address,
            chain=data.chain,
            started_at=data.created_at.isoformat(),
            status=status,
            findings=updated_findings,
            rag_context_used=False,
        )

        final_report_path = save_report(final_report)

        # Delete progress message
        with suppress(Exception):
            await progress_msg.delete()

        # Send final report as reply to original message
        await send_final_report(
            data.address,
            data.chain,
            updated_findings,
            final_report_path,
            reply_to_message_id=message_id,
        )

    except Exception as e:
        logger.error(f"PoC verification failed: {e}")
        # Edit progress message to show error
        with suppress(Exception):
            await progress_msg.edit_text(
                f"❌ *PoC Verification Failed*\n\nError: {str(e)[:200]}",
                parse_mode="Markdown",
            )


async def send_message(text: str, parse_mode: str = "Markdown") -> bool:
    """Send a simple text message (backward compatibility)."""
    bot_token = settings.telegram_bot_token
    chat_id = settings.telegram_chat_id

    if not bot_token or not chat_id:
        return False

    try:
        from telegram import Bot

        bot = Bot(token=bot_token)
        await bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode=parse_mode,
            disable_web_page_preview=True,
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send message: {e}")
        return False


async def run_bot() -> None:
    """
    Run Telegram bot with polling mode.

    This should be run as a separate process/task alongside the daemon.
    """
    bot_token = settings.telegram_bot_token

    if not bot_token:
        logger.error("TELEGRAM_BOT_TOKEN not configured")
        return

    global _app

    # Build application
    _app = Application.builder().token(bot_token).build()

    # Add callback handler for PoC button
    _app.add_handler(CallbackQueryHandler(handle_poc_callback, pattern="^run_poc$"))

    logger.info("Starting Telegram bot polling...")

    # Start polling
    await _app.initialize()
    await _app.start()
    if _app.updater is None:
        raise RuntimeError("Telegram updater is not available")
    updater = _app.updater
    await updater.start_polling(drop_pending_updates=True)

    # Keep running until stopped
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        logger.info("Stopping Telegram bot...")
        await updater.stop()
        await _app.stop()
        await _app.shutdown()


def get_pending_poc_count() -> int:
    """Get count of pending PoC requests (for monitoring)."""
    return len(_load_pending_poc())


def clear_expired_poc(max_age_hours: int = 24) -> int:
    """
    Clear expired pending PoC requests.

    Args:
        max_age_hours: Maximum age in hours before expiration

    Returns:
        Number of cleared entries
    """
    pending = _load_pending_poc()
    now = datetime.now(UTC)
    expired_keys = []

    for key, data in pending.items():
        age = (now - data.created_at).total_seconds() / 3600
        if age > max_age_hours:
            expired_keys.append(key)

    for key in expired_keys:
        del pending[key]
        logger.info(f"Cleared expired PoC request: {key}")

    if expired_keys:
        _save_pending_poc(pending)

    return len(expired_keys)
