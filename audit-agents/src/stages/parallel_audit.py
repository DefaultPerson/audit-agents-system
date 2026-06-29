"""
Parallel Audit - Spawn multiple Claude Code headless instances.

Runs 2-3 identical Claude instances with /ultrathink on the same contract.
Each instance generates an independent audit report.
"""

import asyncio
import json
import logging
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import AuditConfig, RAGConfig, get_audit_dir, settings
from ..models import (
    Chain,
    FindingSource,
    Severity,
    VulnerabilityFinding,
    VulnerabilityLocation,
    VulnerabilityType,
)

log = logging.getLogger(__name__)


async def fetch_rag_context(code: str, top_k: int = 3) -> str:
    """
    Fetch relevant exploit examples from RAG database.

    Extracts key patterns from code and searches for similar exploits.
    Returns formatted context string for inclusion in audit prompt.
    """
    try:
        from ..rag.search import hybrid_search

        # Extract key terms from code for search
        search_terms = []

        # Look for common vulnerability patterns in code
        patterns = [
            ("bonding curve", "bonding curve reserve price manipulation"),
            ("getpurchaseprice", "bonding curve reserve manipulation overflow"),
            ("getsellprice", "bonding curve reserve manipulation"),
            ("_reserve", "reserve manipulation bonding curve"),
            ("totalsupply", "token supply manipulation"),
            ("oracle", "oracle price manipulation"),
            ("flashloan", "flash loan attack"),
            ("flash", "flash loan manipulation"),
            ("reentrancy", "reentrancy callback"),
            ("delegatecall", "delegatecall arbitrary"),
            ("mint", "mint access control"),
            ("burn", "burn token manipulation"),
            ("swap", "swap slippage AMM"),
            ("reward", "reward calculation"),
            ("stake", "staking reward manipulation"),
            ("withdraw", "withdraw access control"),
            ("transfer", "transfer fee token"),
            ("approve", "approval race condition"),
            ("safesub", "integer overflow underflow"),
            ("safeadd", "integer overflow"),
            ("safemul", "integer overflow multiplication"),
        ]

        code_lower = code.lower()
        for keyword, query in patterns:
            if keyword in code_lower:
                search_terms.append(query)

        # Default search if no patterns found
        if not search_terms:
            search_terms = ["smart contract vulnerability exploit"]

        # Search RAG for each term and collect results
        all_results = []
        seen_ids = set()

        for term in search_terms[:3]:  # Limit to 3 searches
            try:
                results = await hybrid_search(term, limit=top_k)
                for r in results:
                    if r.id not in seen_ids:
                        seen_ids.add(r.id)
                        all_results.append(r)
            except Exception as e:
                log.debug("RAG search failed for '%s': %s", term, e)

        if not all_results:
            return ""

        # Sort by score and take top results
        all_results.sort(key=lambda x: x.score, reverse=True)
        top_results = all_results[:top_k]

        # Format context
        context_parts = ["## Similar Exploits from DeFiHackLabs\n"]
        context_parts.append("Use these as reference for vulnerability patterns:\n")

        for i, r in enumerate(top_results, 1):
            loss_str = f"${r.loss_usd/1_000_000:.2f}M" if r.loss_usd else "Unknown"
            context_parts.append(f"""
### {i}. {r.name} ({r.date})
- **Chain**: {r.chain}
- **Loss**: {loss_str}
- **Type**: {r.attack_type}
- **Summary**: {r.summary[:500]}
""")

        return "\n".join(context_parts)

    except Exception as e:
        log.warning("Failed to fetch RAG context: %s", e)
        return ""


@dataclass
class PreAuditResult:
    """Pre-audit result from triage/resolve/decompile stages."""

    address: str
    chain: str
    balance_usd: float
    is_proxy: bool
    proxy_type: str | None
    resolved_address: str
    decompile_dir: str
    dedaub_file: str | None = None
    passed: bool = True
    skip_reason: str | None = None


@dataclass
class InstanceResult:
    """Result from a single Claude instance."""

    instance_id: int
    success: bool
    report_path: str | None = None
    transcript_path: str | None = None
    output: str | None = None
    error: str | None = None
    duration: int = 0  # ms
    session_id: str | None = None  # For --resume follow-up


@dataclass
class ParallelAuditResult:
    """Aggregated result from all parallel instances."""

    all_failed: bool
    report_paths: list[str] = field(default_factory=list)
    transcript_paths: list[str] = field(default_factory=list)
    instance_results: list[InstanceResult] = field(default_factory=list)
    success_count: int = 0
    fail_count: int = 0


# Default parallel instance count
DEFAULT_PARALLEL_COUNT = 3

# Project root for cwd
PROJECT_ROOT = Path(__file__).parent.parent.parent


# ============================================
# Two-Stage Audit Helper Functions
# ============================================


def extract_session_id(stdout: str) -> str | None:
    """Extract session_id from Claude stream-json output."""
    for line in stdout.split("\n"):
        if line.strip():
            try:
                event = json.loads(line)
                # Session ID comes in the "system" event
                if event.get("type") == "system":
                    return event.get("session_id")
            except json.JSONDecodeError:
                pass
    return None


def detect_solidity_version(code: str) -> str | None:
    """
    Detect Solidity version from decompiled code.

    Dedaub includes version in comments:
    // Solidity version: 0.6.10
    """
    import re

    match = re.search(r"Solidity\s*(?:version)?:?\s*(0\.\d+\.\d+)", code, re.I)
    if match:
        return match.group(1)
    return None


def needs_arithmetic_followup(code: str) -> bool:
    """Check if contract needs arithmetic follow-up (Solidity < 0.8.0)."""
    version = detect_solidity_version(code)
    if not version:
        # Assume old version if can't detect
        return True
    try:
        parts = version.split(".")
        if len(parts) >= 2:
            minor = int(parts[1])
            return minor < 8
    except (ValueError, IndexError):
        return True
    return True


def build_followup_prompt(instance_id: int, reports_dir: Path) -> str:
    """
    Build follow-up prompt.

    Minimal and general - Claude has full context via --resume.
    """
    return f"""/ultrathink

Conduct a deeper audit.

Append findings to: `{reports_dir}/audit_{instance_id}.md`
"""


async def spawn_followup_instance(
    instance_id: int,
    pre_audit: "PreAuditResult",
    session_id: str,
    verbose: bool = False,
    timeout_ms: int = 600000,  # 10 min for follow-up
) -> InstanceResult:
    """Spawn follow-up instance continuing previous session via --resume."""
    start_time = time.time()

    audit_dir = get_audit_dir(pre_audit.chain, pre_audit.address)
    reports_dir = audit_dir / "reports"
    logs_dir = audit_dir / "logs"

    prompt = build_followup_prompt(instance_id, reports_dir)
    timestamp = time.strftime("%Y%m%dT%H%M%S")

    transcript_path = logs_dir / f"{instance_id}_{timestamp}_followup_transcript.json"
    output_path = logs_dir / f"{instance_id}_{timestamp}_followup_output.txt"

    log.info("[Follow-up %d] Resuming session %s...", instance_id, session_id[:8])

    try:
        env = {**os.environ}
        if settings.anthropic_api_key:
            env["ANTHROPIC_API_KEY"] = settings.anthropic_api_key
        elif settings.claude_oauth_token:
            env["CLAUDE_CODE_OAUTH_TOKEN"] = settings.claude_oauth_token

        proc = await asyncio.create_subprocess_exec(
            "claude",
            "-p", prompt,
            "--resume", session_id,  # Continue session
            "--allowedTools", "Read,Edit,Bash,Glob,Grep,Write,WebFetch",
            "--output-format", "stream-json",
            "--verbose",
            "--model", "opus",
            env=env,
            cwd=PROJECT_ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_ms / 1000
            )
        except TimeoutError:
            log.warning("[Follow-up %d] Timeout after %dms", instance_id, timeout_ms)
            proc.kill()
            duration = int((time.time() - start_time) * 1000)
            return InstanceResult(
                instance_id=instance_id,
                success=False,
                error=f"Follow-up timeout after {timeout_ms}ms",
                duration=duration,
            )

        stdout = stdout_bytes.decode()
        stderr = stderr_bytes.decode()

        # Parse and save transcript
        transcript_events = []
        for line in stdout.split("\n"):
            if line.strip():
                try:
                    event = json.loads(line)
                    transcript_events.append(event)
                except json.JSONDecodeError:
                    pass

        duration = int((time.time() - start_time) * 1000)

        transcript_path.write_text(json.dumps(transcript_events, indent=2))
        output_path.write_text(stdout)

        if proc.returncode == 0:
            log.info("[Follow-up %d] Completed in %.1fs", instance_id, duration / 1000)
            return InstanceResult(
                instance_id=instance_id,
                success=True,
                transcript_path=str(transcript_path),
                output=stdout[-5000:],
                duration=duration,
            )
        else:
            log.error("[Follow-up %d] Failed with code %d", instance_id, proc.returncode)
            return InstanceResult(
                instance_id=instance_id,
                success=False,
                transcript_path=str(transcript_path),
                error=stderr[-500:] or f"Exit code {proc.returncode}",
                duration=duration,
            )

    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return InstanceResult(
            instance_id=instance_id,
            success=False,
            error=f"Follow-up spawn failed: {e}",
            duration=duration,
        )


def load_audit_prompts() -> list[tuple[str, str]]:
    """
    Load audit prompts from AuditConfig.audit_prompts.

    Returns:
        List of (prompt_name, prompt_content) tuples.
        Each prompt is repeated according to its instance count.

    Example:
        AuditConfig.audit_prompts = {"anchored.md": 2, "open.md": 1}
        -> [("anchored", content), ("anchored", content), ("open", content)]
    """
    prompts: list[tuple[str, str]] = []

    for path_str, count in AuditConfig.audit_prompts.items():
        path = PROJECT_ROOT / path_str
        if not path.exists():
            log.warning("Prompt file not found: %s", path)
            continue

        content = path.read_text()
        name = path.stem  # "anchored" from "anchored.md"

        # Add prompt `count` times
        for _ in range(count):
            prompts.append((name, content))

    return prompts


def build_audit_prompt(
    pre_audit: PreAuditResult,
    instance_id: int,
    prompt_name: str = "",
    prompt_content: str = "",
    rag_context: str = "",
) -> str:
    """
    Build the audit prompt for a Claude instance.

    Structure:
        /ultrathink

        {prompt_content}  <- loaded from file (checklist OR open-ended)

        {rag_context}  <- similar exploits from DeFiHackLabs (optional)

        ---

        {contract_metadata}

        {output_format}
    """
    decompile_dir = Path(pre_audit.decompile_dir)

    # Prefer implementation.sol if exists (proxy case), else dedaub.sol
    implementation_file = decompile_dir / "implementation.sol"
    dedaub_file = decompile_dir / "dedaub.sol"

    if implementation_file.exists():
        code_file = implementation_file
    elif pre_audit.dedaub_file:
        code_file = Path(pre_audit.dedaub_file)
    else:
        code_file = dedaub_file

    if instance_id == 0:
        log.debug("Code source: dedaub -> %s", code_file.name)

    # Make path relative to project root for @ reference
    try:
        relative_code_file = code_file.relative_to(PROJECT_ROOT)
    except ValueError:
        relative_code_file = code_file

    # Build audit output path
    audit_dir = get_audit_dir(pre_audit.chain, pre_audit.address)
    reports_dir = audit_dir / "reports"

    # === PART 1: /ultrathink ===
    part1_ultrathink = "/ultrathink"

    # === PART 2: Loaded prompt (anchored checklist OR open-ended) ===
    part2_prompt = prompt_content if prompt_content else ""

    # === PART 3: Contract metadata + output format ===
    part3_contract_and_output = f"""---

## Contract Under Audit

**File**: @{relative_code_file}

**Metadata**:
- Address: {pre_audit.address}
- Chain: {pre_audit.chain}
- Balance: ${pre_audit.balance_usd:,.0f}
- Proxy: {pre_audit.is_proxy} ({pre_audit.proxy_type or "none"})
- Resolved Address: {pre_audit.resolved_address}

---

## Output Requirements

1. Save report to: `{reports_dir}/audit_{instance_id}.md`

2. At the end of the report, include JSON findings array:

```json
[
  {{
    "id": "VULN-001",
    "type": "reentrancy|access_control|price_manipulation|...",
    "severity": "critical|high|medium|low|info",
    "confidence": 0.0-1.0,
    "title": "Short title",
    "description": "Detailed description",
    "location": {{"function": "functionName", "selector": "0x..."}},
    "impact": "What attacker can achieve",
    "exploitScenario": "1. Step one\\n2. Step two\\n3. Profit",
    "recommendation": "How to fix"
  }}
]
```

Instance ID: {instance_id}
Prompt: {prompt_name}
"""

    # === PART 2.5: RAG context (similar exploits) ===
    part2_5_rag = rag_context if rag_context else ""

    # Combine all parts
    parts = [part1_ultrathink, part2_prompt]
    if part2_5_rag:
        parts.append(part2_5_rag)
    parts.append(part3_contract_and_output)

    return "\n\n".join(filter(None, parts))


async def spawn_audit_instance(
    instance_id: int,
    pre_audit: PreAuditResult,
    prompt_name: str = "",
    prompt_content: str = "",
    rag_context: str = "",
    verbose: bool = False,
    timeout_ms: int = 1200000,  # 20 min default
) -> InstanceResult:
    """
    Spawn a single Claude Code headless instance.

    Uses system credentials by default. OAuth token is optional (legacy).
    Supports: Claude Pro/Max subscription, ANTHROPIC_API_KEY, or CLAUDE_CODE_OAUTH_TOKEN.
    """
    start_time = time.time()

    prompt = build_audit_prompt(
        pre_audit,
        instance_id,
        prompt_name=prompt_name,
        prompt_content=prompt_content,
        rag_context=rag_context,
    )
    timestamp = time.strftime("%Y%m%dT%H%M%S")

    # Paths for output files - consolidated under audit directory
    audit_dir = get_audit_dir(pre_audit.chain, pre_audit.address)
    reports_dir = audit_dir / "reports"
    logs_dir = audit_dir / "logs"

    reports_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    report_path = reports_dir / f"audit_{instance_id}.md"
    transcript_path = logs_dir / f"{instance_id}_{timestamp}_transcript.json"
    output_path = logs_dir / f"{instance_id}_{timestamp}_output.txt"

    log.info("[Instance %d] Starting with prompt: %s", instance_id, prompt_name or "default")
    if verbose:
        log.debug("[Instance %d] Transcript: %s", instance_id, transcript_path)

    try:
        # Build environment - only add credentials if explicitly configured
        # Priority: ANTHROPIC_API_KEY > CLAUDE_CODE_OAUTH_TOKEN > system login
        env = {**os.environ}
        if settings.anthropic_api_key:
            env["ANTHROPIC_API_KEY"] = settings.anthropic_api_key
        elif settings.claude_oauth_token:
            env["CLAUDE_CODE_OAUTH_TOKEN"] = settings.claude_oauth_token

        proc = await asyncio.create_subprocess_exec(
            "claude",
            "-p",
            prompt,
            "--allowedTools",
            "Read,Edit,Bash,Glob,Grep,Write,WebFetch",
            "--output-format",
            "stream-json",
            "--verbose",
            "--model",
            "opus",
            env=env,
            cwd=PROJECT_ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_ms / 1000
            )
        except TimeoutError:
            log.warning("[Instance %d] Timeout after %dms", instance_id, timeout_ms)
            proc.kill()
            duration = int((time.time() - start_time) * 1000)
            return InstanceResult(
                instance_id=instance_id,
                success=False,
                error=f"Timeout after {timeout_ms}ms",
                duration=duration,
            )

        stdout = stdout_bytes.decode()
        stderr = stderr_bytes.decode()

        # Parse stream-json events for transcript
        transcript_events = []
        for line in stdout.split("\n"):
            if line.strip():
                try:
                    event = json.loads(line)
                    transcript_events.append(event)

                    if verbose and event.get("type") == "assistant":
                        msg = (
                            event.get("message", {})
                            .get("content", [{}])[0]
                            .get("text", "")[:100]
                        )
                        if msg:
                            log.debug("[Instance %d] %s...", instance_id, msg)
                except json.JSONDecodeError:
                    pass

        duration = int((time.time() - start_time) * 1000)

        # Save transcript
        transcript_path.write_text(json.dumps(transcript_events, indent=2))

        # Save raw output
        output_path.write_text(stdout)

        # Extract session_id for potential follow-up
        session_id = extract_session_id(stdout)

        if proc.returncode == 0:
            log.info("[Instance %d] Completed in %.1fs", instance_id, duration / 1000)

            # Check if report was generated
            report_exists = report_path.exists()
            if not report_exists:
                log.warning("[Instance %d] Report not found at %s", instance_id, report_path)

            return InstanceResult(
                instance_id=instance_id,
                success=True,
                report_path=str(report_path) if report_exists else None,
                transcript_path=str(transcript_path),
                output=stdout[-5000:],  # Last 5000 chars
                duration=duration,
                session_id=session_id,
            )
        else:
            log.error("[Instance %d] Failed with code %d", instance_id, proc.returncode)
            return InstanceResult(
                instance_id=instance_id,
                success=False,
                transcript_path=str(transcript_path),
                error=stderr[-500:] or f"Exit code {proc.returncode}",
                duration=duration,
            )

    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        return InstanceResult(
            instance_id=instance_id,
            success=False,
            error=f"Spawn failed: {e}",
            duration=duration,
        )


async def retry_with_backoff(
    func,
    max_retries: int = 3,
    base_delay_ms: int = 5000,
    max_delay_ms: int = 60000,
    on_retry=None,
):
    """Retry a coroutine with exponential backoff."""
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            result = await func()
            if result.success:
                return result
            last_error = Exception(result.error or "Unknown error")
        except Exception as e:
            last_error = e

        if attempt < max_retries:
            delay = min(base_delay_ms * (2**attempt), max_delay_ms) / 1000
            if on_retry:
                await on_retry(attempt + 1, last_error)
            await asyncio.sleep(delay)

    raise last_error or Exception("All retries exhausted")


async def run_parallel_audit(
    pre_audit: PreAuditResult,
    max_retries: int | None = None,
    verbose: bool = False,
    timeout_ms: int | None = None,
    use_rag: bool = True,
) -> ParallelAuditResult:
    """
    Run parallel audit with multiple Claude instances.

    Instance count and prompts are determined by AuditConfig.audit_prompts.
    Each prompt can spawn multiple instances (for redundancy/consensus).

    Args:
        pre_audit: Pre-audit result with contract metadata
        max_retries: Max retries per instance (default from AuditConfig)
        verbose: Enable verbose logging
        timeout_ms: Timeout per instance in ms (default from AuditConfig)
        use_rag: Whether to fetch RAG context from DeFiHackLabs exploits

    Returns:
        ParallelAuditResult with aggregated results
    """
    # Load prompts from config
    prompts = load_audit_prompts()

    if not prompts:
        log.warning("No prompts configured, using single default instance")
        prompts = [("default", "")]

    count = len(prompts)

    # Use config values if not overridden
    if max_retries is None:
        max_retries = AuditConfig.audit_max_retries
    if timeout_ms is None:
        timeout_ms = AuditConfig.audit_timeout_ms

    # Fetch RAG context if enabled
    rag_context = ""
    if use_rag:
        try:
            # Read decompiled code for RAG search
            code_file = Path(pre_audit.dedaub_file) if pre_audit.dedaub_file else None
            if code_file and code_file.exists():
                code = code_file.read_text()[:10000]  # First 10k chars
                rag_context = await fetch_rag_context(code, top_k=RAGConfig.top_k)
                if rag_context:
                    log.info("RAG context fetched: %d chars", len(rag_context))
        except Exception as e:
            log.warning("Failed to fetch RAG context: %s", e)

    # Calculate prompt distribution for logging
    prompt_distribution = dict(Counter(p[0] for p in prompts))

    log.info("=" * 50)
    log.info("PARALLEL AUDIT: %s (%s)", pre_audit.address[:16], pre_audit.chain)
    log.info("Instances: %d | Prompts: %s | RAG: %s", count, prompt_distribution, bool(rag_context))
    log.info("=" * 50)

    async def spawn_with_retry(i: int) -> InstanceResult:
        prompt_name, prompt_content = prompts[i]

        async def on_retry(attempt: int, error: Exception):
            log.warning("[Instance %d/%s] Retry %d: %s", i, prompt_name, attempt, error)

        try:
            return await retry_with_backoff(
                lambda: spawn_audit_instance(
                    i,
                    pre_audit,
                    prompt_name=prompt_name,
                    prompt_content=prompt_content,
                    rag_context=rag_context,
                    verbose=verbose,
                    timeout_ms=timeout_ms,
                ),
                max_retries=max_retries,
                base_delay_ms=5000,
                max_delay_ms=60000,
                on_retry=on_retry,
            )
        except Exception as e:
            return InstanceResult(
                instance_id=i,
                success=False,
                error=str(e),
            )

    # Spawn all instances in parallel (Stage 1)
    tasks = [spawn_with_retry(i) for i in range(count)]
    stage1_results = await asyncio.gather(*tasks)

    # Stage 2: Follow-up for Solidity < 0.8.0
    all_results = list(stage1_results)

    if AuditConfig.enable_arithmetic_followup:
        # Check code for Solidity version
        code_file = Path(pre_audit.decompile_dir) / "implementation.sol"
        if not code_file.exists():
            code_file = Path(pre_audit.decompile_dir) / "dedaub.sol"

        if code_file.exists() and needs_arithmetic_followup(code_file.read_text()):
            log.info("[Follow-up] Solidity < 0.8.0 detected, running deeper analysis...")

            # Run follow-up for instances with session_id
            followup_tasks = []
            for r in stage1_results:
                if r.success and r.session_id:
                    followup_tasks.append(
                        spawn_followup_instance(
                            r.instance_id,
                            pre_audit,
                            session_id=r.session_id,
                            verbose=verbose,
                            timeout_ms=timeout_ms // 2,  # Half timeout for follow-up
                        )
                    )

            if followup_tasks:
                log.info("[Follow-up] Resuming %d sessions...", len(followup_tasks))
                stage2_results = await asyncio.gather(*followup_tasks)

                # Log follow-up results
                for r in stage2_results:
                    status = "✓" if r.success else "✗"
                    log.info("[Follow-up %d] %s", r.instance_id, status)

                all_results.extend(stage2_results)

    # Aggregate results
    success_results = [r for r in stage1_results if r.success]
    failed_results = [r for r in stage1_results if not r.success]

    parallel_result = ParallelAuditResult(
        all_failed=len(success_results) == 0,
        report_paths=[r.report_path for r in success_results if r.report_path],
        transcript_paths=[r.transcript_path for r in all_results if r.transcript_path],
        instance_results=list(stage1_results),
        success_count=len(success_results),
        fail_count=len(failed_results),
    )

    log.info("=" * 50)
    log.info("PARALLEL AUDIT COMPLETE: %d/%d success, %d reports",
             parallel_result.success_count, count, len(parallel_result.report_paths))
    if parallel_result.all_failed:
        log.error("All instances failed!")
    log.info("=" * 50)

    return parallel_result


async def run_single_test_instance(
    address: str,
    chain: Chain,
    pre_audit: PreAuditResult,
    verbose: bool = False,
    prompt_name: str = "",
    prompt_content: str = "",
) -> InstanceResult:
    """Run a single test instance (for debugging)."""
    log.info("Running single test instance for %s...", address[:16])
    return await spawn_audit_instance(
        0,
        pre_audit,
        prompt_name=prompt_name,
        prompt_content=prompt_content,
        verbose=verbose,
        timeout_ms=AuditConfig.audit_timeout_ms,
    )


# ============================================
# Findings Aggregation Functions
# ============================================

# Severity score mapping for ranking
SEVERITY_SCORES = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def parse_findings_from_report(report_path: str) -> list[VulnerabilityFinding]:
    """
    Parse findings JSON from audit report markdown file.

    Looks for ```json blocks containing findings array.
    """
    import re

    path = Path(report_path)
    if not path.exists():
        log.warning("Report not found: %s", report_path)
        return []

    content = path.read_text()

    # Find JSON blocks in markdown
    json_blocks = re.findall(r"```json\s*([\s\S]*?)\s*```", content, re.MULTILINE)

    findings: list[VulnerabilityFinding] = []

    for block in json_blocks:
        try:
            data = json.loads(block)

            # Handle both array and single object
            items = data if isinstance(data, list) else [data]

            for item in items:
                # Skip if not a finding structure
                if not isinstance(item, dict) or "id" not in item:
                    continue

                try:
                    # Map severity string to enum
                    severity_str = item.get("severity", "info").lower()
                    severity = Severity(severity_str)

                    # Map type string to enum
                    type_str = item.get("type", "other").lower().replace(" ", "_")
                    try:
                        vuln_type = VulnerabilityType(type_str)
                    except ValueError:
                        vuln_type = VulnerabilityType.OTHER

                    # Parse location
                    loc_data = item.get("location", {})
                    location = VulnerabilityLocation(
                        function=loc_data.get("function"),
                        selector=loc_data.get("selector"),
                        line=loc_data.get("line"),
                    )

                    finding = VulnerabilityFinding(
                        id=item.get("id", f"VULN-{len(findings)+1:03d}"),
                        type=vuln_type,
                        severity=severity,
                        confidence=float(item.get("confidence", 0.5)),
                        title=item.get("title", "Unknown"),
                        description=item.get("description", ""),
                        location=location,
                        impact=item.get("impact", ""),
                        exploitScenario=item.get("exploitScenario"),
                        estimatedProfit=item.get("estimatedProfit"),
                        source=FindingSource.STATIC,
                        verified=False,
                    )
                    findings.append(finding)

                except Exception as e:
                    log.warning("Failed to parse finding: %s", e)
                    continue

        except json.JSONDecodeError:
            continue

    log.debug("Parsed %d findings from %s", len(findings), path.name)
    return findings


def normalize_title(title: str) -> str:
    """Normalize title for fuzzy matching."""
    import re
    # Lowercase
    t = title.lower()
    # Remove common prefixes
    t = re.sub(r"^(potential|possible|likely)\s+", "", t)
    # Remove function names in parentheses
    t = re.sub(r"\s*\([^)]*\)\s*", " ", t)
    # Remove hex addresses/selectors
    t = re.sub(r"0x[a-f0-9]+", "", t)
    # Remove "unresolved_" prefix
    t = re.sub(r"unresolved_[a-f0-9]+", "func", t)
    # Normalize whitespace
    t = re.sub(r"\s+", " ", t).strip()
    # Remove common suffixes
    t = re.sub(r"\s+(vulnerability|issue|risk|attack)$", "", t)
    return t


def deduplicate_findings(
    all_findings: list[VulnerabilityFinding],
) -> list[VulnerabilityFinding]:
    """
    Deduplicate findings using fuzzy matching on type + normalized title.

    Keeps finding with higher confidence on collision.
    """
    seen: dict[str, VulnerabilityFinding] = {}

    for finding in all_findings:
        # Build dedup key with normalized title
        norm_title = normalize_title(finding.title)
        # Use type + first 2 significant words of title
        title_words = [w for w in norm_title.split() if len(w) > 2][:3]
        key = f"{finding.type.value}:{':'.join(title_words)}"

        if key not in seen:
            seen[key] = finding
        else:
            # Keep higher confidence, or higher severity on tie
            existing = seen[key]
            existing_score = SEVERITY_SCORES.get(existing.severity, 1) * existing.confidence
            new_score = SEVERITY_SCORES.get(finding.severity, 1) * finding.confidence
            if new_score > existing_score:
                seen[key] = finding

    deduped = list(seen.values())
    log.debug("Deduplicated: %d → %d findings", len(all_findings), len(deduped))
    return deduped


def rank_findings(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    """
    Sort findings by severity_score * confidence (descending).

    CRITICAL=5, HIGH=4, MEDIUM=3, LOW=2, INFO=1
    """

    def score(f: VulnerabilityFinding) -> float:
        severity_score = SEVERITY_SCORES.get(f.severity, 1)
        return severity_score * f.confidence

    ranked = sorted(findings, key=score, reverse=True)
    return ranked


def aggregate_findings(report_paths: list[str]) -> list[VulnerabilityFinding]:
    """
    Aggregate findings from multiple reports → dedupe → rank.

    Args:
        report_paths: Paths to audit report markdown files

    Returns:
        Deduplicated and ranked list of findings
    """
    log.info("Aggregating findings from %d reports...", len(report_paths))

    all_findings: list[VulnerabilityFinding] = []

    for path in report_paths:
        findings = parse_findings_from_report(path)
        all_findings.extend(findings)

    if not all_findings:
        log.info("No findings to aggregate")
        return []

    # Deduplicate
    deduped = deduplicate_findings(all_findings)

    # Rank by severity * confidence
    ranked = rank_findings(deduped)

    # Summary
    severity_counts: dict[str, int] = {}
    for f in ranked:
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    log.info("Final: %d findings %s", len(ranked), severity_counts)

    return ranked


# ============================================
# Critic Phase: Validate Findings
# ============================================


def build_critic_prompt(
    findings: list[VulnerabilityFinding],
    code_file: Path,
) -> str:
    """
    Build critic prompt to validate findings.

    Args:
        findings: List of findings to validate
        code_file: Path to decompiled code for reference

    Returns:
        Full critic prompt with findings JSON
    """
    critic_path = PROJECT_ROOT / AuditConfig.critic_prompt_path
    if not critic_path.exists():
        log.warning("Critic prompt not found: %s", critic_path)
        return ""

    critic_content = critic_path.read_text()

    # Convert findings to JSON for critic
    findings_json = json.dumps(
        [
            {
                "id": f.id,
                "type": f.type.value,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "title": f.title,
                "description": f.description,
                "location": {
                    "function": f.location.function if f.location else None,
                    "line": f.location.line if f.location else None,
                },
                "impact": f.impact,
                "exploitScenario": f.exploit_scenario,
            }
            for f in findings
        ],
        indent=2,
    )

    # Make code path relative
    try:
        relative_code = code_file.relative_to(PROJECT_ROOT)
    except ValueError:
        relative_code = code_file

    return f"""/ultrathink

{critic_content}

---

## Code Reference

**File**: @{relative_code}

---

## Findings to Evaluate

```json
{findings_json}
```

Evaluate each finding and output JSON with scores:

```json
[
  {{
    "id": "VULN-001",
    "correctness": 7,
    "severity": 8,
    "exploitability": 6,
    "total": 21,
    "verdict": "VALID",
    "reason": "Brief explanation"
  }}
]
```
"""


def parse_critic_results(output: str) -> dict[str, dict[str, Any]]:
    """
    Parse critic output to extract scores per finding.

    Returns:
        Dict mapping finding_id -> {correctness, severity, exploitability, total, verdict}
    """
    import re

    results: dict[str, dict[str, Any]] = {}

    # Find JSON blocks
    json_blocks = re.findall(r"```json\s*([\s\S]*?)\s*```", output, re.MULTILINE)

    for block in json_blocks:
        try:
            data = json.loads(block)
            items = data if isinstance(data, list) else [data]

            for item in items:
                if isinstance(item, dict) and "id" in item:
                    results[item["id"]] = {
                        "correctness": item.get("correctness", 0),
                        "severity": item.get("severity", 0),
                        "exploitability": item.get("exploitability", 0),
                        "total": item.get("total", 0),
                        "verdict": item.get("verdict", "NEEDS_REVIEW"),
                        "reason": item.get("reason", ""),
                    }
        except json.JSONDecodeError:
            continue

    return results


async def run_critic_phase(
    findings: list[VulnerabilityFinding],
    pre_audit: PreAuditResult,
    timeout_ms: int = 600000,  # 10 min
) -> list[VulnerabilityFinding]:
    """
    Run critic phase to validate findings.

    Spawns Claude to evaluate each finding on correctness/severity/exploitability.
    Filters out findings with total score < critic_min_score.

    Args:
        findings: Findings from audit phase
        pre_audit: Pre-audit context
        timeout_ms: Timeout in ms

    Returns:
        Filtered list of validated findings
    """
    if not findings:
        return []

    if not AuditConfig.enable_critic_phase:
        log.info("[Critic] Disabled, skipping validation")
        return findings

    log.info("[Critic] Validating %d findings...", len(findings))

    # Get code file path
    decompile_dir = Path(pre_audit.decompile_dir)
    code_file = decompile_dir / "implementation.sol"
    if not code_file.exists():
        code_file = decompile_dir / "dedaub.sol"

    if not code_file.exists():
        log.warning("[Critic] Code file not found, skipping")
        return findings

    prompt = build_critic_prompt(findings, code_file)
    if not prompt:
        return findings

    # Spawn Claude for critic
    start_time = time.time()

    try:
        env = {**os.environ}
        if settings.anthropic_api_key:
            env["ANTHROPIC_API_KEY"] = settings.anthropic_api_key
        elif settings.claude_oauth_token:
            env["CLAUDE_CODE_OAUTH_TOKEN"] = settings.claude_oauth_token

        proc = await asyncio.create_subprocess_exec(
            "claude",
            "-p", prompt,
            "--allowedTools", "Read,Glob,Grep",
            "--output-format", "text",
            "--model", "sonnet",  # Faster for validation
            env=env,
            cwd=PROJECT_ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_ms / 1000
            )
        except TimeoutError:
            log.warning("[Critic] Timeout, returning unfiltered findings")
            proc.kill()
            return findings

        stdout = stdout_bytes.decode()
        duration = int((time.time() - start_time) * 1000)

        if proc.returncode != 0:
            log.error("[Critic] Failed with code %d", proc.returncode)
            return findings

        log.info("[Critic] Completed in %.1fs", duration / 1000)

        # Parse results
        critic_results = parse_critic_results(stdout)

        if not critic_results:
            log.warning("[Critic] No scores parsed, returning unfiltered")
            return findings

        # Filter findings
        min_score = AuditConfig.critic_min_score
        validated: list[VulnerabilityFinding] = []

        for finding in findings:
            scores = critic_results.get(finding.id)
            if not scores:
                # No score = keep it (conservative)
                validated.append(finding)
                continue

            total = scores.get("total", 0)
            verdict = scores.get("verdict", "NEEDS_REVIEW")

            if total >= min_score or verdict == "VALID":
                # Update confidence based on critic score
                new_confidence = min(1.0, total / 27.0)
                finding.confidence = (finding.confidence + new_confidence) / 2
                validated.append(finding)
                log.debug("[Critic] %s: VALID (score=%d)", finding.id, total)
            else:
                log.info("[Critic] %s: FILTERED (score=%d < %d)", finding.id, total, min_score)

        log.info("[Critic] Validated: %d/%d findings passed", len(validated), len(findings))
        return validated

    except Exception as e:
        log.error("[Critic] Error: %s", e)
        return findings
