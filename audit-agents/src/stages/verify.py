"""
Verify stage - Claude-based PoC generation and testing.

Spawns Claude Code instances to generate Solidity PoC tests
and run them against forked chain state.

Features:
- Retry with exponential backoff (3 attempts)
- Timeout handling per instance
- PoC code extraction and storage
"""

import asyncio
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from ..config import get_audit_dir, get_chain_config, settings
from ..models import Chain, Severity, VulnerabilityFinding

logger = logging.getLogger(__name__)


@dataclass
class VerifyResult:
    """Result of PoC verification."""

    verified: bool
    skipped: bool = False
    poc_path: str | None = None
    poc_code: str | None = None
    output: str | None = None
    error: str | None = None
    duration_ms: int = 0


# Project root for cwd
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Retry configuration
MAX_RETRIES = 3
BASE_DELAY_MS = 5000
MAX_DELAY_MS = 30000


async def retry_with_backoff[T](
    func: Callable[[], Awaitable[T]],
    max_retries: int = MAX_RETRIES,
    base_delay_ms: int = BASE_DELAY_MS,
    max_delay_ms: int = MAX_DELAY_MS,
    on_retry: Callable[[int, Exception], None] | None = None,
) -> T:
    """
    Retry a coroutine with exponential backoff.

    Args:
        func: Async function to retry
        max_retries: Maximum number of retries (default: 3)
        base_delay_ms: Base delay in milliseconds (default: 5000)
        max_delay_ms: Maximum delay in milliseconds (default: 30000)
        on_retry: Optional callback on retry (attempt, error)

    Returns:
        Result from successful func() call

    Raises:
        Last exception if all retries exhausted
    """
    last_error: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            result = await func()
            # For VerifyResult, check if it's a retryable error
            if isinstance(result, VerifyResult):
                if result.verified or result.skipped:
                    return result
                # Retry on timeout or certain errors
                if result.error and "timeout" in result.error.lower():
                    last_error = Exception(result.error)
                    if attempt < max_retries:
                        delay = min(base_delay_ms * (2**attempt), max_delay_ms) / 1000
                        if on_retry:
                            on_retry(attempt + 1, last_error)
                        logger.info(
                            f"Retrying after {delay:.1f}s (attempt {attempt + 1}/{max_retries})"
                        )
                        await asyncio.sleep(delay)
                        continue
                # Non-retryable failure
                return result
            return result
        except Exception as e:
            last_error = e
            if attempt < max_retries:
                delay = min(base_delay_ms * (2**attempt), max_delay_ms) / 1000
                if on_retry:
                    on_retry(attempt + 1, e)
                logger.warning(f"Retry {attempt + 1}/{max_retries} after error: {e}")
                await asyncio.sleep(delay)

    raise last_error or Exception("All retries exhausted")


def build_verify_prompt(
    finding: VulnerabilityFinding,
    address: str,
    chain: str,
    decompiled_code: str,
    rpc_url: str,
    poc_dir: Path,
) -> str:
    """Build prompt for Claude to generate and test PoC."""
    finding_id_safe = finding.id.replace("-", "_")

    return f"""You are an expert in smart contract vulnerability exploitation.

## Task
Write a Foundry PoC test to verify the vulnerability and run it.

## Vulnerability
- **ID**: {finding.id}
- **Type**: {finding.type.value}
- **Severity**: {finding.severity.value}
- **Title**: {finding.title}
- **Description**: {finding.description}
- **Function**: {finding.location.function or "unknown"}
- **Impact**: {finding.impact}
- **Exploit Scenario**: {finding.exploit_scenario or "N/A"}

## Contract
- **Address**: {address}
- **Chain**: {chain}
- **RPC**: {rpc_url}

## Decompiled Code
```solidity
{decompiled_code[:12000]}
```

## Instructions

1. Create file `{poc_dir}/{finding_id_safe}.t.sol` with the PoC test
2. PoC must:
   - Use `pragma solidity ^0.8.20;`
   - Import `forge-std/Test.sol`
   - Fork mainnet: `vm.createSelectFork("{rpc_url}")`
   - Contain `testExploit()` function
   - Attempt to exploit the vulnerability
   - Log state before/after

3. Run the test with:
   ```bash
   forge test --match-path {poc_dir}/{finding_id_safe}.t.sol --fork-url {rpc_url} -vvv
   ```

4. Analyze the test result

5. At the VERY END output exactly one line:
   - `VERIFIED: true` - if exploit succeeded (test passed AND profit extracted/invariant broken)
   - `VERIFIED: false` - if exploit failed

IMPORTANT: The VERIFIED line must be the last line in your response!
"""


async def spawn_verify_instance(
    finding: VulnerabilityFinding,
    address: str,
    chain: Chain,
    decompiled_code: str,
    timeout_ms: int = 300000,  # 5 min
) -> VerifyResult:
    """Spawn Claude Code to generate and run PoC for a finding."""
    start_time = time.time()

    # Priority: ANTHROPIC_API_KEY > OAuth > system login.
    # NOTE: Requires the user's OWN API key/credentials; this tool is for
    # testnet/authorized targets only and ships no credentials.
    env = {**os.environ}
    if settings.anthropic_api_key:
        env["ANTHROPIC_API_KEY"] = settings.anthropic_api_key
    elif settings.claude_oauth_token:
        env["CLAUDE_CODE_OAUTH_TOKEN"] = settings.claude_oauth_token
    # else: rely on system claude login

    chain_config = get_chain_config(chain.value)
    rpc_url = chain_config.rpc_url

    # Compute paths based on audit directory
    audit_dir = get_audit_dir(chain.value, address)
    poc_dir = audit_dir / "poc"
    logs_dir = audit_dir / "logs"

    prompt = build_verify_prompt(
        finding, address, chain.value, decompiled_code, rpc_url, poc_dir
    )

    # Ensure directories exist
    poc_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    finding_id_safe = finding.id.replace("-", "_")
    poc_path = poc_dir / f"{finding_id_safe}.t.sol"

    timestamp = time.strftime("%Y%m%dT%H%M%S")
    log_path = logs_dir / f"verify_{finding_id_safe}_{timestamp}.txt"

    logger.info("[Verify] Generating PoC for: %s...", finding.title[:50])

    try:
        proc = await asyncio.create_subprocess_exec(
            "claude",
            "-p",
            prompt,
            "--allowedTools",
            "Read,Write,Bash,Glob,Grep",
            "--output-format",
            "text",
            "--model",
            "sonnet",  # Faster for PoC generation
            env=env,
            cwd=str(PROJECT_ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_ms / 1000
        )

        duration_ms = int((time.time() - start_time) * 1000)
        output = stdout_bytes.decode()

        # Save log
        log_path.write_text(output)

        # Parse result - look for VERIFIED line
        output_lower = output.lower()
        verified = (
            "verified: true" in output_lower
            and "verified: false" not in output_lower.split("verified: true")[-1]
        )

        # Read PoC code if exists
        poc_code = None
        if poc_path.exists():
            poc_code = poc_path.read_text()

        return VerifyResult(
            verified=verified,
            poc_path=str(poc_path) if poc_path.exists() else None,
            poc_code=poc_code,
            output=output[-2000:],
            error=None if verified else "Exploit not successful or test failed",
            duration_ms=duration_ms,
        )

    except TimeoutError:
        duration_ms = int((time.time() - start_time) * 1000)
        return VerifyResult(
            verified=False,
            error=f"Timeout ({timeout_ms}ms)",
            duration_ms=duration_ms,
        )
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        return VerifyResult(
            verified=False,
            error=str(e)[:200],
            duration_ms=duration_ms,
        )


async def run_verify(
    address: str,
    chain: Chain,
    findings: list[VulnerabilityFinding],
    decompiled: str,
) -> list[VulnerabilityFinding]:
    """
    Verify CRITICAL findings using Claude-generated PoCs.

    Spawns Claude Code instances to generate and test exploits.
    Modifies findings in place (sets verified flag and pocCode).
    """
    if not findings:
        logger.debug("No findings to verify")
        return findings

    # Filter CRITICAL with high confidence
    to_verify = [
        f for f in findings if f.confidence >= 0.6 and f.severity == Severity.CRITICAL
    ]

    if not to_verify:
        logger.debug("No CRITICAL findings with sufficient confidence to verify")
        return findings

    logger.info(
        "Verifying %d/%d CRITICAL findings (max %d retries)",
        len(to_verify),
        len(findings),
        MAX_RETRIES,
    )

    for i, finding in enumerate(to_verify, 1):
        logger.info("[%d/%d] %s", i, len(to_verify), finding.title[:60])

        def on_retry(attempt: int, error: Exception) -> None:
            logger.warning("Retry %d/%d: %s", attempt, MAX_RETRIES, error)

        try:
            result = await retry_with_backoff(
                lambda f=finding: spawn_verify_instance(f, address, chain, decompiled),
                max_retries=MAX_RETRIES,
                on_retry=on_retry,
            )
        except Exception as e:
            logger.error(f"All retries failed for {finding.id}: {e}")
            result = VerifyResult(
                verified=False,
                error=f"All {MAX_RETRIES} retries failed: {e}",
            )

        # Update finding
        finding.verified = result.verified
        if result.poc_code:
            finding.poc_code = result.poc_code

        if result.verified:
            logger.info("VERIFIED - Exploit successful (%dms)", result.duration_ms)
        else:
            logger.info(
                "Not exploitable: %s (%dms)",
                result.error or "test failed",
                result.duration_ms,
            )

    verified_count = sum(1 for f in to_verify if f.verified)
    logger.info("Summary: %d/%d findings verified", verified_count, len(to_verify))

    return findings
