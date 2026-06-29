"""
Decompile stage - Bytecode decompilation using Dedaub API.

Uses curl_cffi for Cloudflare bypass on Dedaub API.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from curl_cffi import requests as curl_requests

from ..config import get_audit_dir, settings
from ..models import Chain, DecompiledFunction

log = logging.getLogger(__name__)


@dataclass
class DecompileResult:
    """Result from a single decompiler."""

    success: bool
    sol_file: str | None = None
    output_dir: str | None = None
    error: str | None = None
    duration_ms: int = 0


async def run_dedaub(
    bytecode: str,
    output_dir: Path,
    max_retries: int = 2,
    poll_attempts: int | None = None,
    poll_interval_seconds: float | None = None,
) -> DecompileResult:
    """
    Run Dedaub decompilation via curl_cffi with Chrome impersonation.

    Based on working dedaub_client.py implementation.
    """
    import json as json_lib

    start_time = datetime.now()
    dedaub_file = output_dir / "dedaub.sol"
    base_url = "https://app.dedaub.com/api"
    configured_poll_attempts = getattr(settings, "dedaub_poll_attempts", 120)
    if not isinstance(configured_poll_attempts, int):
        configured_poll_attempts = 120
    configured_poll_interval = getattr(settings, "dedaub_poll_interval_seconds", 2.0)
    if not isinstance(configured_poll_interval, int | float):
        configured_poll_interval = 2.0

    poll_attempts = poll_attempts or configured_poll_attempts
    poll_interval_seconds = (
        poll_interval_seconds
        if poll_interval_seconds is not None
        else float(configured_poll_interval)
    )

    # Validate bytecode
    if not bytecode or len(bytecode) < 4:
        return DecompileResult(
            success=False,
            error="Empty or invalid bytecode",
            duration_ms=0,
        )

    # Ensure bytecode has 0x prefix
    clean_bytecode = bytecode if bytecode.startswith("0x") else f"0x{bytecode}"

    # Get cookies from settings.
    # NOTE: Requires the user's OWN Dedaub session cookies; this tool is for
    # testnet/authorized targets only and ships no credentials.
    dedaub_cookies = settings.dedaub_cookies or ""
    if not dedaub_cookies:
        return DecompileResult(
            success=False,
            error="Dedaub: DEDAUB_COOKIES not set in .env",
            duration_ms=int((datetime.now() - start_time).total_seconds() * 1000),
        )

    last_error = ""

    for attempt in range(max_retries + 1):
        if attempt > 0:
            log.debug("Dedaub retry %d/%d", attempt, max_retries)
            await asyncio.sleep(2)

        try:
            # Step 1: Submit bytecode
            response = curl_requests.post(
                f"{base_url}/on_demand",
                data=json_lib.dumps(clean_bytecode),  # data, not json
                headers={
                    "accept": "*/*",
                    "content-type": "application/json",
                    "origin": "https://app.dedaub.com",
                    "referer": "https://app.dedaub.com/decompile?network=ethereum",
                    "cookie": dedaub_cookies,
                },
                impersonate="chrome124",  # specific version
                timeout=120,
            )

            if response.status_code != 200:
                last_error = (
                    f"Dedaub submit: {response.status_code} {response.text[:200]}"
                )
                continue

            # Response is MD5 hash string
            job_id = response.text.strip().strip('"')
            if len(job_id) < 10:
                last_error = f"Invalid job ID: {job_id}"
                continue

            log.info("Dedaub job started: %s...", job_id[:16])

            # Step 2: Poll for completion.
            completed = False
            last_status = ""
            for _poll_attempt in range(poll_attempts):
                await asyncio.sleep(poll_interval_seconds)

                try:
                    status_response = curl_requests.get(
                        f"{base_url}/on_demand/{job_id}/status",
                        headers={
                            "accept": "*/*",
                            "cookie": dedaub_cookies,
                        },
                        impersonate="chrome124",
                        timeout=30,
                    )
                except Exception as e:
                    log.debug("Poll status request failed: %s", e)
                    continue

                status = status_response.text
                last_status = status[:200]

                if "ANALYSIS_ENDED" in status or "COMPLETED" in status:
                    completed = True
                    break

                if "ERROR" in status or "FAILED" in status:
                    last_error = f"Dedaub failed: {status[:100]}"
                    break

            if not completed:
                if not last_error:
                    duration = poll_attempts * poll_interval_seconds
                    last_error = f"Dedaub timeout ({duration:.0f}s polling)"
                if last_status:
                    last_error = f"{last_error}; last status: {last_status}"
                continue

            # Step 3: Get decompilation result
            result_response = curl_requests.get(
                f"{base_url}/on_demand/decompilation/{job_id}",
                headers={
                    "accept": "*/*",
                    "cookie": dedaub_cookies,
                    "referer": f"https://app.dedaub.com/decompile?md5={job_id}",
                },
                impersonate="chrome124",
                timeout=120,
            )

            if result_response.status_code != 200:
                last_error = f"Dedaub result: {result_response.status_code}"
                continue

            result = result_response.json()

            # Save disassembly regardless
            if result.get("disassembled"):
                (output_dir / "dedaub.dasm").write_text(result["disassembled"])

            source = result.get("source", "")

            if source and "must be logged in" not in source:
                dedaub_file.write_text(source)
                return DecompileResult(
                    success=True,
                    sol_file=str(dedaub_file),
                    duration_ms=int(
                        (datetime.now() - start_time).total_seconds() * 1000
                    ),
                )

            last_error = "Dedaub: requires login (cookies expired?)"

        except Exception as e:
            error_str = str(e)
            log.warning("Dedaub request error: %s", error_str[:150])
            if "timeout" in error_str.lower():
                last_error = "Dedaub: connection timeout"
            else:
                last_error = f"Dedaub: {error_str[:150]}"

    return DecompileResult(
        success=False,
        error=last_error,
        duration_ms=int((datetime.now() - start_time).total_seconds() * 1000),
    )


async def decompile_contract(
    address: str,
    chain: Chain,
    bytecode: str,
    skip_dedaub: bool = False,
) -> tuple[bool, Path, str | None]:
    """
    Decompile a contract using Dedaub API.

    Returns (success, output_dir, sol_file).
    """
    audit_dir = get_audit_dir(chain.value, address)
    output_dir = audit_dir / "decompiled"
    output_dir.mkdir(parents=True, exist_ok=True)

    bytecode_size = (
        (len(bytecode) - 2) // 2 if bytecode.startswith("0x") else len(bytecode) // 2
    )
    log.debug("Bytecode size: %d bytes", bytecode_size)

    sol_file: str | None = None

    if not skip_dedaub:
        log.info("Running Dedaub decompilation")
        dedaub_result = await run_dedaub(bytecode, output_dir)

        if dedaub_result.success and dedaub_result.sol_file:
            log.info(
                "Dedaub completed: %s (%dms)",
                dedaub_result.sol_file,
                dedaub_result.duration_ms,
            )
            sol_file = dedaub_result.sol_file
        else:
            log.warning("Dedaub failed: %s", dedaub_result.error)

    success = sol_file is not None
    return success, output_dir, sol_file


def parse_decompiled_functions(sol_file: str) -> list[DecompiledFunction]:
    """Parse decompiled Solidity file to extract functions."""
    import re

    functions: list[DecompiledFunction] = []

    try:
        content = Path(sol_file).read_text()

        # Match function definitions
        func_pattern = (
            r"function\s+(\w+)\s*\(([^)]*)\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}"
        )
        matches = re.finditer(func_pattern, content, re.DOTALL)

        for match in matches:
            name = match.group(1)
            # Try to extract selector from comments
            selector_match = re.search(r"//.*?0x([a-fA-F0-9]{8})", match.group(0))
            selector = f"0x{selector_match.group(1)}" if selector_match else None

            functions.append(
                DecompiledFunction(
                    selector=selector or "",
                    signature=None,
                    name=name,
                    decompiled=match.group(0),
                )
            )

    except Exception as e:
        log.warning("Failed to parse functions: %s", e)

    return functions
