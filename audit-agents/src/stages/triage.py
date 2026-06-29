"""
Triage stage - Check if contract should be audited.

Checks:
1. Has bytecode (not EOA)
2. Not a known verified protocol (skip unless proxy)
3. Meets minimum balance criteria
"""

import hashlib
import logging

import httpx
from web3 import AsyncWeb3

from ..config import AuditConfig, get_chain_config
from ..constants import EIP1967_BEACON_SLOT, EIP1967_IMPL_SLOT
from ..models import Chain, SkipReason, TriageResult

log = logging.getLogger(__name__)


def _code_hash(bytecode: bytes) -> str:
    """Calculate SHA256 hash of bytecode."""
    return hashlib.sha256(bytecode).hexdigest()


async def detect_proxy(
    w3: AsyncWeb3, address: str, bytecode: bytes
) -> tuple[bool, str | None]:
    """
    Detect if contract is a proxy.

    Returns (is_proxy, implementation_address).
    Supports: EIP-1167 minimal proxy, EIP-1967 transparent/UUPS, beacon proxies.
    """
    hex_code = bytecode.hex()
    checksum_addr = w3.to_checksum_address(address)

    # 1. EIP-1167 minimal proxy (bytecode pattern)
    if hex_code.startswith("363d3d373d3d3d363d73") and "5af43d82803e903d91602b57fd5bf3" in hex_code:
        impl_addr = "0x" + hex_code[20:60]
        log.debug("EIP-1167 minimal proxy detected, impl=%s", impl_addr)
        return True, impl_addr

    # 2. EIP-1967 transparent/UUPS proxy (storage slot)
    try:
        impl_value = await w3.eth.get_storage_at(checksum_addr, int(EIP1967_IMPL_SLOT, 16))
        if impl_value and impl_value != b'\x00' * 32:
            impl_addr = "0x" + impl_value.hex()[-40:]
            if impl_addr != "0x" + "0" * 40:
                log.debug("EIP-1967 transparent/UUPS proxy detected, impl=%s", impl_addr)
                return True, impl_addr
    except Exception as e:
        log.debug("EIP-1967 impl slot read failed: %s", e)

    # 3. EIP-1967 beacon proxy
    try:
        beacon_value = await w3.eth.get_storage_at(checksum_addr, int(EIP1967_BEACON_SLOT, 16))
        if beacon_value and beacon_value != b'\x00' * 32:
            beacon_addr = "0x" + beacon_value.hex()[-40:]
            if beacon_addr != "0x" + "0" * 40:
                log.debug("EIP-1967 beacon proxy detected, beacon=%s", beacon_addr)
                return True, None
    except Exception as e:
        log.debug("EIP-1967 beacon slot read failed: %s", e)

    return False, None


async def check_contract_verified(
    address: str, chain: Chain, request_timeout: int = 10
) -> tuple[bool, str | None]:
    """Check if contract is verified on block explorer."""
    chain_config = get_chain_config(chain.value)

    if not chain_config.explorer_api_key:
        log.debug("No explorer API key for %s, skipping verification check", chain.value)
        return False, None

    api_url = chain_config.explorer_api_url
    url = (
        f"{api_url}?chainid={chain_config.chain_id}"
        f"&module=contract&action=getsourcecode&address={address}"
        f"&apikey={chain_config.explorer_api_key}"
    )

    try:
        async with httpx.AsyncClient(timeout=request_timeout) as client:
            response = await client.get(url)
            data = response.json()

            if data.get("status") == "1" and data.get("result"):
                result = data["result"][0]
                source_code = result.get("SourceCode", "")
                contract_name = result.get("ContractName")

                is_verified = bool(source_code and len(source_code) > 10)
                if is_verified:
                    log.debug("Contract verified on explorer: %s", contract_name or "unnamed")
                return is_verified, contract_name

            log.debug("Explorer API returned non-success status: %s", data.get("message", "unknown"))
            return False, None
    except httpx.TimeoutException:
        log.warning("Explorer API timeout for %s on %s", address[:10], chain.value)
        return False, None
    except Exception as e:
        log.warning("Explorer API error for %s: %s", address[:10], e)
        return False, None


def _triage_result(
    *,
    address: str,
    chain: Chain,
    passed: bool,
    skip_reason: SkipReason | None,
    is_proxy: bool,
    code_hash: str,
    code_size: int,
    balance_usd: float,
    confidence: float,
    proxy_implementation: str | None = None,
) -> TriageResult:
    return TriageResult.model_validate(
        {
            "address": address,
            "chain": chain,
            "pass": passed,
            "skipReason": skip_reason,
            "isProxy": is_proxy,
            "proxyImplementation": proxy_implementation,
            "codeHash": code_hash,
            "codeSize": code_size,
            "balanceUsd": balance_usd,
            "confidence": confidence,
        }
    )


async def triage_contract(
    address: str,
    chain: Chain,
    balance_usd: float = 0,
) -> TriageResult:
    """
    Triage a contract to determine if it should be audited.

    Returns TriageResult with pass=True if contract should proceed to audit.
    """
    address = address.lower()
    chain_config = get_chain_config(chain.value)
    short_addr = f"{address[:6]}...{address[-4:]}"

    log.info("Triaging %s on %s (balance=$%.0f)", short_addr, chain.value, balance_usd)

    # Connect to RPC
    w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(chain_config.rpc_url))

    # Step 1: Get bytecode
    try:
        bytecode = await w3.eth.get_code(w3.to_checksum_address(address))
    except Exception as e:
        log.warning("Failed to get bytecode for %s: %s", short_addr, e)
        return _triage_result(
            address=address,
            chain=chain,
            passed=False,
            skip_reason=SkipReason.NO_CODE,
            is_proxy=False,
            code_hash="",
            code_size=0,
            balance_usd=balance_usd,
            confidence=1.0,
        )

    # No code = EOA or empty contract
    if not bytecode or bytecode == b"" or bytecode.hex() == "0x":
        log.info("SKIP %s: no bytecode (EOA or selfdestructed)", short_addr)
        return _triage_result(
            address=address,
            chain=chain,
            passed=False,
            skip_reason=SkipReason.NO_CODE,
            is_proxy=False,
            code_hash="",
            code_size=0,
            balance_usd=balance_usd,
            confidence=1.0,
        )

    code_size = len(bytecode)
    code_hash = _code_hash(bytecode)
    log.debug("Bytecode: %d bytes, hash=%s", code_size, code_hash[:16])

    # Step 2: Proxy detection (EIP-1167, EIP-1967)
    is_proxy, impl_address = await detect_proxy(w3, address, bytecode)
    if is_proxy:
        log.info("Proxy detected: impl=%s", impl_address or "beacon")

    # Step 3: Check if it's a known verified protocol
    is_verified, contract_name = await check_contract_verified(address, chain)

    if is_verified and not is_proxy:
        log.info("SKIP %s: verified on explorer (%s)", short_addr, contract_name or "unnamed")
        return _triage_result(
            address=address,
            chain=chain,
            passed=False,
            skip_reason=SkipReason.VERIFIED,
            is_proxy=is_proxy,
            proxy_implementation=impl_address,
            code_hash=code_hash,
            code_size=code_size,
            balance_usd=balance_usd,
            confidence=0.9,
        )

    # Step 4: Check balance threshold
    if balance_usd > 0 and balance_usd < AuditConfig.min_balance_usd:
        log.info(
            "SKIP %s: balance $%.0f < min $%d",
            short_addr, balance_usd, AuditConfig.min_balance_usd
        )
        return _triage_result(
            address=address,
            chain=chain,
            passed=False,
            skip_reason=SkipReason.LOW_BALANCE,
            is_proxy=is_proxy,
            proxy_implementation=impl_address,
            code_hash=code_hash,
            code_size=code_size,
            balance_usd=balance_usd,
            confidence=0.7,
        )

    # Passed all checks
    log.info(
        "PASS %s: %d bytes, proxy=%s, verified=%s",
        short_addr, code_size, is_proxy, is_verified
    )
    return _triage_result(
        address=address,
        chain=chain,
        passed=True,
        skip_reason=None,
        is_proxy=is_proxy,
        proxy_implementation=impl_address,
        code_hash=code_hash,
        code_size=code_size,
        balance_usd=balance_usd,
        confidence=0.85,
    )


async def triage_batch(
    addresses: list[tuple[str, Chain]],
) -> list[TriageResult]:
    """Triage multiple contracts."""
    import asyncio

    log.info("Triaging batch of %d contracts", len(addresses))
    tasks = [triage_contract(addr, chain) for addr, chain in addresses]
    results = await asyncio.gather(*tasks)

    passed = sum(1 for r in results if r.passed)
    log.info("Batch complete: %d/%d passed triage", passed, len(results))

    return results
