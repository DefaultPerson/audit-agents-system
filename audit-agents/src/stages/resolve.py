"""
Resolve stage - Proxy detection and ABI extraction.

Replaces WhatsABI with:
1. EVMole for selector extraction
2. Custom proxy detection via storage slots

Supported proxy types:
- EIP-1967 (Transparent Proxy)
- EIP-1167 (Minimal Proxy / Clone)
- EIP-1822 (UUPS)
- Diamond (EIP-2535)
- Gnosis Safe
- Custom storage-based proxies
"""

import inspect
import logging
from typing import cast

import evmole
from eth_typing import HexStr
from web3 import AsyncWeb3
from web3.types import BlockIdentifier, TxParams

from ..config import get_chain_config
from ..constants import (
    DIAMOND_STORAGE_SLOT,
    EIP1822_IMPL_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPL_SLOT,
    GNOSIS_SINGLETON_SLOT,
    IMPLEMENTATION_SELECTOR,
)
from ..models import Chain, ProxyType, ResolvedContract

log = logging.getLogger(__name__)


async def _close_web3_provider(w3: AsyncWeb3) -> None:
    """Close AsyncWeb3 provider sessions when available."""
    disconnect = getattr(w3.provider, "disconnect", None)
    if callable(disconnect):
        result = disconnect()
        if inspect.isawaitable(result):
            await result


def _slot_position(slot: str) -> int:
    """Convert canonical hex slot constants to Web3's typed storage position."""
    return int(slot, 16)


def _implementation_call(to_address: str) -> TxParams:
    return {
        "to": to_address,
        "data": cast(HexStr, IMPLEMENTATION_SELECTOR),
    }


def _extract_address_from_slot(slot_value: bytes | None) -> str | None:
    """Extract address from storage slot or ABI-encoded return value.

    Handles:
    - 32-byte storage slots (address in last 20 bytes)
    - 20-byte direct returns (e.g., from beacon.implementation())
    """
    if not slot_value:
        return None

    # Handle both 32-byte slots and 20-byte returns
    if len(slot_value) == 20:
        addr_bytes = slot_value
    elif len(slot_value) >= 32:
        addr_bytes = slot_value[-20:]
    else:
        log.debug("Unexpected slot_value length: %d", len(slot_value))
        return None

    # Check if it's a zero address
    if addr_bytes == b"\x00" * 20:
        return None

    return "0x" + addr_bytes.hex()


def _extract_eip1167_impl(bytecode: bytes) -> str | None:
    """Extract implementation address from EIP-1167 minimal proxy bytecode."""
    hex_code = bytecode.hex()

    # Standard pattern: 363d3d373d3d3d363d73<20 bytes address>5af43d82803e903d91602b57fd5bf3
    if hex_code.startswith("363d3d373d3d3d363d73"):
        # Address is next 20 bytes (40 hex chars) after prefix
        addr_hex = hex_code[20:60]
        if len(addr_hex) == 40:
            return "0x" + addr_hex

    # Alternative pattern: look for pattern anywhere in code
    pattern_start = hex_code.find("363d3d373d3d3d363d73")
    if pattern_start != -1:
        addr_start = pattern_start + 20
        addr_hex = hex_code[addr_start : addr_start + 40]
        if len(addr_hex) == 40:
            return "0x" + addr_hex

    return None


async def detect_proxy(
    w3: AsyncWeb3,
    address: str,
    bytecode: bytes,
    block_identifier: BlockIdentifier = "latest",
) -> tuple[ProxyType, str | None]:
    """
    Detect proxy type and implementation address.

    Returns (ProxyType, implementation_address or None).
    """
    checksum_addr = w3.to_checksum_address(address)
    short_addr = f"{address[:8]}...{address[-4:]}"

    # 1. Check EIP-1167 minimal proxy (bytecode pattern)
    impl = _extract_eip1167_impl(bytecode)
    if impl:
        log.debug("%s: EIP-1167 minimal proxy, impl=%s", short_addr, impl[:16])
        return ProxyType.EIP1167, impl

    # 2. Check EIP-1967 implementation slot
    try:
        slot_value = await w3.eth.get_storage_at(
            checksum_addr,
            _slot_position(EIP1967_IMPL_SLOT),
            block_identifier=block_identifier,
        )
        impl = _extract_address_from_slot(slot_value)
        if impl:
            log.debug("%s: EIP-1967 proxy, impl=%s", short_addr, impl[:16])
            return ProxyType.EIP1967, impl
    except Exception as e:
        log.debug("%s: EIP-1967 impl slot read failed: %s", short_addr, e)

    # 3. Check EIP-1967 beacon slot
    try:
        slot_value = await w3.eth.get_storage_at(
            checksum_addr,
            _slot_position(EIP1967_BEACON_SLOT),
            block_identifier=block_identifier,
        )
        beacon_addr = _extract_address_from_slot(slot_value)
        if beacon_addr:
            # Get implementation from beacon
            beacon_checksum = w3.to_checksum_address(beacon_addr)
            try:
                # Call beacon.implementation()
                impl_call = await w3.eth.call(
                    _implementation_call(beacon_checksum),
                    block_identifier,
                )
                impl = _extract_address_from_slot(impl_call)
                if impl:
                    log.debug(
                        "%s: EIP-1967 beacon proxy, beacon=%s, impl=%s",
                        short_addr,
                        beacon_addr[:16],
                        impl[:16],
                    )
                    return ProxyType.EIP1967, impl
            except Exception as e:
                log.debug("%s: beacon.implementation() call failed: %s", short_addr, e)
    except Exception as e:
        log.debug("%s: EIP-1967 beacon slot read failed: %s", short_addr, e)

    # 4. Check EIP-1822 (UUPS) slot
    try:
        slot_value = await w3.eth.get_storage_at(
            checksum_addr,
            _slot_position(EIP1822_IMPL_SLOT),
            block_identifier=block_identifier,
        )
        impl = _extract_address_from_slot(slot_value)
        if impl:
            log.debug("%s: EIP-1822 (UUPS) proxy, impl=%s", short_addr, impl[:16])
            return ProxyType.EIP1967, impl  # UUPS is a variant of EIP-1967
    except Exception as e:
        log.debug("%s: EIP-1822 slot read failed: %s", short_addr, e)

    # 5. Check Diamond (EIP-2535)
    try:
        # Diamond uses facets, check if it has diamond storage
        slot_value = await w3.eth.get_storage_at(
            checksum_addr,
            _slot_position(DIAMOND_STORAGE_SLOT),
            block_identifier=block_identifier,
        )
        if slot_value != b"\x00" * 32:
            # Has diamond storage, but we can't easily get single impl
            # For now, return the proxy type without impl
            log.debug("%s: Diamond proxy detected (facets not resolved)", short_addr)
            return ProxyType.DIAMOND, None
    except Exception as e:
        log.debug("%s: Diamond slot read failed: %s", short_addr, e)

    # 6. Check Gnosis Safe singleton pattern
    try:
        slot_value = await w3.eth.get_storage_at(
            checksum_addr,
            _slot_position(GNOSIS_SINGLETON_SLOT),
            block_identifier=block_identifier,
        )
        impl = _extract_address_from_slot(slot_value)
        if impl:
            # Verify it's a Safe by checking for known Safe selectors
            hex_code = bytecode.hex()
            # execTransaction selector
            if "6a761202" in hex_code:
                log.debug("%s: Gnosis Safe proxy, singleton=%s", short_addr, impl[:16])
                return ProxyType.GNOSIS_SAFE, impl
    except Exception as e:
        log.debug("%s: Gnosis Safe slot read failed: %s", short_addr, e)

    # 7. Try calling implementation() directly
    try:
        impl_call = await w3.eth.call(
            _implementation_call(checksum_addr),
            block_identifier,
        )
        impl = _extract_address_from_slot(impl_call)
        if impl:
            log.debug("%s: Custom proxy (impl() returned %s)", short_addr, impl[:16])
            return ProxyType.CUSTOM, impl
    except Exception as e:
        log.debug("%s: implementation() call failed: %s", short_addr, e)

    return ProxyType.NONE, None


def extract_selectors(bytecode: bytes | None) -> list[str]:
    """Extract function selectors using EVMole."""
    if not bytecode:
        return []

    try:
        hex_code = bytecode.hex()
        if hex_code.startswith("0x"):
            hex_code = hex_code[2:]

        result = evmole.contract_info(hex_code, selectors=True)
        if result and result.functions:
            return [f"0x{func.selector}" for func in result.functions]
        return []
    except Exception as e:
        log.warning("EVMole selector extraction failed: %s", e)
        return []


def extract_function_arguments(bytecode: bytes) -> dict[str, str]:
    """Extract function arguments using EVMole."""
    if not bytecode:
        return {}

    try:
        hex_code = bytecode.hex()
        if hex_code.startswith("0x"):
            hex_code = hex_code[2:]

        result = evmole.contract_info(hex_code, selectors=True, arguments=True)
        if result and result.functions:
            return {
                f"0x{func.selector}": func.arguments or "" for func in result.functions
            }
        return {}
    except Exception as e:
        log.warning("EVMole argument extraction failed: %s", e)
        return {}


async def resolve_contract(
    address: str,
    chain: Chain,
    snapshot_block: int | None = None,
) -> ResolvedContract:
    """
    Resolve a contract - detect proxy and extract ABI information.

    Returns ResolvedContract with resolved implementation address if proxy.
    """
    address = address.lower()
    chain_config = get_chain_config(chain.value)
    short_addr = f"{address[:8]}...{address[-4:]}"

    log.info("Resolving %s on %s", short_addr, chain.value)

    # Connect to RPC
    w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(chain_config.rpc_url))
    checksum_addr = w3.to_checksum_address(address)
    block_identifier: BlockIdentifier = snapshot_block if snapshot_block is not None else "latest"

    try:
        # Get bytecode
        bytecode = await w3.eth.get_code(checksum_addr, block_identifier=block_identifier)
        if not bytecode or bytecode == b"":
            log.debug("%s: No bytecode (EOA or destroyed)", short_addr)
            return ResolvedContract(
                originalAddress=address,
                resolvedAddress=address,
                chain=chain,
                isProxy=False,
                proxyType=None,
                selectors=[],
            )

        # Detect proxy
        proxy_type, impl_address = await detect_proxy(w3, address, bytecode, block_identifier)
        is_proxy = proxy_type != ProxyType.NONE

        # Determine which address to use for analysis
        if is_proxy and impl_address:
            resolved_address = impl_address.lower()
            # Get implementation bytecode for selector extraction
            impl_bytecode = await w3.eth.get_code(
                w3.to_checksum_address(impl_address),
                block_identifier=block_identifier,
            )
            analysis_bytecode = impl_bytecode if impl_bytecode else bytecode
        else:
            resolved_address = address
            analysis_bytecode = bytecode

        # Extract selectors from the resolved bytecode
        selectors = extract_selectors(analysis_bytecode)

        log.info(
            "Resolved %s: proxy=%s, type=%s, selectors=%d",
            short_addr,
            is_proxy,
            proxy_type.value if proxy_type != ProxyType.NONE else "none",
            len(selectors),
        )

        return ResolvedContract(
            originalAddress=address,
            resolvedAddress=resolved_address,
            chain=chain,
            isProxy=is_proxy,
            proxyType=proxy_type if is_proxy else None,
            selectors=selectors,
        )
    finally:
        await _close_web3_provider(w3)


async def get_bytecode(
    address: str,
    chain: Chain,
    snapshot_block: int | None = None,
) -> bytes:
    """Get bytecode for a contract address."""
    chain_config = get_chain_config(chain.value)
    w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(chain_config.rpc_url))
    checksum_addr = w3.to_checksum_address(address)
    block_identifier: BlockIdentifier = snapshot_block if snapshot_block is not None else "latest"
    try:
        return await w3.eth.get_code(checksum_addr, block_identifier=block_identifier)
    finally:
        await _close_web3_provider(w3)
