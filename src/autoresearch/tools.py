"""Cheap deterministic facts and tool manifests exposed to the research loop."""

import inspect
import json
from pathlib import Path
from typing import Any, cast

from eth_typing import HexStr
from web3 import AsyncWeb3
from web3.types import BlockIdentifier, TxParams

from .models import ArtifactBundle

TOKEN_BALANCE_CANDIDATES: dict[str, list[dict[str, str]]] = {
    "eth": [
        {"symbol": "WETH", "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"},
        {"symbol": "USDC", "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
        {"symbol": "USDT", "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7"},
        {"symbol": "DAI", "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F"},
        {"symbol": "WBTC", "address": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"},
    ],
    "bsc": [
        {"symbol": "WBNB", "address": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"},
        {"symbol": "USDT", "address": "0x55d398326f99059fF775485246999027B3197955"},
        {"symbol": "BUSD", "address": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56"},
        {"symbol": "USDC", "address": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"},
    ],
    "base": [
        {"symbol": "WETH", "address": "0x4200000000000000000000000000000000000006"},
        {"symbol": "USDC", "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
    ],
    "polygon": [
        {"symbol": "WMATIC", "address": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"},
        {"symbol": "USDC", "address": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"},
        {"symbol": "USDT", "address": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F"},
    ],
    "arbitrum": [
        {"symbol": "WETH", "address": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"},
        {"symbol": "USDC", "address": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"},
        {"symbol": "USDT", "address": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"},
    ],
}


def _chain_token_candidates(chain: str) -> list[dict[str, str]]:
    return TOKEN_BALANCE_CANDIDATES.get(chain, [])


def build_cheap_fact_index(
    bundle: ArtifactBundle,
    materialized_tool_dir: str | Path | None = None,
) -> set[str]:
    """Build fact refs that model hypotheses are allowed to cite."""
    facts = {
        f"bytecode_hash:{bundle.runtime_bytecode_hash}",
        f"bytecode_size:{bundle.runtime_bytecode_size}",
        f"chain:{bundle.chain.value}",
        f"target:{bundle.target_address}",
        f"resolved:{bundle.resolved_address}",
        f"proxy:{str(bundle.is_proxy).lower()}",
    }
    if bundle.proxy_type:
        facts.add(f"proxy_type:{bundle.proxy_type.value}")
    facts.update(f"selector:{selector}" for selector in bundle.selectors)
    facts.update(f"material:{material.kind}" for material in bundle.materials)
    if materialized_tool_dir:
        facts.update(collect_materialized_facts(materialized_tool_dir))
    return facts


def write_cheap_fact_index(
    bundle: ArtifactBundle,
    path: str | Path,
    materialized_tool_dir: str | Path | None = None,
) -> Path:
    """Persist deterministic cheap facts as a JSON array."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(sorted(build_cheap_fact_index(bundle, materialized_tool_dir)), indent=2) + "\n",
        encoding="utf-8",
    )
    return output_path


def build_cheap_tool_manifest(bundle: ArtifactBundle) -> dict:
    """Build deterministic tool requests for Pi.dev/worker loops.

    Planned artifacts are not evidence. They are explicit contracts for tools
    that may later materialize storage, trace or call facts at the pinned block.
    """
    block = bundle.snapshot_block or "latest"
    proxy_slots = [
        {
            "label": "eip1967.implementation",
            "slot": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        },
        {
            "label": "eip1967.admin",
            "slot": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
        },
        {
            "label": "eip1967.beacon",
            "slot": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
        },
    ]

    return {
        "schemaVersion": "evm-cheap-tool-manifest/v1",
        "chain": bundle.chain.value,
        "chainId": bundle.chain_id,
        "snapshotBlock": bundle.snapshot_block,
        "targetAddress": bundle.target_address,
        "resolvedAddress": bundle.resolved_address,
        "tools": [
            {
                "name": "selector_lookup",
                "status": "observed",
                "artifact": "selector_lookup.json",
                "evidenceRefs": [f"selector:{selector}" for selector in bundle.selectors],
            },
            {
                "name": "static_reachability",
                "status": "observed",
                "artifact": "static_reachability.json",
                "inputs": {
                    "selectors": bundle.selectors[:50],
                    "materials": [material.path for material in bundle.materials],
                },
                "evidenceRefs": [f"reachability:selector:{selector}" for selector in bundle.selectors],
            },
            {
                "name": "raw_storage_read",
                "status": "planned",
                "artifact": "storage_read_plan.json",
                "inputs": {
                    "address": bundle.resolved_address,
                    "block": block,
                    "slots": proxy_slots,
                },
                "evidenceRefs": [],
            },
            {
                "name": "storage_diff_around_tx",
                "status": "planned",
                "artifact": "storage_diff_plan.json",
                "inputs": {
                    "address": bundle.resolved_address,
                    "block": block,
                    "sourceTransactionsArtifact": "recent_logs.json",
                    "slots": proxy_slots,
                    "window": "before_after_each_recent_tx",
                },
                "evidenceRefs": [],
            },
            {
                "name": "recent_trace_read",
                "status": "planned",
                "artifact": "trace_read_plan.json",
                "materializedArtifacts": ["recent_logs.json", "recent_traces.json"],
                "inputs": {
                    "address": bundle.target_address,
                    "block": block,
                    "limit": 25,
                },
                "evidenceRefs": [],
            },
            {
                "name": "cast_call",
                "status": "planned",
                "artifact": "cast_call_plan.json",
                "inputs": {
                    "address": bundle.resolved_address,
                    "block": block,
                    "selectors": bundle.selectors[:20],
                },
                "evidenceRefs": [],
            },
            {
                "name": "native_balance_scan",
                "status": "planned",
                "artifact": "native_balance_plan.json",
                "inputs": {
                    "block": block,
                    "addresses": [bundle.target_address, bundle.resolved_address],
                },
                "evidenceRefs": [],
            },
            {
                "name": "token_balance_candidates",
                "status": "planned",
                "artifact": "token_balance_plan.json",
                "materializedArtifact": "token_balances.json",
                "inputs": {
                    "block": block,
                    "addresses": [bundle.target_address, bundle.resolved_address],
                    "tokens": _chain_token_candidates(bundle.chain.value),
                },
                "evidenceRefs": [],
            },
            {
                "name": "rag_exploit_search",
                "status": "planned",
                "artifact": "rag_search_plan.json",
                "inputs": {
                    "selectors": bundle.selectors[:20],
                    "domains": [
                        "access_control",
                        "proxy_storage_delegatecall",
                        "oracle_price_liquidity",
                        "external_calls_reentrancy",
                    ],
                    "materials": [material.path for material in bundle.materials],
                    "limit": 5,
                },
                "evidenceRefs": [],
            },
        ],
    }


def write_cheap_tool_artifacts(bundle: ArtifactBundle, output_dir: str | Path) -> Path:
    """Write deterministic cheap-tool plans and return the manifest path."""
    tool_dir = Path(output_dir)
    tool_dir.mkdir(parents=True, exist_ok=True)

    selector_lookup = {
        "schemaVersion": "evm-selector-lookup/v1",
        "status": "observed",
        "selectors": [
            {
                "selector": selector,
                "evidenceRef": f"selector:{selector}",
                "source": "runtime_bytecode",
            }
            for selector in bundle.selectors
        ],
    }
    storage_read_plan = {
        "schemaVersion": "evm-storage-read-plan/v1",
        "status": "planned",
        "note": "Fill with cast storage/RPC results before citing storage facts.",
        "requests": [
            tool["inputs"]
            for tool in build_cheap_tool_manifest(bundle)["tools"]
            if tool["name"] == "raw_storage_read"
        ],
    }
    static_reachability = {
        "schemaVersion": "evm-static-reachability/v1",
        "status": "observed",
        "note": "Selector-level static reachability hint derived from runtime selector recovery.",
        "selectors": [
            {
                "selector": selector,
                "evidenceRef": f"reachability:selector:{selector}",
                "source": "runtime_selector_recovery",
            }
            for selector in bundle.selectors
        ],
    }
    trace_read_plan = {
        "schemaVersion": "evm-trace-read-plan/v1",
        "status": "planned",
        "note": "Fill with tx/log/trace artifacts before citing trace facts.",
        "requests": [
            tool["inputs"]
            for tool in build_cheap_tool_manifest(bundle)["tools"]
            if tool["name"] == "recent_trace_read"
        ],
    }
    cast_call_plan = {
        "schemaVersion": "evm-cast-call-plan/v1",
        "status": "planned",
        "note": "Fill with pinned-block cast call outputs before citing fork behavior.",
        "requests": [
            tool["inputs"]
            for tool in build_cheap_tool_manifest(bundle)["tools"]
            if tool["name"] == "cast_call"
        ],
    }
    native_balance_plan = {
        "schemaVersion": "evm-native-balance-plan/v1",
        "status": "planned",
        "note": "Fill with pinned-block native balance outputs before citing balance facts.",
        "requests": [
            tool["inputs"]
            for tool in build_cheap_tool_manifest(bundle)["tools"]
            if tool["name"] == "native_balance_scan"
        ],
    }
    token_balance_plan = {
        "schemaVersion": "evm-token-balance-plan/v1",
        "status": "planned",
        "note": "Fill with pinned-block ERC-20 balanceOf outputs before citing token balance facts.",
        "requests": [
            tool["inputs"]
            for tool in build_cheap_tool_manifest(bundle)["tools"]
            if tool["name"] == "token_balance_candidates"
        ],
    }
    storage_diff_plan = {
        "schemaVersion": "evm-storage-diff-plan/v1",
        "status": "planned",
        "note": "Fill with before/after storage around recent txs before citing storage diff facts.",
        "requests": [
            tool["inputs"]
            for tool in build_cheap_tool_manifest(bundle)["tools"]
            if tool["name"] == "storage_diff_around_tx"
        ],
    }
    rag_search_plan = {
        "schemaVersion": "evm-rag-search-plan/v1",
        "status": "planned",
        "note": "Fill with curated RAG hits before citing exploit precedent facts.",
        "requests": [
            tool["inputs"]
            for tool in build_cheap_tool_manifest(bundle)["tools"]
            if tool["name"] == "rag_exploit_search"
        ],
    }

    artifacts = {
        "selector_lookup.json": selector_lookup,
        "static_reachability.json": static_reachability,
        "storage_read_plan.json": storage_read_plan,
        "storage_diff_plan.json": storage_diff_plan,
        "trace_read_plan.json": trace_read_plan,
        "cast_call_plan.json": cast_call_plan,
        "native_balance_plan.json": native_balance_plan,
        "token_balance_plan.json": token_balance_plan,
        "rag_search_plan.json": rag_search_plan,
    }
    for filename, payload in artifacts.items():
        (tool_dir / filename).write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )

    manifest_path = tool_dir / "tool_manifest.json"
    manifest_path.write_text(
        json.dumps(build_cheap_tool_manifest(bundle), indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def _block_identifier(bundle: ArtifactBundle) -> BlockIdentifier:
    return bundle.snapshot_block if bundle.snapshot_block is not None else "latest"


def _hex(value: Any) -> str:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if hasattr(value, "hex"):
        hex_value = value.hex()
        return hex_value if str(hex_value).startswith("0x") else f"0x{hex_value}"
    return str(value)


def _log_to_json(log: Any) -> dict[str, Any]:
    data = dict(log)
    for key in ("transactionHash", "blockHash"):
        if key in data and data[key] is not None:
            data[key] = _hex(data[key])
    if "topics" in data:
        data["topics"] = [_hex(topic) for topic in data["topics"]]
    if "data" in data:
        data["data"] = _hex(data["data"])
    return data


async def materialize_cheap_tool_artifacts(
    bundle: ArtifactBundle,
    output_dir: str | Path,
    *,
    rpc_url: str,
    cast_selector_limit: int = 10,
    log_window_blocks: int = 5_000,
    log_limit: int = 25,
) -> Path:
    """Materialize portable cheap facts from RPC without claiming vulnerability evidence."""
    tool_dir = Path(output_dir)
    tool_dir.mkdir(parents=True, exist_ok=True)
    w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(rpc_url))
    try:
        block_identifier = _block_identifier(bundle)

        storage_results = await _read_storage_slots(w3, bundle, block_identifier)
        balance_results = await _read_native_balances(w3, bundle, block_identifier)
        token_balance_results = await _read_token_balances(w3, bundle, block_identifier)
        call_results = await _run_cast_calls(
            w3,
            bundle,
            block_identifier,
            cast_selector_limit=cast_selector_limit,
        )
        log_results = await _read_recent_logs(
            w3,
            bundle,
            block_identifier=block_identifier,
            log_window_blocks=log_window_blocks,
            log_limit=log_limit,
        )
        trace_results = await _read_recent_traces(w3, log_results, trace_limit=5)
        storage_diff_results = await _read_storage_diffs(w3, bundle, log_results, diff_limit=5)
    finally:
        await _close_web3_provider(w3)
    rag_results = await _run_rag_exploit_search(bundle)

    outputs = {
        "storage_reads.json": storage_results,
        "storage_diffs.json": storage_diff_results,
        "native_balances.json": balance_results,
        "token_balances.json": token_balance_results,
        "cast_calls.json": call_results,
        "recent_logs.json": log_results,
        "recent_traces.json": trace_results,
        "rag_hits.json": rag_results,
    }
    for filename, payload in outputs.items():
        (tool_dir / filename).write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )

    manifest_path = tool_dir / "tool_manifest.json"
    manifest = build_cheap_tool_manifest(bundle)
    materialized_refs = sorted(collect_materialized_facts(tool_dir))
    manifest["materializedArtifacts"] = sorted(outputs)
    manifest["materializedEvidenceRefs"] = materialized_refs
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_path


async def _close_web3_provider(w3: AsyncWeb3) -> None:
    """Close AsyncWeb3 provider sessions when the provider exposes a close hook."""
    disconnect = getattr(w3.provider, "disconnect", None)
    if callable(disconnect):
        result = disconnect()
        if inspect.isawaitable(result):
            await result


async def _read_storage_slots(
    w3: AsyncWeb3,
    bundle: ArtifactBundle,
    block_identifier: BlockIdentifier,
) -> dict[str, Any]:
    storage_tool = next(
        tool for tool in build_cheap_tool_manifest(bundle)["tools"] if tool["name"] == "raw_storage_read"
    )
    slots = storage_tool["inputs"]["slots"]
    reads = []
    errors = []
    for slot in slots:
        label = slot["label"]
        try:
            value = await w3.eth.get_storage_at(
                w3.to_checksum_address(bundle.resolved_address),
                int(slot["slot"], 16),
                block_identifier=block_identifier,
            )
            reads.append(
                {
                    "label": label,
                    "slot": slot["slot"],
                    "value": _hex(value),
                    "evidenceRef": f"storage:{label}",
                }
            )
        except Exception as exc:  # noqa: BLE001 - stored as tool error artifact
            errors.append({"label": label, "slot": slot["slot"], "error": str(exc)[:500]})

    return {
        "schemaVersion": "evm-storage-reads/v1",
        "status": "observed" if reads else "error",
        "block": block_identifier,
        "address": bundle.resolved_address,
        "reads": reads,
        "errors": errors,
    }


async def _read_native_balances(
    w3: AsyncWeb3,
    bundle: ArtifactBundle,
    block_identifier: BlockIdentifier,
) -> dict[str, Any]:
    addresses = [
        ("target", bundle.target_address),
        ("resolved", bundle.resolved_address),
    ]
    reads = []
    errors = []
    seen: set[str] = set()
    for role, address in addresses:
        if address in seen:
            continue
        seen.add(address)
        try:
            balance = await w3.eth.get_balance(
                w3.to_checksum_address(address),
                block_identifier=block_identifier,
            )
            reads.append(
                {
                    "role": role,
                    "address": address,
                    "balanceWei": str(balance),
                    "evidenceRef": f"balance:native:{role}",
                }
            )
        except Exception as exc:  # noqa: BLE001 - stored as tool error artifact
            errors.append({"role": role, "address": address, "error": str(exc)[:500]})

    return {
        "schemaVersion": "evm-native-balances/v1",
        "status": "observed" if reads else "error",
        "block": block_identifier,
        "reads": reads,
        "errors": errors,
    }


async def _read_token_balances(
    w3: AsyncWeb3,
    bundle: ArtifactBundle,
    block_identifier: BlockIdentifier,
) -> dict[str, Any]:
    tokens = _chain_token_candidates(bundle.chain.value)
    addresses = [
        ("target", bundle.target_address),
        ("resolved", bundle.resolved_address),
    ]
    reads = []
    errors = []
    seen: set[tuple[str, str]] = set()

    for token in tokens:
        token_address = token["address"]
        token_symbol = token["symbol"]
        for role, holder in addresses:
            key = (token_address.lower(), holder.lower())
            if key in seen:
                continue
            seen.add(key)
            try:
                tx: TxParams = {
                    "to": w3.to_checksum_address(token_address),
                    "data": cast(HexStr, _balance_of_data(holder)),
                }
                result = await w3.eth.call(tx, block_identifier)
                reads.append(
                    {
                        "symbol": token_symbol,
                        "tokenAddress": token_address.lower(),
                        "holderRole": role,
                        "holderAddress": holder,
                        "balanceRaw": str(int.from_bytes(bytes(result), "big")),
                        "evidenceRef": f"balance:token:{token_symbol.lower()}:{role}",
                    }
                )
            except Exception as exc:  # noqa: BLE001 - token calls may revert on non-standard tokens
                errors.append(
                    {
                        "symbol": token_symbol,
                        "tokenAddress": token_address.lower(),
                        "holderRole": role,
                        "holderAddress": holder,
                        "error": str(exc)[:500],
                    }
                )

    return {
        "schemaVersion": "evm-token-balances/v1",
        "status": "observed" if reads else "error",
        "block": block_identifier,
        "reads": reads,
        "errors": errors,
    }


def _balance_of_data(holder: str) -> str:
    return "0x70a08231" + holder.lower().removeprefix("0x").rjust(64, "0")


async def _run_cast_calls(
    w3: AsyncWeb3,
    bundle: ArtifactBundle,
    block_identifier: BlockIdentifier,
    *,
    cast_selector_limit: int,
) -> dict[str, Any]:
    calls = []
    for selector in bundle.selectors[:cast_selector_limit]:
        entry: dict[str, Any] = {"selector": selector}
        try:
            tx: TxParams = {
                "to": w3.to_checksum_address(bundle.resolved_address),
                "data": cast(HexStr, selector),
            }
            result = await w3.eth.call(
                tx,
                block_identifier,
            )
            entry.update(
                {
                    "status": "success",
                    "result": _hex(result),
                    "evidenceRef": f"call:{selector}",
                }
            )
        except Exception as exc:  # noqa: BLE001 - revert/error is useful context
            entry.update({"status": "reverted_or_error", "error": str(exc)[:500]})
        calls.append(entry)

    return {
        "schemaVersion": "evm-cast-calls/v1",
        "status": "observed",
        "block": block_identifier,
        "address": bundle.resolved_address,
        "calls": calls,
    }


async def _read_recent_logs(
    w3: AsyncWeb3,
    bundle: ArtifactBundle,
    *,
    block_identifier: BlockIdentifier,
    log_window_blocks: int,
    log_limit: int,
) -> dict[str, Any]:
    try:
        end_block = (
            block_identifier if isinstance(block_identifier, int) else await w3.eth.block_number
        )
        from_block = max(0, end_block - log_window_blocks)
        logs = await w3.eth.get_logs(
            {
                "address": w3.to_checksum_address(bundle.target_address),
                "fromBlock": from_block,
                "toBlock": end_block,
            }
        )
        entries = []
        for log in logs[-log_limit:]:
            item = _log_to_json(log)
            tx_hash = item.get("transactionHash", "unknown")
            log_index = item.get("logIndex", "unknown")
            item["evidenceRef"] = f"log:{tx_hash}:{log_index}"
            entries.append(item)
        return {
            "schemaVersion": "evm-recent-logs/v1",
            "status": "observed",
            "fromBlock": from_block,
            "toBlock": end_block,
            "logs": entries,
        }
    except Exception as exc:  # noqa: BLE001 - RPC trace/log gaps are expected on BSC
        return {
            "schemaVersion": "evm-recent-logs/v1",
            "status": "error",
            "block": block_identifier,
            "logs": [],
            "errors": [str(exc)[:500]],
        }


async def _read_recent_traces(
    w3: AsyncWeb3,
    log_results: dict[str, Any],
    *,
    trace_limit: int,
) -> dict[str, Any]:
    tx_hashes = _tx_hashes_from_logs(log_results)[:trace_limit]
    if not tx_hashes:
        return {
            "schemaVersion": "evm-recent-traces/v1",
            "status": "skipped",
            "traces": [],
            "errors": [],
        }

    traces = []
    errors = []
    for tx_hash in tx_hashes:
        trace = await _trace_transaction(w3, tx_hash)
        if trace["status"] == "observed":
            traces.append(trace)
        else:
            errors.append(trace)

    return {
        "schemaVersion": "evm-recent-traces/v1",
        "status": "observed" if traces else "error",
        "traces": traces,
        "errors": errors,
    }


def _tx_hashes_from_logs(log_results: dict[str, Any]) -> list[str]:
    hashes = []
    seen: set[str] = set()
    for log in log_results.get("logs", []):
        if not isinstance(log, dict):
            continue
        tx_hash = log.get("transactionHash")
        if not isinstance(tx_hash, str) or tx_hash in seen:
            continue
        seen.add(tx_hash)
        hashes.append(tx_hash)
    return hashes


def _parse_block_number(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith("0x") else int(value)
        except ValueError:
            return None
    return None


async def _read_storage_diffs(
    w3: AsyncWeb3,
    bundle: ArtifactBundle,
    log_results: dict[str, Any],
    *,
    diff_limit: int,
) -> dict[str, Any]:
    storage_tool = next(
        tool for tool in build_cheap_tool_manifest(bundle)["tools"] if tool["name"] == "storage_diff_around_tx"
    )
    slots = storage_tool["inputs"]["slots"]
    diffs = []
    errors = []
    seen_txs: set[str] = set()

    for log in log_results.get("logs", []):
        if len(seen_txs) >= diff_limit:
            break
        if not isinstance(log, dict):
            continue
        tx_hash = log.get("transactionHash")
        block_number = _parse_block_number(log.get("blockNumber"))
        if not isinstance(tx_hash, str) or block_number is None or block_number <= 0:
            continue
        if tx_hash in seen_txs:
            continue
        seen_txs.add(tx_hash)
        for slot in slots:
            label = slot["label"]
            try:
                before = await w3.eth.get_storage_at(
                    w3.to_checksum_address(bundle.resolved_address),
                    int(slot["slot"], 16),
                    block_identifier=block_number - 1,
                )
                after = await w3.eth.get_storage_at(
                    w3.to_checksum_address(bundle.resolved_address),
                    int(slot["slot"], 16),
                    block_identifier=block_number,
                )
            except Exception as exc:  # noqa: BLE001 - diagnostic artifact only
                errors.append(
                    {
                        "transactionHash": tx_hash,
                        "label": label,
                        "slot": slot["slot"],
                        "error": str(exc)[:500],
                    }
                )
                continue
            before_hex = _hex(before)
            after_hex = _hex(after)
            if before_hex == after_hex:
                continue
            diffs.append(
                {
                    "transactionHash": tx_hash,
                    "label": label,
                    "slot": slot["slot"],
                    "before": before_hex,
                    "after": after_hex,
                    "beforeBlock": block_number - 1,
                    "afterBlock": block_number,
                    "evidenceRef": f"storage_diff:{tx_hash}:{label}",
                }
            )

    status = "observed" if diffs else ("no_changes" if seen_txs else "skipped")
    return {
        "schemaVersion": "evm-storage-diffs/v1",
        "status": status,
        "address": bundle.resolved_address,
        "diffs": diffs,
        "errors": errors,
    }


async def _trace_transaction(w3: AsyncWeb3, tx_hash: str) -> dict[str, Any]:
    attempts = [
        ("debug_traceTransaction", [tx_hash, {"tracer": "callTracer", "timeout": "5s"}]),
        ("trace_transaction", [tx_hash]),
    ]
    errors = []
    for method, params in attempts:
        try:
            response = await w3.provider.make_request(method, params)
            if isinstance(response, dict) and response.get("error"):
                errors.append({"method": method, "error": _json_safe(response["error"])})
                continue
            result = response.get("result") if isinstance(response, dict) else response
            return {
                "status": "observed",
                "method": method,
                "transactionHash": tx_hash,
                "trace": _json_safe(result),
                "evidenceRef": f"trace:{tx_hash}",
            }
        except Exception as exc:  # noqa: BLE001 - provider-specific trace APIs are optional
            errors.append({"method": method, "error": str(exc)[:500]})

    return {
        "status": "error",
        "transactionHash": tx_hash,
        "errors": errors,
    }


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return _hex(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(nested) for key, nested in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    if hasattr(value, "hex") and not isinstance(value, str):
        return _hex(value)
    return value


def _safe_snippet(path: str, *, limit: int = 2_000) -> str:
    try:
        source = Path(path)
        if not source.is_file():
            return ""
        return source.read_text(encoding="utf-8", errors="ignore")[:limit]
    except OSError:
        return ""


def _build_rag_query(bundle: ArtifactBundle) -> str:
    material_snippets = "\n".join(
        snippet
        for snippet in (_safe_snippet(material.path, limit=1_000) for material in bundle.materials[:3])
        if snippet
    )
    return "\n".join(
        [
            f"chain: {bundle.chain.value}",
            f"proxy: {bundle.is_proxy} {bundle.proxy_type.value if bundle.proxy_type else ''}",
            "selectors: " + ", ".join(bundle.selectors[:20]),
            "domains: access control, proxy storage delegatecall, oracle price liquidity, reentrancy",
            material_snippets,
        ]
    ).strip()


async def _run_rag_exploit_search(bundle: ArtifactBundle, *, limit: int = 5) -> dict[str, Any]:
    query = _build_rag_query(bundle)
    if not query:
        return {
            "schemaVersion": "evm-rag-hits/v1",
            "status": "skipped",
            "query": "",
            "hits": [],
            "errors": ["empty RAG query"],
        }
    try:
        from ..rag.search import hybrid_search

        results = await hybrid_search(query, limit=limit)
    except Exception as exc:  # noqa: BLE001 - RAG is optional and often unconfigured locally
        return {
            "schemaVersion": "evm-rag-hits/v1",
            "status": "error",
            "query": query,
            "hits": [],
            "errors": [str(exc)[:500]],
        }

    hits = []
    for index, result in enumerate(results[:limit], start=1):
        hit_id = result.id or f"result-{index}"
        hits.append(
            {
                "id": hit_id,
                "name": result.name,
                "chain": result.chain,
                "attackType": result.attack_type,
                "rootCause": result.root_cause,
                "summary": result.summary,
                "score": result.score,
                "matchType": result.match_type,
                "filePath": result.file_path,
                "evidenceRef": f"rag:{index}:{hit_id}",
            }
        )
    return {
        "schemaVersion": "evm-rag-hits/v1",
        "status": "observed" if hits else "empty",
        "query": query,
        "hits": hits,
        "errors": [],
    }


def collect_materialized_facts(tool_dir: str | Path) -> set[str]:
    """Collect evidence refs from materialized cheap-tool artifacts."""
    facts: set[str] = set()
    for filename in (
        "storage_reads.json",
        "storage_diffs.json",
        "native_balances.json",
        "token_balances.json",
        "cast_calls.json",
        "recent_logs.json",
        "recent_traces.json",
        "rag_hits.json",
    ):
        path = Path(tool_dir) / filename
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        facts.update(_collect_evidence_refs(data))
    return facts


def _collect_evidence_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        ref = value.get("evidenceRef")
        if isinstance(ref, str):
            refs.add(ref)
        for nested in value.values():
            refs.update(_collect_evidence_refs(nested))
    elif isinstance(value, list):
        for item in value:
            refs.update(_collect_evidence_refs(item))
    return refs
