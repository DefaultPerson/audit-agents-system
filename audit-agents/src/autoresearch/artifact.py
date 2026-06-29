"""Artifact bundle creation and persistence."""

import hashlib
import json
from pathlib import Path

from ..models import Chain, ProxyType
from .models import ArtifactBundle, MaterialRef, SnapshotContext

OPCODES = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x10: "LT",
    0x11: "GT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x20: "SHA3",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x39: "CODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x45: "GASLIMIT",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x5B: "JUMPDEST",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}


def _normalize_bytecode(bytecode_hex: str) -> str:
    """Return lowercase bytecode without 0x prefix."""
    value = bytecode_hex.lower()
    return value[2:] if value.startswith("0x") else value


def _sha256_hex(value: str) -> str:
    """Hash normalized hex text as bytes when possible."""
    try:
        payload = bytes.fromhex(value)
    except ValueError:
        payload = value.encode()
    return "0x" + hashlib.sha256(payload).hexdigest()


def opcode_listing(bytecode_hex: str) -> str:
    """Return a deterministic EVM opcode listing for fallback review."""
    bytecode = bytes.fromhex(_normalize_bytecode(bytecode_hex))
    lines = ["pc opcode argument"]
    pc = 0
    while pc < len(bytecode):
        opcode = bytecode[pc]
        if 0x60 <= opcode <= 0x7F:
            push_size = opcode - 0x5F
            argument = bytecode[pc + 1 : pc + 1 + push_size].hex()
            lines.append(f"0x{pc:04x} PUSH{push_size} 0x{argument}")
            pc += 1 + push_size
            continue
        if 0x80 <= opcode <= 0x8F:
            name = f"DUP{opcode - 0x7F}"
        elif 0x90 <= opcode <= 0x9F:
            name = f"SWAP{opcode - 0x8F}"
        elif 0xA0 <= opcode <= 0xA4:
            name = f"LOG{opcode - 0xA0}"
        else:
            name = OPCODES.get(opcode, f"UNKNOWN_0x{opcode:02x}")
        lines.append(f"0x{pc:04x} {name}")
        pc += 1
    return "\n".join(lines) + "\n"


def write_opcode_listing(bytecode_hex: str, path: str | Path) -> Path:
    """Persist deterministic fallback opcode listing."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(opcode_listing(bytecode_hex), encoding="utf-8")
    return output_path


def build_artifact_bundle(
    *,
    chain: Chain,
    chain_id: int,
    target_address: str,
    resolved_address: str,
    bytecode_hex: str,
    is_proxy: bool,
    proxy_type: ProxyType | None = None,
    selectors: list[str] | None = None,
    snapshot_block: int | None = None,
    decompile_dir: str | Path | None = None,
    dedaub_file: str | Path | None = None,
    runtime_bytecode_path: str | Path | None = None,
    opcode_listing_path: str | Path | None = None,
    snapshot_context: SnapshotContext | None = None,
    tool_versions: dict[str, str] | None = None,
    tool_errors: dict[str, str] | None = None,
) -> ArtifactBundle:
    """Build a minimal immutable artifact bundle from pipeline outputs."""
    normalized_bytecode = _normalize_bytecode(bytecode_hex)
    materials: list[MaterialRef] = []

    if decompile_dir:
        materials.append(
            MaterialRef(
                kind="decompile_dir",
                path=str(decompile_dir),
                description="Directory with Dedaub or fallback decompiler outputs.",
            )
        )
    if dedaub_file:
        materials.append(
            MaterialRef(
                kind="dedaub_solidity",
                path=str(dedaub_file),
                description="Primary decompiled Solidity-like material.",
            )
        )
    if runtime_bytecode_path:
        materials.append(
            MaterialRef(
                kind="runtime_bytecode",
                path=str(runtime_bytecode_path),
                description="Runtime bytecode at snapshot block.",
            )
        )
    if opcode_listing_path:
        materials.append(
            MaterialRef(
                kind="opcode_listing",
                path=str(opcode_listing_path),
                description="Deterministic opcode listing fallback for bytecode review.",
            )
        )

    return ArtifactBundle(
        chain=chain,
        chainId=chain_id,
        snapshotBlock=snapshot_block,
        targetAddress=target_address,
        resolvedAddress=resolved_address,
        isProxy=is_proxy,
        proxyType=proxy_type,
        runtimeBytecodeHash=_sha256_hex(normalized_bytecode),
        runtimeBytecodeSize=len(normalized_bytecode) // 2,
        selectors=selectors or [],
        snapshotContext=snapshot_context or SnapshotContext(),
        materials=materials,
        toolVersions=tool_versions or {},
        toolErrors=tool_errors or {},
    )


def write_artifact_bundle(bundle: ArtifactBundle, path: str | Path) -> Path:
    """Persist an artifact bundle as stable JSON."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        bundle.model_dump_json(by_alias=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return output_path


def load_artifact_bundle(path: str | Path) -> ArtifactBundle:
    """Load an artifact bundle from disk."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ArtifactBundle.model_validate(data)
