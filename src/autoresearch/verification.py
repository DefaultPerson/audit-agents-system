"""Verification package generation for consensus hypotheses."""

import hashlib
import json
import re
from pathlib import Path

from .models import ArtifactBundle, AttackHypothesis, ValidationMethod, VerificationPackage


def _safe_id(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "_", value).strip("_") or "hypothesis"


def _rpc_env_var(chain_value: str) -> str:
    return f"{chain_value.upper()}_RPC_URL"


def _foundry_stub(bundle: ArtifactBundle, hypothesis: AttackHypothesis) -> str:
    selectors = ", ".join(hypothesis.affected_selectors) or "fallback/unknown"
    rpc_env = _rpc_env_var(bundle.chain.value)
    contract_name = "AutoresearchHypothesisTest"

    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface Vm {{
    function createSelectFork(string calldata rpcUrl) external returns (uint256);
    function createSelectFork(string calldata rpcUrl, uint256 blockNumber) external returns (uint256);
    function envString(string calldata key) external view returns (string memory);
}}

contract {contract_name} {{
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant TARGET = {bundle.resolved_address};

    function setUp() public {{
        {_fork_statement(rpc_env, bundle.snapshot_block)}
    }}

    function testHypothesis() public {{
        // Hypothesis: {hypothesis.title}
        // Selectors: {selectors}
        // Preconditions:
{_comment_lines(hypothesis.preconditions, "        // - ")}
        // Expected impact: {hypothesis.expected_impact}
        //
        // Replace this scaffold with concrete calls and assertions.
        // A passing empty test is not evidence.
        require(TARGET.code.length > 0, "target must exist on fork");
    }}
}}
"""


def _fork_statement(rpc_env: str, snapshot_block: int | None) -> str:
    if snapshot_block is None:
        return f'vm.createSelectFork(vm.envString("{rpc_env}"));'
    return f'vm.createSelectFork(vm.envString("{rpc_env}"), {snapshot_block});'


def _comment_lines(values: list[str], prefix: str) -> str:
    if not values:
        return f"{prefix}none recorded"
    return "\n".join(f"{prefix}{value}" for value in values)


def _instructions(bundle: ArtifactBundle, hypothesis: AttackHypothesis) -> str:
    methods = ", ".join(method.value for method in hypothesis.validation_methods)
    return f"""# Verification package: {hypothesis.id}

This package validates one consensus hypothesis only.

## Target

- Chain: `{bundle.chain.value}`
- Snapshot block: `{bundle.snapshot_block or "latest/not pinned"}`
- Target: `{bundle.target_address}`
- Resolved implementation: `{bundle.resolved_address}`
- Runtime bytecode hash: `{bundle.runtime_bytecode_hash}`

## Hypothesis

- Domain: `{hypothesis.domain.value}`
- Title: {hypothesis.title}
- Affected selectors: {", ".join(hypothesis.affected_selectors) or "unknown"}
- Validation methods: {methods}

## Preconditions

{_markdown_list(hypothesis.preconditions)}

## Evidence refs

{_markdown_list(hypothesis.evidence_refs)}

## Rule

Do not promote this hypothesis to a finding until a fork/fuzz/symbolic/property
artifact demonstrates the impact. Reasoning-only output remains internal research
memory.
"""


def _ityfuzz_plan(bundle: ArtifactBundle, hypothesis: AttackHypothesis) -> str:
    selectors = ", ".join(hypothesis.affected_selectors) or "fallback/unknown"
    block = bundle.snapshot_block or "latest/not pinned"
    return f"""# ItyFuzz plan: {hypothesis.id}

This is a bytecode-level fuzzing plan for one consensus hypothesis.

- Chain: `{bundle.chain.value}`
- Snapshot block: `{block}`
- Target: `{bundle.resolved_address}`
- Selectors: {selectors}
- Expected impact: {hypothesis.expected_impact}

The wrapper script must be replaced with a concrete ItyFuzz command and must
emit `VALIDATED_EVIDENCE: true` only after a reproducible exploit artifact exists.
"""


def _ityfuzz_script(bundle: ArtifactBundle, hypothesis: AttackHypothesis) -> str:
    selectors = " ".join(hypothesis.affected_selectors)
    block_arg = f"--onchain-block-number {bundle.snapshot_block}" if bundle.snapshot_block else ""
    return f"""#!/usr/bin/env bash
set -euo pipefail

# Hypothesis: {hypothesis.id}
# Selectors: {selectors or "fallback/unknown"}
# Replace this scaffold with a concrete ItyFuzz invocation and reproducible artifact checks.
# A passing empty fuzz run is not evidence.

ITYFUZZ_BIN="${{ITYFUZZ_BIN:-ityfuzz}}"
TARGET="{bundle.resolved_address}"

echo "Scaffold only. Example shape:"
echo "$ITYFUZZ_BIN evm --target $TARGET {block_arg}"
exit 2
"""


def _sha256_file(path: Path) -> str:
    return "0x" + hashlib.sha256(path.read_bytes()).hexdigest()


def _file_manifest_entry(path: Path, package_dir: Path, role: str) -> dict[str, str | int]:
    return {
        "path": str(path.relative_to(package_dir)),
        "role": role,
        "sha256": _sha256_file(path),
        "sizeBytes": path.stat().st_size,
    }


def _write_evidence_manifest(
    *,
    package_dir: Path,
    bundle: ArtifactBundle,
    hypothesis: AttackHypothesis,
    files: dict[str, Path],
) -> Path:
    manifest_path = package_dir / "evidence_manifest.json"
    manifest = {
        "schemaVersion": "evm-verification-evidence-manifest/v1",
        "status": "planned",
        "hypothesisId": hypothesis.id,
        "chain": bundle.chain.value,
        "snapshotBlock": bundle.snapshot_block,
        "targetAddress": bundle.target_address,
        "resolvedAddress": bundle.resolved_address,
        "runtimeBytecodeHash": bundle.runtime_bytecode_hash,
        "files": [
            _file_manifest_entry(path, package_dir, role)
            for role, path in sorted(files.items())
            if path.exists()
        ],
        "promotionRule": (
            "Only validator outputs with explicit validated evidence markers can promote "
            "this package to a finding."
        ),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def _write_worker_receipt(
    *,
    package_dir: Path,
    bundle: ArtifactBundle,
    hypothesis: AttackHypothesis,
    artifact_path: str | Path,
) -> Path:
    receipt_path = package_dir / "worker_receipt.json"
    receipt = {
        "schemaVersion": "evm-verification-worker-receipt/v1",
        "workerScope": "one_consensus_hypothesis",
        "hypothesisId": hypothesis.id,
        "goalId": hypothesis.goal_id,
        "chain": bundle.chain.value,
        "snapshotBlock": bundle.snapshot_block,
        "targetAddress": bundle.target_address,
        "artifactPath": str(artifact_path),
        "packageDir": str(package_dir),
        "validationMethods": [method.value for method in hypothesis.validation_methods],
        "status": "package_written",
        "promotionRule": "Worker output is not validation evidence; validator results decide.",
    }
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt_path


def _markdown_list(values: list[str]) -> str:
    if not values:
        return "- none"
    return "\n".join(f"- {value}" for value in values)


def write_verification_package(
    *,
    bundle: ArtifactBundle,
    hypothesis: AttackHypothesis,
    artifact_path: str | Path,
    output_dir: str | Path,
) -> VerificationPackage:
    """Write package files for validating exactly one consensus hypothesis."""
    package_dir = Path(output_dir) / _safe_id(hypothesis.id)
    package_dir.mkdir(parents=True, exist_ok=True)

    hypothesis_path = package_dir / "hypothesis.json"
    instructions_path = package_dir / "README.md"
    foundry_test_path = package_dir / f"{_safe_id(hypothesis.id)}.t.sol"
    ityfuzz_plan_path = package_dir / "ityfuzz_plan.md"
    ityfuzz_script_path = package_dir / "run_ityfuzz.sh"
    worker_receipt_path = package_dir / "worker_receipt.json"

    hypothesis_path.write_text(
        json.dumps(hypothesis.model_dump(by_alias=True, mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    instructions_path.write_text(_instructions(bundle, hypothesis), encoding="utf-8")
    foundry_test_path.write_text(_foundry_stub(bundle, hypothesis), encoding="utf-8")
    ityfuzz_plan_path.write_text(_ityfuzz_plan(bundle, hypothesis), encoding="utf-8")
    ityfuzz_script_path.write_text(_ityfuzz_script(bundle, hypothesis), encoding="utf-8")
    ityfuzz_script_path.chmod(0o755)
    worker_receipt_path = _write_worker_receipt(
        package_dir=package_dir,
        bundle=bundle,
        hypothesis=hypothesis,
        artifact_path=artifact_path,
    )
    evidence_manifest_path = _write_evidence_manifest(
        package_dir=package_dir,
        bundle=bundle,
        hypothesis=hypothesis,
        files={
            "foundry_test": foundry_test_path,
            "hypothesis": hypothesis_path,
            "instructions": instructions_path,
            "ityfuzz_plan": ityfuzz_plan_path,
            "ityfuzz_script": ityfuzz_script_path,
            "worker_receipt": worker_receipt_path,
        },
    )

    foundry_path: str | None = str(foundry_test_path)
    if ValidationMethod.FOUNDRY_FORK not in hypothesis.validation_methods:
        foundry_path = None
    ityfuzz_plan: str | None = str(ityfuzz_plan_path)
    ityfuzz_script: str | None = str(ityfuzz_script_path)
    if ValidationMethod.ITYFUZZ not in hypothesis.validation_methods:
        ityfuzz_plan = None
        ityfuzz_script = None

    package = VerificationPackage(
        hypothesisId=hypothesis.id,
        artifactPath=str(artifact_path),
        packageDir=str(package_dir),
        validationMethods=hypothesis.validation_methods,
        foundryTestPath=foundry_path,
        ityfuzzPlanPath=ityfuzz_plan,
        ityfuzzScriptPath=ityfuzz_script,
        evidenceManifestPath=str(evidence_manifest_path),
        instructionsPath=str(instructions_path),
    )
    (package_dir / "verification_package.json").write_text(
        package.model_dump_json(by_alias=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return package
