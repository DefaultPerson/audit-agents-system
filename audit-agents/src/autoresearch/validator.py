"""Validator runners for verification packages."""

import asyncio
import json
import os
import subprocess
import time
from pathlib import Path
from shutil import which

from .models import (
    ValidationMethod,
    ValidationResult,
    ValidationStatus,
    ValidatorKind,
    VerificationPackage,
)

SCAFFOLD_MARKERS = (
    "Replace this scaffold with concrete calls and assertions.",
    "Replace this scaffold with a concrete ItyFuzz invocation",
    "A passing empty test is not evidence.",
    "A passing empty fuzz run is not evidence.",
)
EVIDENCE_MARKER = "VALIDATED_EVIDENCE: true"


def _as_text(value: str | bytes | None) -> str:
    """Decode subprocess output values returned from normal and timeout paths."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _result(
    package: VerificationPackage,
    *,
    validator: ValidatorKind = ValidatorKind.FOUNDRY,
    status: ValidationStatus,
    reason: str,
    impact_demonstrated: bool = False,
    command: list[str] | None = None,
    output_path: str | None = None,
    duration_ms: int = 0,
) -> ValidationResult:
    return ValidationResult(
        hypothesisId=package.hypothesis_id,
        packageDir=package.package_dir,
        validator=validator,
        status=status,
        impactDemonstrated=impact_demonstrated,
        reason=reason,
        command=command or [],
        outputPath=output_path,
        durationMs=duration_ms,
    )


def _validator_for_method(method: ValidationMethod) -> ValidatorKind:
    return {
        ValidationMethod.FOUNDRY_FORK: ValidatorKind.FOUNDRY,
        ValidationMethod.ITYFUZZ: ValidatorKind.ITYFUZZ,
        ValidationMethod.SYMBOLIC: ValidatorKind.SYMBOLIC,
        ValidationMethod.PROPERTY: ValidatorKind.PROPERTY,
        ValidationMethod.ECONOMIC: ValidatorKind.ECONOMIC,
        ValidationMethod.MANUAL: ValidatorKind.ECONOMIC,
    }[method]


def _unsupported_result(package: VerificationPackage, method: ValidationMethod) -> ValidationResult:
    validator = _validator_for_method(method)
    reason = (
        "Manual validation requires reviewer action; no automated runner by design."
        if method == ValidationMethod.MANUAL
        else f"{validator.value} validator runner is not configured for this method."
    )
    return _result(
        package,
        validator=validator,
        status=ValidationStatus.SKIPPED,
        reason=reason,
    )


async def validate_package(
    package: VerificationPackage,
    *,
    cwd: str | Path,
    timeout_seconds: int = 300,
) -> list[ValidationResult]:
    """Run all requested validators for one verification package."""
    results: list[ValidationResult] = []
    for method in package.validation_methods:
        if method == ValidationMethod.FOUNDRY_FORK:
            results.append(
                await validate_foundry_package(
                    package,
                    cwd=cwd,
                    timeout_seconds=timeout_seconds,
                )
            )
            continue
        if method == ValidationMethod.ITYFUZZ:
            results.append(
                await validate_ityfuzz_package(
                    package,
                    cwd=cwd,
                    timeout_seconds=timeout_seconds,
                )
            )
            continue
        if method == ValidationMethod.ECONOMIC:
            results.append(validate_economic_package(package))
            continue
        if method == ValidationMethod.SYMBOLIC:
            results.append(validate_symbolic_package(package))
            continue
        if method == ValidationMethod.PROPERTY:
            results.append(validate_property_package(package))
            continue
        results.append(_unsupported_result(package, method))
    return results


def _write_plan_result(
    package: VerificationPackage,
    *,
    validator: ValidatorKind,
    filename: str,
    schema_version: str,
    required_checks: list[str],
    promotion_rule: str,
    reason: str,
) -> ValidationResult:
    output_path = Path(package.package_dir) / filename
    plan = {
        "schemaVersion": schema_version,
        "hypothesisId": package.hypothesis_id,
        "packageDir": package.package_dir,
        "status": "requirements_only",
        "requiredChecks": required_checks,
        "promotionRule": promotion_rule,
    }
    output_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    return _result(
        package,
        validator=validator,
        status=ValidationStatus.SKIPPED,
        reason=reason,
        output_path=str(output_path),
    )


def _run_external_validator_script(
    package: VerificationPackage,
    *,
    validator: ValidatorKind,
    script_name: str,
    output_name: str,
    timeout_seconds: int = 300,
) -> ValidationResult | None:
    """Run an optional package-local validator script behind the evidence gate."""
    package_dir = Path(package.package_dir)
    script_path = package_dir / script_name
    if not script_path.exists():
        return None

    output_path = package_dir / output_name
    command = ["bash", script_path.name]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=str(package_dir),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        return_code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        output = _as_text(exc.stdout) + _as_text(exc.stderr)
        output_path.write_text(output, encoding="utf-8")
        return _result(
            package,
            validator=validator,
            status=ValidationStatus.ERROR,
            reason=f"{validator.value} validator timed out after {timeout_seconds}s.",
            command=command,
            output_path=str(output_path),
            duration_ms=duration_ms,
        )

    duration_ms = int((time.monotonic() - started) * 1000)
    output_path.write_text(output, encoding="utf-8")

    if return_code != 0:
        return _result(
            package,
            validator=validator,
            status=ValidationStatus.FAILED,
            reason=f"{validator.value} validator script failed.",
            command=command,
            output_path=str(output_path),
            duration_ms=duration_ms,
        )

    if EVIDENCE_MARKER not in output:
        return _result(
            package,
            validator=validator,
            status=ValidationStatus.INCONCLUSIVE,
            reason=f"{validator.value} validator passed but did not emit validated evidence marker.",
            command=command,
            output_path=str(output_path),
            duration_ms=duration_ms,
        )

    return _result(
        package,
        validator=validator,
        status=ValidationStatus.VALIDATED,
        reason=f"{validator.value} validator passed and emitted validated evidence marker.",
        impact_demonstrated=True,
        command=command,
        output_path=str(output_path),
        duration_ms=duration_ms,
    )


def validate_economic_package(package: VerificationPackage) -> ValidationResult:
    """Run optional economic validator or write requirements without promoting weak evidence."""
    script_result = _run_external_validator_script(
        package,
        validator=ValidatorKind.ECONOMIC,
        script_name="economic_validator.sh",
        output_name="economic_validator_output.txt",
    )
    if script_result is not None:
        return script_result

    return _write_plan_result(
        package,
        validator=ValidatorKind.ECONOMIC,
        filename="economic_validation_plan.json",
        schema_version="evm-economic-validation-plan/v1",
        required_checks=[
            "profit_after_gas",
            "available_liquidity",
            "slippage_bounds",
            "fee_on_transfer_or_rebase_behavior",
            "oracle_manipulation_cost",
            "capital_and_flash_liquidity_constraints",
        ],
        promotion_rule=(
            "Do not mark validated until a fork/fuzz/symbolic reproducer demonstrates "
            "positive expected profit or concrete loss under pinned-chain state."
        ),
        reason="Economic validation requirements written; no profit evidence executed yet.",
    )


def validate_symbolic_package(package: VerificationPackage) -> ValidationResult:
    """Run optional symbolic validator or write requirements without promoting weak evidence."""
    script_result = _run_external_validator_script(
        package,
        validator=ValidatorKind.SYMBOLIC,
        script_name="symbolic_validator.sh",
        output_name="symbolic_validator_output.txt",
    )
    if script_result is not None:
        return script_result

    return _write_plan_result(
        package,
        validator=ValidatorKind.SYMBOLIC,
        filename="symbolic_validation_plan.json",
        schema_version="evm-symbolic-validation-plan/v1",
        required_checks=[
            "bounded_call_sequence",
            "path_constraints_for_preconditions",
            "storage_state_assumptions",
            "access_control_constraints",
            "concrete_counterexample_transaction_sequence",
        ],
        promotion_rule=(
            "Do not mark validated until Mythril/Manticore-style output includes a concrete "
            "counterexample that is replayed on a pinned fork or equivalent bytecode state."
        ),
        reason="Symbolic validation requirements written; no counterexample executed yet.",
    )


def validate_property_package(package: VerificationPackage) -> ValidationResult:
    """Run optional property validator or write requirements without promoting weak evidence."""
    script_result = _run_external_validator_script(
        package,
        validator=ValidatorKind.PROPERTY,
        script_name="property_validator.sh",
        output_name="property_validator_output.txt",
    )
    if script_result is not None:
        return script_result

    return _write_plan_result(
        package,
        validator=ValidatorKind.PROPERTY,
        filename="property_validation_plan.json",
        schema_version="evm-property-validation-plan/v1",
        required_checks=[
            "explicit_invariant_or_postcondition",
            "harness_preconditions",
            "stateful_sequence_bounds",
            "seed_corpus_or_replay_trace",
            "shrunk_counterexample",
        ],
        promotion_rule=(
            "Do not mark validated until Halmos/Echidna/Medusa-style output provides a "
            "counterexample with reproducible harness and pinned initial state."
        ),
        reason="Property validation requirements written; no invariant counterexample executed yet.",
    )


async def validate_ityfuzz_package(
    package: VerificationPackage,
    *,
    cwd: str | Path,
    timeout_seconds: int = 300,
) -> ValidationResult:
    """Run the package ItyFuzz wrapper without treating weak runs as evidence."""
    if not package.ityfuzz_script_path:
        return _result(
            package,
            validator=ValidatorKind.ITYFUZZ,
            status=ValidationStatus.SKIPPED,
            reason="No ItyFuzz wrapper path in verification package.",
        )

    script_path = Path(package.ityfuzz_script_path)
    if not script_path.exists():
        return _result(
            package,
            validator=ValidatorKind.ITYFUZZ,
            status=ValidationStatus.SKIPPED,
            reason="ItyFuzz wrapper script does not exist.",
        )

    script_code = script_path.read_text(encoding="utf-8")
    if any(marker in script_code for marker in SCAFFOLD_MARKERS):
        return _result(
            package,
            validator=ValidatorKind.ITYFUZZ,
            status=ValidationStatus.SKIPPED,
            reason="Generated ItyFuzz scaffold is not executable evidence.",
        )

    ityfuzz_bin = os.environ.get("ITYFUZZ_BIN", "ityfuzz")
    ityfuzz_path = which(ityfuzz_bin)
    if not ityfuzz_path:
        return _result(
            package,
            validator=ValidatorKind.ITYFUZZ,
            status=ValidationStatus.SKIPPED,
            reason=f"ItyFuzz binary not found: {ityfuzz_bin}.",
        )

    output_path = Path(package.package_dir) / "ityfuzz_output.txt"
    command = ["bash", str(script_path)]
    started = time.monotonic()

    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except TimeoutError:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        duration_ms = int((time.monotonic() - started) * 1000)
        return _result(
            package,
            validator=ValidatorKind.ITYFUZZ,
            status=ValidationStatus.ERROR,
            reason=f"ItyFuzz validation timed out after {timeout_seconds}s.",
            command=command,
            duration_ms=duration_ms,
        )

    duration_ms = int((time.monotonic() - started) * 1000)
    output = stdout.decode(errors="replace")
    output_path.write_text(output, encoding="utf-8")

    if proc.returncode != 0:
        return _result(
            package,
            validator=ValidatorKind.ITYFUZZ,
            status=ValidationStatus.FAILED,
            reason="ItyFuzz wrapper failed.",
            command=command,
            output_path=str(output_path),
            duration_ms=duration_ms,
        )

    if EVIDENCE_MARKER not in output:
        return _result(
            package,
            validator=ValidatorKind.ITYFUZZ,
            status=ValidationStatus.INCONCLUSIVE,
            reason="ItyFuzz wrapper passed but did not emit validated evidence marker.",
            command=command,
            output_path=str(output_path),
            duration_ms=duration_ms,
        )

    return _result(
        package,
        validator=ValidatorKind.ITYFUZZ,
        status=ValidationStatus.VALIDATED,
        reason="ItyFuzz wrapper passed and emitted validated evidence marker.",
        impact_demonstrated=True,
        command=command,
        output_path=str(output_path),
        duration_ms=duration_ms,
    )


async def validate_foundry_package(
    package: VerificationPackage,
    *,
    cwd: str | Path,
    timeout_seconds: int = 300,
) -> ValidationResult:
    """
    Run Foundry validation for one package.

    A passing test is considered validated only if the output contains
    `VALIDATED_EVIDENCE: true`. This prevents scaffold or weak PoCs from being
    promoted to findings.
    """
    if not package.foundry_test_path:
        return _result(
            package,
            status=ValidationStatus.SKIPPED,
            reason="No Foundry test path in verification package.",
        )

    test_path = Path(package.foundry_test_path)
    if not test_path.exists():
        return _result(
            package,
            status=ValidationStatus.SKIPPED,
            reason="Foundry test file does not exist.",
        )

    test_code = test_path.read_text(encoding="utf-8")
    if any(marker in test_code for marker in SCAFFOLD_MARKERS):
        return _result(
            package,
            status=ValidationStatus.SKIPPED,
            reason="Generated scaffold is not executable evidence.",
        )

    forge_path = which("forge")
    if not forge_path:
        return _result(
            package,
            status=ValidationStatus.SKIPPED,
            reason="Foundry forge binary not found.",
        )

    output_path = Path(package.package_dir) / "foundry_output.txt"
    command = [forge_path, "test", "--match-path", str(test_path), "-vvv"]
    started = time.monotonic()

    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except TimeoutError:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        duration_ms = int((time.monotonic() - started) * 1000)
        return _result(
            package,
            status=ValidationStatus.ERROR,
            reason=f"Foundry validation timed out after {timeout_seconds}s.",
            command=command,
            duration_ms=duration_ms,
        )

    duration_ms = int((time.monotonic() - started) * 1000)
    output = stdout.decode(errors="replace")
    output_path.write_text(output, encoding="utf-8")

    if proc.returncode != 0:
        return _result(
            package,
            status=ValidationStatus.FAILED,
            reason="Foundry test failed.",
            command=command,
            output_path=str(output_path),
            duration_ms=duration_ms,
        )

    if EVIDENCE_MARKER not in output:
        return _result(
            package,
            status=ValidationStatus.INCONCLUSIVE,
            reason="Foundry test passed but did not emit validated evidence marker.",
            command=command,
            output_path=str(output_path),
            duration_ms=duration_ms,
        )

    return _result(
        package,
        status=ValidationStatus.VALIDATED,
        reason="Foundry test passed and emitted validated evidence marker.",
        impact_demonstrated=True,
        command=command,
        output_path=str(output_path),
        duration_ms=duration_ms,
    )
