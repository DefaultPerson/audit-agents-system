"""Manual disclosure workflow helpers.

This module never sends messages. It only creates local drafts, reproduction
packages and approval state when validated evidence exists.
"""

import json
import shutil
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, Field
from web3 import AsyncWeb3

from .autoresearch import AutoresearchInternalReport, ValidationResult, ValidationStatus

OWNER_SELECTORS = {
    "owner()": "0x8da5cb5b",
    "getOwner()": "0x893d20e8",
    "admin()": "0xf851a440",
}
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"


class DisclosureStatus(str, Enum):
    """Manual disclosure lifecycle state."""

    DRAFT = "draft"
    PACKAGE_READY = "package_ready"
    APPROVED = "approved"
    REJECTED = "rejected"
    SENT_RECORDED = "sent_recorded"


class DisclosureSeverity(str, Enum):
    """Severity levels eligible for manual owner contact approval."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DisclosurePackageManifest(BaseModel):
    """Machine-readable reproduction package manifest."""

    schema_version: str = Field(default="evm-disclosure-package/v1", alias="schemaVersion")
    target_address: str = Field(alias="targetAddress")
    chain: str
    snapshot_block: int | None = Field(default=None, alias="snapshotBlock")
    report_path: str = Field(alias="reportPath")
    validated_hypothesis_ids: list[str] = Field(alias="validatedHypothesisIds")
    copied_files: list[str] = Field(default_factory=list, alias="copiedFiles")
    manual_approval_required: bool = Field(default=True, alias="manualApprovalRequired")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}


class DisclosureContactState(BaseModel):
    """Local-only owner/contact tracking state."""

    schema_version: str = Field(default="evm-disclosure-contact-state/v1", alias="schemaVersion")
    target_address: str = Field(alias="targetAddress")
    chain: str
    report_path: str = Field(alias="reportPath")
    package_dir: str = Field(alias="packageDir")
    status: DisclosureStatus = DisclosureStatus.DRAFT
    owner_contact: str | None = Field(default=None, alias="ownerContact")
    owner_lookup_notes: str | None = Field(default=None, alias="ownerLookupNotes")
    owner_lookup_path: str | None = Field(default=None, alias="ownerLookupPath")
    finding_severity: DisclosureSeverity | None = Field(default=None, alias="findingSeverity")
    approved_by: str | None = Field(default=None, alias="approvedBy")
    approved_at: datetime | None = Field(default=None, alias="approvedAt")
    notes: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="updatedAt")

    model_config = {"populate_by_name": True}


class OwnerLookupCandidate(BaseModel):
    """One read-only owner/admin candidate."""

    source: str
    address: str
    evidence_ref: str = Field(alias="evidenceRef")
    confidence: str

    model_config = {"populate_by_name": True}


class OwnerLookupResult(BaseModel):
    """Local owner lookup result for manual disclosure routing."""

    schema_version: str = Field(default="evm-owner-lookup/v1", alias="schemaVersion")
    target_address: str = Field(alias="targetAddress")
    chain: str
    snapshot_block: int | None = Field(default=None, alias="snapshotBlock")
    candidates: list[OwnerLookupCandidate] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), alias="createdAt")

    model_config = {"populate_by_name": True}


def load_internal_report(path: str | Path) -> AutoresearchInternalReport:
    """Load an autoresearch internal report."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return AutoresearchInternalReport.model_validate(data)


def _validated_results(report: AutoresearchInternalReport) -> list[ValidationResult]:
    return [
        result
        for result in report.validation_results
        if result.status == ValidationStatus.VALIDATED and result.impact_demonstrated
    ]


def build_disclosure_draft(report: AutoresearchInternalReport) -> str:
    """Build a manual disclosure draft from validated evidence."""
    validated = _validated_results(report)
    if not validated:
        raise ValueError("Disclosure draft requires at least one validated finding.")

    evidence_lines = "\n".join(
        f"- `{result.hypothesis_id}` via `{result.validator.value}`: {result.reason}"
        for result in validated
    )

    return f"""# Manual Disclosure Draft

Do not send without human approval.

## Target

- Chain: `{report.chain.value}`
- Contract: `{report.target_address}`
- Artifact: `{report.artifact_path}`
- Internal report state: `{report.state_path}`

## Validated Evidence

{evidence_lines}

## Required Manual Review

- Confirm affected contract owner/contact.
- Confirm snapshot block and current exploitability.
- Confirm legal/bug-bounty disclosure route.
- Attach minimal reproduction package.
- Remove internal notes that are not needed by the owner.
"""


def write_disclosure_draft(report_path: str | Path, output_dir: str | Path) -> Path:
    """Write a local manual disclosure draft."""
    report = load_internal_report(report_path)
    draft = build_disclosure_draft(report)
    path = Path(output_dir) / "disclosure_draft.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(draft, encoding="utf-8")
    return path


def _bytes_from_rpc_value(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        raw = value.removeprefix("0x")
        return bytes.fromhex(raw) if raw else b""
    if hasattr(value, "hex"):
        raw = value.hex()
        if isinstance(raw, str):
            return bytes.fromhex(raw.removeprefix("0x"))
    return b""


def _address_from_word(value: Any) -> str | None:
    data = _bytes_from_rpc_value(value)
    if len(data) < 20:
        return None
    address = "0x" + data[-20:].hex()
    if address == "0x" + "00" * 20:
        return None
    return address


async def _close_web3_provider(w3: AsyncWeb3) -> None:
    provider = getattr(w3, "provider", None)
    close = getattr(provider, "disconnect", None) or getattr(provider, "close", None)
    if close is None:
        return
    result = close()
    if hasattr(result, "__await__"):
        await result


async def lookup_owner_candidates(
    *,
    address: str,
    chain: str,
    rpc_url: str,
    snapshot_block: int | None = None,
) -> OwnerLookupResult:
    """Read common owner/admin surfaces from a pinned block."""
    w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(rpc_url))
    block_identifier: int | str = snapshot_block if snapshot_block is not None else "latest"
    result = OwnerLookupResult(
        targetAddress=address.lower(),
        chain=chain,
        snapshotBlock=snapshot_block,
    )
    seen: set[tuple[str, str]] = set()

    try:
        checksum = w3.to_checksum_address(address)
        for signature, selector in OWNER_SELECTORS.items():
            try:
                raw = await w3.eth.call(
                    cast(Any, {"to": checksum, "data": selector}),
                    block_identifier,
                )
                candidate = _address_from_word(raw)
            except Exception as exc:
                result.errors.append(f"{signature}: {exc}")
                continue
            if candidate is None:
                continue
            key = (signature, candidate)
            if key in seen:
                continue
            seen.add(key)
            result.candidates.append(
                OwnerLookupCandidate(
                    source=signature,
                    address=candidate,
                    evidenceRef=f"owner_call:{selector}",
                    confidence="medium",
                )
            )

        try:
            raw_admin = await w3.eth.get_storage_at(checksum, int(EIP1967_ADMIN_SLOT, 16), block_identifier)
            candidate = _address_from_word(raw_admin)
        except Exception as exc:
            result.errors.append(f"eip1967.admin: {exc}")
        else:
            if candidate is not None:
                key = ("eip1967.admin", candidate)
                if key not in seen:
                    result.candidates.append(
                        OwnerLookupCandidate(
                            source="eip1967.admin",
                            address=candidate,
                            evidenceRef="storage:eip1967.admin",
                            confidence="high",
                        )
                    )
    finally:
        await _close_web3_provider(w3)

    return result


async def write_owner_lookup(
    report_path: str | Path,
    output_dir: str | Path,
    *,
    rpc_url: str | None = None,
    state_path: str | Path | None = None,
) -> tuple[Path, OwnerLookupResult]:
    """Write local owner lookup artifact and optionally link contact state."""
    from .config import get_chain_config

    report = load_internal_report(report_path)
    target_rpc_url = rpc_url or get_chain_config(report.chain.value).rpc_url
    result = await lookup_owner_candidates(
        address=report.target_address,
        chain=report.chain.value,
        rpc_url=target_rpc_url,
        snapshot_block=report.snapshot_block,
    )
    path = Path(output_dir) / "owner_lookup.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(by_alias=True, indent=2) + "\n", encoding="utf-8")

    if state_path is not None:
        state = load_contact_state(state_path)
        state.owner_lookup_path = str(path)
        state.owner_lookup_notes = (
            f"{len(result.candidates)} owner/admin candidates; "
            f"{len(result.errors)} lookup errors. Manual verification required."
        )
        state.updated_at = datetime.now(UTC)
        write_contact_state(state, state_path)

    return path, result


def _resolve_existing_path(raw_path: str | Path, report_path: Path) -> Path | None:
    path = Path(raw_path)
    candidates = [path] if path.is_absolute() else [
        report_path.parent / path,
        report_path.parent.parent / path,
        Path.cwd() / path,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def _copy_file_once(source: Path, package_dir: Path, copied: set[Path]) -> str:
    source = source.resolve()
    if source in copied:
        return str(source)
    copied.add(source)
    destination = package_dir / "evidence" / source.name
    suffix = 1
    while destination.exists():
        destination = package_dir / "evidence" / f"{source.stem}-{suffix}{source.suffix}"
        suffix += 1
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return str(destination.relative_to(package_dir))


def write_reproduction_package(
    report_path: str | Path,
    output_dir: str | Path,
    *,
    owner_contact: str | None = None,
    owner_lookup_notes: str | None = None,
    owner_lookup_path: str | None = None,
) -> tuple[Path, DisclosurePackageManifest, DisclosureContactState]:
    """Write a local reproduction package and draft contact state."""
    resolved_report_path = Path(report_path)
    report = load_internal_report(resolved_report_path)
    validated = _validated_results(report)
    if not validated:
        raise ValueError("Reproduction package requires at least one validated finding.")

    package_dir = Path(output_dir) / "reproduction_package"
    package_dir.mkdir(parents=True, exist_ok=True)
    copied: set[Path] = set()
    copied_files: list[str] = []

    report_copy = package_dir / "internal_report.json"
    report_copy.write_text(
        json.dumps(report.model_dump(by_alias=True, mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    copied_files.append(str(report_copy.relative_to(package_dir)))

    draft_path = package_dir / "disclosure_draft.md"
    draft_path.write_text(build_disclosure_draft(report), encoding="utf-8")
    copied_files.append(str(draft_path.relative_to(package_dir)))

    readme_path = package_dir / "README.md"
    readme_path.write_text(
        "# Reproduction Package\n\n"
        "This package is local-only evidence for manual review. It does not "
        "send or publish a disclosure.\n\n"
        "Review `manifest.json`, `internal_report.json` and copied evidence "
        "before contacting any owner.\n",
        encoding="utf-8",
    )
    copied_files.append(str(readme_path.relative_to(package_dir)))

    for result in validated:
        package_path = _resolve_existing_path(result.package_dir, resolved_report_path)
        if not package_path or not package_path.is_dir():
            raise ValueError(
                "Reproduction package requires existing verification package "
                f"for validated finding {result.hypothesis_id}: {result.package_dir}"
            )

        if result.output_path:
            source = _resolve_existing_path(result.output_path, resolved_report_path)
            if source and source.is_file():
                copied_files.append(_copy_file_once(source, package_dir, copied))

        for filename in ("evidence_manifest.json", "instructions.md", "README.md"):
            source = package_path / filename
            if source.is_file():
                copied_files.append(_copy_file_once(source, package_dir, copied))

    manifest = DisclosurePackageManifest(
        targetAddress=report.target_address,
        chain=report.chain.value,
        snapshotBlock=report.snapshot_block,
        reportPath=str(resolved_report_path),
        validatedHypothesisIds=sorted({result.hypothesis_id for result in validated}),
        copiedFiles=sorted(set(copied_files)),
    )
    manifest_path = package_dir / "manifest.json"
    manifest_path.write_text(
        manifest.model_dump_json(by_alias=True, indent=2) + "\n",
        encoding="utf-8",
    )

    state = DisclosureContactState(
        targetAddress=report.target_address,
        chain=report.chain.value,
        reportPath=str(resolved_report_path),
        packageDir=str(package_dir),
        status=DisclosureStatus.PACKAGE_READY,
        ownerContact=owner_contact,
        ownerLookupNotes=owner_lookup_notes,
        ownerLookupPath=owner_lookup_path,
    )
    write_contact_state(state, package_dir / "contact_state.json")
    return package_dir, manifest, state


def load_contact_state(path: str | Path) -> DisclosureContactState:
    """Load local disclosure contact state."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return DisclosureContactState.model_validate(data)


def write_contact_state(state: DisclosureContactState, path: str | Path) -> Path:
    """Persist local disclosure contact state."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        state.model_dump_json(by_alias=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return output_path


def _assert_approval_evidence_complete(state: DisclosureContactState) -> None:
    package_dir = Path(state.package_dir)
    required_files = [
        package_dir / "manifest.json",
        package_dir / "internal_report.json",
        package_dir / "disclosure_draft.md",
    ]
    missing = [str(path) for path in required_files if not path.is_file()]
    if state.owner_lookup_path and not Path(state.owner_lookup_path).is_file():
        missing.append(state.owner_lookup_path)
    if missing:
        raise ValueError("Manual approval requires complete local evidence: " + ", ".join(missing))


def _normalize_approval_severity(finding_severity: DisclosureSeverity | str | None) -> DisclosureSeverity:
    if finding_severity is None:
        raise ValueError("Manual approval requires finding severity high or critical.")
    if isinstance(finding_severity, DisclosureSeverity):
        severity = finding_severity
    else:
        try:
            severity = DisclosureSeverity(finding_severity.lower())
        except ValueError as exc:
            allowed = ", ".join(level.value for level in DisclosureSeverity)
            raise ValueError(f"Unknown finding severity '{finding_severity}'. Expected one of: {allowed}") from exc
    if severity not in {DisclosureSeverity.CRITICAL, DisclosureSeverity.HIGH}:
        raise ValueError("Owner contact approval is limited to high/critical findings.")
    return severity


def approve_contact_state(
    state_path: str | Path,
    *,
    approved_by: str,
    finding_severity: DisclosureSeverity | str | None = None,
    owner_contact: str | None = None,
    owner_lookup_notes: str | None = None,
    owner_lookup_path: str | None = None,
    notes: str | None = None,
) -> DisclosureContactState:
    """Mark a local disclosure package as manually approved.

    Approval is only state tracking; it never sends a message.
    """
    state = load_contact_state(state_path)
    if owner_lookup_path is not None:
        state.owner_lookup_path = owner_lookup_path
    _assert_approval_evidence_complete(state)
    state.finding_severity = _normalize_approval_severity(finding_severity)
    state.status = DisclosureStatus.APPROVED
    state.approved_by = approved_by
    state.approved_at = datetime.now(UTC)
    state.updated_at = state.approved_at
    if owner_contact is not None:
        state.owner_contact = owner_contact
    if owner_lookup_notes is not None:
        state.owner_lookup_notes = owner_lookup_notes
    if notes is not None:
        state.notes = notes
    write_contact_state(state, state_path)
    return state
