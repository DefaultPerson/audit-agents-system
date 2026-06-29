"""Tests for manual disclosure draft generation."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.disclosure import (
    DisclosureSeverity,
    DisclosureStatus,
    approve_contact_state,
    build_disclosure_draft,
    load_contact_state,
    load_internal_report,
    lookup_owner_candidates,
    write_disclosure_draft,
    write_owner_lookup,
    write_reproduction_package,
)


def _write_report(
    path: Path,
    *,
    validated: bool,
    package_dir: str = "verification/hyp",
    output_path: str | None = None,
) -> Path:
    validation_result = {
        "hypothesisId": "hyp-1",
        "packageDir": package_dir,
        "validator": "foundry",
        "status": "validated" if validated else "skipped",
        "impactDemonstrated": validated,
        "reason": "test reason",
        "command": [],
        "durationMs": 0,
        "createdAt": "2026-05-18T00:00:00Z",
    }
    if output_path:
        validation_result["outputPath"] = output_path

    path.write_text(
        json.dumps(
            {
                "targetAddress": "0x0000000000000000000000000000000000000001",
                "chain": "eth",
                "artifactPath": "artifact.json",
                "statePath": "loop_state.json",
                "consensusCount": 1,
                "rejectedCount": 0,
                "verificationPackages": ["verification/hyp"],
                "validationResults": [validation_result],
                "validatedFindingsCount": 1 if validated else 0,
                "disclosureAllowed": False,
                "createdAt": "2026-05-18T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_verification_package(root: Path) -> Path:
    package_dir = root / "verification" / "hyp"
    package_dir.mkdir(parents=True)
    (package_dir / "evidence_manifest.json").write_text('{"evidence":[]}\n', encoding="utf-8")
    (package_dir / "instructions.md").write_text("# Instructions\n", encoding="utf-8")
    return package_dir


def test_build_disclosure_draft_requires_validated_evidence(tmp_path: Path) -> None:
    report = load_internal_report(_write_report(tmp_path / "report.json", validated=False))

    with pytest.raises(ValueError, match="validated finding"):
        build_disclosure_draft(report)


def test_write_disclosure_draft(tmp_path: Path) -> None:
    report_path = _write_report(tmp_path / "report.json", validated=True)

    draft_path = write_disclosure_draft(report_path, tmp_path / "out")

    assert draft_path.exists()
    draft = draft_path.read_text()
    assert "Do not send without human approval" in draft
    assert "hyp-1" in draft


def test_write_reproduction_package_requires_validated_evidence(tmp_path: Path) -> None:
    report_path = _write_report(tmp_path / "report.json", validated=False)

    with pytest.raises(ValueError, match="validated finding"):
        write_reproduction_package(report_path, tmp_path / "out")


def test_write_reproduction_package_requires_existing_verification_package(tmp_path: Path) -> None:
    report_path = _write_report(tmp_path / "report.json", validated=True)

    with pytest.raises(ValueError, match="existing verification package"):
        write_reproduction_package(report_path, tmp_path / "out")


def test_write_reproduction_package_copies_validated_evidence(tmp_path: Path) -> None:
    _write_verification_package(tmp_path)
    output_file = tmp_path / "validation-output.txt"
    output_file.write_text("VALIDATED_EVIDENCE: true\n", encoding="utf-8")
    report_path = _write_report(
        tmp_path / "report.json",
        validated=True,
        output_path="validation-output.txt",
    )

    package_dir, manifest, state = write_reproduction_package(
        report_path,
        tmp_path / "out",
        owner_contact="security@example.test",
        owner_lookup_notes="manual lookup",
    )

    assert package_dir.exists()
    assert manifest.validated_hypothesis_ids == ["hyp-1"]
    assert "internal_report.json" in manifest.copied_files
    assert "disclosure_draft.md" in manifest.copied_files
    assert "README.md" in manifest.copied_files
    assert any(path.endswith("evidence_manifest.json") for path in manifest.copied_files)
    assert any(path.endswith("validation-output.txt") for path in manifest.copied_files)
    assert state.status == DisclosureStatus.PACKAGE_READY
    assert state.owner_contact == "security@example.test"

    saved_state = load_contact_state(package_dir / "contact_state.json")
    assert saved_state.status == DisclosureStatus.PACKAGE_READY
    assert saved_state.owner_lookup_notes == "manual lookup"


@pytest.mark.asyncio
async def test_lookup_owner_candidates_reads_selectors_and_admin_slot() -> None:
    owner = bytes.fromhex("00" * 12 + "11" * 20)
    admin = bytes.fromhex("00" * 12 + "22" * 20)
    mock_w3 = MagicMock()
    mock_w3.to_checksum_address.side_effect = lambda value: value
    mock_w3.eth.call = AsyncMock(side_effect=[owner, b"\x00" * 32, Exception("revert")])
    mock_w3.eth.get_storage_at = AsyncMock(return_value=admin)

    with patch("src.disclosure.AsyncWeb3") as mock_web3:
        mock_web3.AsyncHTTPProvider.return_value = object()
        mock_web3.return_value = mock_w3

        result = await lookup_owner_candidates(
            address="0x0000000000000000000000000000000000000001",
            chain="eth",
            rpc_url="https://rpc.invalid",
            snapshot_block=123,
        )

    assert [candidate.source for candidate in result.candidates] == ["owner()", "eip1967.admin"]
    assert result.candidates[0].address == "0x" + "11" * 20
    assert result.candidates[1].confidence == "high"
    assert result.snapshot_block == 123
    assert result.errors == ["admin(): revert"]


@pytest.mark.asyncio
async def test_write_owner_lookup_updates_contact_state(tmp_path: Path) -> None:
    _write_verification_package(tmp_path)
    report_path = _write_report(tmp_path / "report.json", validated=True)
    package_dir, _manifest, _state = write_reproduction_package(report_path, tmp_path / "out")
    state_path = package_dir / "contact_state.json"
    mock_w3 = MagicMock()
    mock_w3.to_checksum_address.side_effect = lambda value: value
    mock_w3.eth.call = AsyncMock(return_value=b"\x00" * 32)
    mock_w3.eth.get_storage_at = AsyncMock(return_value=bytes.fromhex("00" * 12 + "33" * 20))

    with patch("src.disclosure.AsyncWeb3") as mock_web3:
        mock_web3.AsyncHTTPProvider.return_value = object()
        mock_web3.return_value = mock_w3

        path, result = await write_owner_lookup(
            report_path,
            tmp_path / "out",
            rpc_url="https://rpc.invalid",
            state_path=state_path,
        )

    assert path.exists()
    assert result.candidates[0].address == "0x" + "33" * 20
    state = load_contact_state(state_path)
    assert state.owner_lookup_path == str(path)
    assert state.owner_lookup_notes == "1 owner/admin candidates; 0 lookup errors. Manual verification required."


def test_approve_contact_state_records_manual_approval(tmp_path: Path) -> None:
    _write_verification_package(tmp_path)
    report_path = _write_report(tmp_path / "report.json", validated=True)
    package_dir, _manifest, _state = write_reproduction_package(report_path, tmp_path / "out")
    state_path = package_dir / "contact_state.json"
    owner_lookup_path = package_dir / "owner_lookup.json"
    owner_lookup_path.write_text('{"candidates":[]}\n', encoding="utf-8")

    state = approve_contact_state(
        state_path,
        approved_by="reviewer",
        finding_severity=DisclosureSeverity.HIGH,
        owner_contact="security@example.test",
        owner_lookup_path=str(owner_lookup_path),
        notes="approved for manual contact",
    )

    assert state.status == DisclosureStatus.APPROVED
    assert state.finding_severity == DisclosureSeverity.HIGH
    assert state.approved_by == "reviewer"
    assert state.owner_contact == "security@example.test"
    assert state.owner_lookup_path == str(owner_lookup_path)
    assert state.notes == "approved for manual contact"
    saved_state = load_contact_state(state_path)
    assert saved_state.status == DisclosureStatus.APPROVED
    assert saved_state.finding_severity == DisclosureSeverity.HIGH


def test_approve_contact_state_requires_high_or_critical_severity(tmp_path: Path) -> None:
    _write_verification_package(tmp_path)
    report_path = _write_report(tmp_path / "report.json", validated=True)
    package_dir, _manifest, _state = write_reproduction_package(report_path, tmp_path / "out")

    with pytest.raises(ValueError, match="finding severity high or critical"):
        approve_contact_state(package_dir / "contact_state.json", approved_by="reviewer")

    with pytest.raises(ValueError, match="limited to high/critical"):
        approve_contact_state(
            package_dir / "contact_state.json",
            approved_by="reviewer",
            finding_severity="medium",
        )


def test_approve_contact_state_requires_complete_package(tmp_path: Path) -> None:
    _write_verification_package(tmp_path)
    report_path = _write_report(tmp_path / "report.json", validated=True)
    package_dir, _manifest, _state = write_reproduction_package(report_path, tmp_path / "out")
    (package_dir / "manifest.json").unlink()

    with pytest.raises(ValueError, match="complete local evidence"):
        approve_contact_state(
            package_dir / "contact_state.json",
            approved_by="reviewer",
            finding_severity=DisclosureSeverity.HIGH,
        )
