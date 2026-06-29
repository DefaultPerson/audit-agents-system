"""Tests for OpenAI-compatible model handoff."""

import json
from pathlib import Path

import httpx
import pytest

from src.autoresearch import (
    OpenAICompatibleConfig,
    build_artifact_bundle,
    extract_json_object,
    generate_model_hypotheses,
    parse_hypotheses_payload,
)
from src.models import Chain, ProxyType


def _bundle(tmp_path: Path):
    decompiled = tmp_path / "Contract.sol"
    decompiled.write_text(
        "contract Contract { function upgradeTo(address impl) external {} }\n",
        encoding="utf-8",
    )
    return build_artifact_bundle(
        chain=Chain.BSC,
        chain_id=56,
        target_address="0x742D35CC6634C0532925A3B844BC454E4438F44E",
        resolved_address="0x742D35CC6634C0532925A3B844BC454E4438F44E",
        bytecode_hex="0x6001600055",
        is_proxy=True,
        proxy_type=ProxyType.EIP1967,
        selectors=["0x3659cfe6"],
        snapshot_block=48123456,
        dedaub_file=decompiled,
    )


def test_extract_json_object_accepts_fenced_and_wrapped_json() -> None:
    assert extract_json_object("```json\n{\"hypotheses\": []}\n```") == {"hypotheses": []}
    assert extract_json_object("prefix {\"hypotheses\": []} suffix") == {"hypotheses": []}


def test_parse_hypotheses_payload_keeps_item_errors() -> None:
    hypotheses, errors = parse_hypotheses_payload(
        {
            "hypotheses": [
                {
                    "id": "hyp-001",
                    "goalId": "goal-auth",
                    "domain": "auth_upgradeability",
                    "title": "Upgrade selector might be callable",
                    "affectedSelectors": ["0x3659cfe6"],
                    "preconditions": ["selector is reachable"],
                    "expectedImpact": "Unauthorized upgrade if auth is bypassable.",
                    "evidenceRefs": ["selector:0x3659cfe6"],
                    "validationMethods": ["foundry_fork"],
                },
                {"id": "broken"},
            ]
        }
    )

    assert [hypothesis.id for hypothesis in hypotheses] == ["hyp-001"]
    assert errors and "hypotheses[1]" in errors[0]


@pytest.mark.asyncio
async def test_generate_model_hypotheses_writes_handoff_files(tmp_path: Path) -> None:
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(json.loads(request.content))
        content = {
            "hypotheses": [
                {
                    "id": "hyp-001",
                    "goalId": "goal-auth",
                    "domain": "auth_upgradeability",
                    "title": "Upgrade selector might be callable",
                    "affectedSelectors": ["0x3659cfe6"],
                    "preconditions": ["selector is reachable"],
                    "expectedImpact": "Unauthorized upgrade if auth is bypassable.",
                    "evidenceRefs": ["selector:0x3659cfe6"],
                    "validationMethods": ["foundry_fork"],
                }
            ]
        }
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(content)}}]},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await generate_model_hypotheses(
            bundle=_bundle(tmp_path),
            cheap_facts=["selector:0x3659cfe6", "proxy:true"],
            output_dir=tmp_path / "model_handoff",
            config=OpenAICompatibleConfig(
                base_url="https://models.example/v1",
                api_key="test-key",
                researcher_model="researcher",
                skeptic_model="skeptic",
            ),
            client=client,
        )

    assert [call["model"] for call in calls] == ["researcher", "skeptic"]
    assert result.hypotheses_path.exists()
    assert result.transcript_path.exists()
    hypotheses_file = json.loads(result.hypotheses_path.read_text(encoding="utf-8"))
    transcript = json.loads(result.transcript_path.read_text(encoding="utf-8"))
    assert hypotheses_file["hypotheses"][0]["id"] == "hyp-001"
    assert transcript["researcherModel"] == "researcher"
    assert transcript["skepticModel"] == "skeptic"
    assert transcript["cheapFactCount"] == 2
