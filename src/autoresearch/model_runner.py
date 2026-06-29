"""OpenAI-compatible two-model handoff for external hypothesis generation."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError

from .models import ArtifactBundle, AttackHypothesis, ValidationMethod


@dataclass(frozen=True)
class OpenAICompatibleConfig:
    """Config for any OpenAI-compatible chat completions endpoint."""

    base_url: str
    api_key: str | None
    researcher_model: str
    skeptic_model: str
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout_seconds: float = 120.0


@dataclass(frozen=True)
class ModelHandoffResult:
    """Files produced by the researcher/skeptic handoff."""

    hypotheses: list[AttackHypothesis]
    hypotheses_path: Path
    transcript_path: Path
    researcher_model: str
    skeptic_model: str


async def generate_model_hypotheses(
    *,
    bundle: ArtifactBundle,
    cheap_facts: list[str],
    output_dir: str | Path,
    config: OpenAICompatibleConfig,
    hypotheses_filename: str = "hypotheses.json",
    transcript_filename: str = "model_transcript.json",
    client: httpx.AsyncClient | None = None,
) -> ModelHandoffResult:
    """Run researcher then skeptic and write a gated hypotheses-file candidate."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    context = _build_model_context(bundle, cheap_facts)

    owns_client = client is None
    http_client = client or httpx.AsyncClient(timeout=config.timeout_seconds)
    try:
        researcher_text = await _chat_completion(
            http_client,
            config=config,
            model=config.researcher_model,
            messages=_researcher_messages(context),
        )
        researcher_payload = extract_json_object(researcher_text)
        researcher_hypotheses, researcher_errors = parse_hypotheses_payload(researcher_payload)

        skeptic_text = await _chat_completion(
            http_client,
            config=config,
            model=config.skeptic_model,
            messages=_skeptic_messages(context, researcher_hypotheses),
        )
        skeptic_payload = extract_json_object(skeptic_text)
        skeptic_hypotheses, skeptic_errors = parse_hypotheses_payload(skeptic_payload)
    finally:
        if owns_client:
            await http_client.aclose()

    hypotheses_path = out_dir / hypotheses_filename
    hypotheses_path.write_text(
        json.dumps(
            {
                "schemaVersion": "evm-autoresearch-hypotheses/v1",
                "hypotheses": [
                    hypothesis.model_dump(by_alias=True, mode="json")
                    for hypothesis in skeptic_hypotheses
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    transcript_path = out_dir / transcript_filename
    transcript_path.write_text(
        json.dumps(
            {
                "schemaVersion": "evm-model-handoff-transcript/v1",
                "createdAt": datetime.now(UTC).isoformat(),
                "targetAddress": bundle.target_address,
                "chain": bundle.chain.value,
                "snapshotBlock": bundle.snapshot_block,
                "researcherModel": config.researcher_model,
                "skepticModel": config.skeptic_model,
                "cheapFactCount": len(cheap_facts),
                "materialCount": len(context["materials"]),
                "researcher": {
                    "rawContent": researcher_text,
                    "acceptedHypotheses": len(researcher_hypotheses),
                    "validationErrors": researcher_errors,
                },
                "skeptic": {
                    "rawContent": skeptic_text,
                    "acceptedHypotheses": len(skeptic_hypotheses),
                    "validationErrors": skeptic_errors,
                },
                "outputHypothesesPath": str(hypotheses_path),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    return ModelHandoffResult(
        hypotheses=skeptic_hypotheses,
        hypotheses_path=hypotheses_path,
        transcript_path=transcript_path,
        researcher_model=config.researcher_model,
        skeptic_model=config.skeptic_model,
    )


def extract_json_object(text: str) -> dict[str, Any]:
    """Extract a JSON object from strict JSON, fenced JSON, or text-wrapped JSON."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("Model response did not contain a JSON object.") from None
        parsed = json.loads(stripped[start : end + 1])

    if not isinstance(parsed, dict):
        raise ValueError("Model response JSON must be an object.")
    return parsed


def parse_hypotheses_payload(payload: dict[str, Any]) -> tuple[list[AttackHypothesis], list[str]]:
    """Parse valid hypotheses and retain per-item validation errors for transcript."""
    raw_items = payload.get("hypotheses", [])
    if not isinstance(raw_items, list):
        return [], ["`hypotheses` must be a list."]

    hypotheses: list[AttackHypothesis] = []
    errors: list[str] = []
    for index, raw in enumerate(raw_items):
        try:
            hypotheses.append(AttackHypothesis.model_validate(raw))
        except ValidationError as exc:
            errors.append(f"hypotheses[{index}]: {exc.errors()}")
    return hypotheses, errors


async def _chat_completion(
    client: httpx.AsyncClient,
    *,
    config: OpenAICompatibleConfig,
    model: str,
    messages: list[dict[str, str]],
) -> str:
    headers = {"content-type": "application/json"}
    if config.api_key:
        headers["authorization"] = f"Bearer {config.api_key}"

    response = await client.post(
        f"{config.base_url.rstrip('/')}/chat/completions",
        headers=headers,
        json={
            "model": model,
            "messages": messages,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "response_format": {"type": "json_object"},
        },
    )
    response.raise_for_status()
    data = response.json()
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("Chat completion response is missing choices[0].message.content.") from exc
    if not isinstance(content, str):
        raise ValueError("Chat completion content must be a string.")
    return content


def _build_model_context(bundle: ArtifactBundle, cheap_facts: list[str]) -> dict[str, Any]:
    return {
        "artifactBundle": bundle.model_dump(by_alias=True, mode="json"),
        "cheapFacts": sorted(set(cheap_facts)),
        "allowedDomains": [
            "auth_upgradeability",
            "proxy_storage_delegatecall",
            "accounting_share_math",
            "oracle_price_liquidity",
            "state_machine_lifecycle",
            "external_calls_reentrancy",
        ],
        "allowedValidationMethods": [method.value for method in ValidationMethod],
        "materials": _read_material_snippets(bundle),
    }


def _read_material_snippets(
    bundle: ArtifactBundle,
    *,
    max_chars_per_file: int = 12_000,
    max_total_chars: int = 50_000,
) -> list[dict[str, str]]:
    snippets: list[dict[str, str]] = []
    remaining = max_total_chars
    for material in bundle.materials:
        if remaining <= 0:
            break
        path = Path(material.path)
        candidate_files = _material_candidate_files(path)
        for file_path in candidate_files:
            if remaining <= 0:
                break
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            snippet = text[: min(max_chars_per_file, remaining)]
            remaining -= len(snippet)
            snippets.append(
                {
                    "kind": material.kind,
                    "path": str(file_path),
                    "description": material.description or "",
                    "content": snippet,
                }
            )
    return snippets


def _material_candidate_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []

    candidates: list[Path] = []
    for pattern in ("*.sol", "*.json", "*.txt", "*.hex"):
        candidates.extend(sorted(file_path for file_path in path.rglob(pattern) if file_path.is_file()))
    return candidates[:8]


def _researcher_messages(context: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": (
                "You are a closed-source EVM security researcher. Propose only concrete "
                "attack hypotheses that cite provided cheapFacts. Do not claim a finding."
            ),
        },
        {
            "role": "user",
            "content": (
                "Return JSON object {\"hypotheses\": [...]} only. Each hypothesis must use "
                "fields id, goalId, domain, title, affectedSelectors, preconditions, "
                "expectedImpact, evidenceRefs, validationMethods. Propose at most 3.\n\n"
                + json.dumps(context, ensure_ascii=True)
            ),
        },
    ]


def _skeptic_messages(
    context: dict[str, Any],
    researcher_hypotheses: list[AttackHypothesis],
) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": (
                "You are a skeptical EVM audit reviewer. Keep only hypotheses that are "
                "specific, reproducible on a fork, and supported by provided cheapFacts."
            ),
        },
        {
            "role": "user",
            "content": (
                "Return JSON object {\"hypotheses\": [...]} only. Drop vague, uncited, "
                "duplicate, or non-actionable hypotheses. Do not add unsupported evidenceRefs.\n\n"
                + json.dumps(
                    {
                        "context": context,
                        "researcherHypotheses": [
                            hypothesis.model_dump(by_alias=True, mode="json")
                            for hypothesis in researcher_hypotheses
                        ],
                    },
                    ensure_ascii=True,
                )
            ),
        },
    ]
