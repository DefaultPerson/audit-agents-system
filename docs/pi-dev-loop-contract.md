# Pi.dev loop contract

**Date**: 2026-05-18
**Status**: implementation contract

## Goal

Pi.dev must run not “free agents,” but a bounded loop with disk-backed state and verifiable artifacts.

## Inputs

- `artifact_bundle.json`;
- iteration budget;
- model pair;
- allowed tools;
- previous rejected hypotheses, if the target has already been run;
- validator policy.

## Parent responsibilities

- holds the target goal and budgets;
- selects bounded specialist goals;
- invokes `Researcher` and `Skeptic`;
- writes `loop_state.json`;
- does not write validation code;
- does not promote a finding without validator evidence.

## Worker responsibilities

- receives one consensus hypothesis;
- reads the artifact bundle;
- writes one verification package;
- runs the allowed validators;
- writes a receipt;
- does not send disclosure;
- does not declare a finding proven without a validator result.

## Tool surface

- read artifact bundle;
- selector lookup;
- decompiler slice search;
- raw storage read;
- storage diff around tx;
- recent tx/log/trace read;
- `cast call` on pinned block;
- token/native balance scanner;
- Foundry/Anvil runner;
- ItyFuzz runner;
- symbolic/property runner when configured.

## State layout

```text
audits/<chain>_<address>/
  artifacts/artifact_bundle.json
  artifacts/runtime_bytecode.hex
  artifacts/cheap_facts.json
  artifacts/cheap_tools/
    tool_manifest.json
    selector_lookup.json
    storage_read_plan.json
    trace_read_plan.json
    cast_call_plan.json
    storage_reads.json
    native_balances.json
    cast_calls.json
    recent_logs.json
  autoresearch/loop_state.json
  autoresearch/rejected_hypotheses.jsonl
  verification/<hypothesis_id>/
    hypothesis.json
    README.md
    <hypothesis_id>.t.sol
    ityfuzz_plan.md
    run_ityfuzz.sh
    evidence_manifest.json
    verification_package.json
    validation_results.json
  reports/
    internal_report.json
    internal_report.md
  disclosure/
    disclosure_draft.md
```

## Gates

- Hypothesis gate: selector/fallback path, preconditions, impact, validation method, cheap fact.
- Verification gate: fork/fuzz/symbolic/property evidence.
- Foundry gate: a passing test is insufficient unless validator output includes explicit evidence marker.
- Report gate: only validated evidence.
- Disclosure gate: manual approval only.

## Current implementation

The repository now has the first local scaffold for this contract:

- `audit-agents/src/autoresearch/`
- `audit-agents/src/stages/autoresearch.py`
- CLI command: `audit autoresearch <address> --chain <chain> --iterations <n>`
- Pinned block input: `audit autoresearch ... --block <number>`
- Two-model handoff: `audit propose-hypotheses artifacts/artifact_bundle.json` or inline `audit autoresearch ... --generate-hypotheses`
- External model handoff: `audit autoresearch ... --hypotheses-file hypotheses.json`
- Cheap tool contracts: `artifacts/cheap_tools/tool_manifest.json`
- Materialized cheap facts: `storage_reads.json`, `storage_diffs.json`, `native_balances.json`, `token_balances.json`, `cast_calls.json`, `recent_logs.json`, `recent_traces.json`, `rag_hits.json`; planned artifacts alone are not evidence.
- Rejected memory: `autoresearch/rejected_hypotheses.jsonl`
- Foundry validator scaffold guard: generated empty tests are marked `skipped`, not validated.
- ItyFuzz validator scaffold guard: generated wrappers are marked `skipped`, not validated.
- Economic/symbolic/property optional validators: package-local `economic_validator.sh`, `symbolic_validator.sh` and `property_validator.sh` run when present, but only exit 0 plus `VALIDATED_EVIDENCE: true` promotes evidence.
- Verification evidence manifest: `verification/<hypothesis_id>/evidence_manifest.json`.
- Internal report writer: `reports/internal_report.md` and `reports/internal_report.json`.
- Disclosure draft command: `audit disclosure draft reports/internal_report.json`; it writes `disclosure/disclosure_draft.md` near the audit target by default and never sends it.
- Clone-family grouping command: `audit discovery clone-families`; it groups discovered targets by identical `codeHash` for batch prioritization.

## External hypotheses file

Pi.dev or a two-model runner may write:

```json
{
  "hypotheses": [
    {
      "id": "hyp-001",
      "goalId": "goal-auth",
      "domain": "auth_upgradeability",
      "title": "Upgrade selector might be callable",
      "affectedSelectors": ["0x3659cfe6"],
      "preconditions": ["upgrade selector is reachable"],
      "expectedImpact": "Unauthorized upgrade if auth is bypassable.",
      "evidenceRefs": ["selector:0x3659cfe6"],
      "validationMethods": ["foundry_fork"]
    }
  ]
}
```

The pipeline still applies the consensus gate. Incomplete hypotheses are rejected
and retained in `loop_state.json`; only consensus hypotheses get verification
packages.

`audit propose-hypotheses` writes `autoresearch/model_handoff/hypotheses.json`
and `model_transcript.json`. The transcript is debug evidence for the handoff
only; validation still starts from the gated hypotheses file and fork/fuzz
packages.
