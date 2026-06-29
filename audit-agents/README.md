# Audit Agents — reference implementation

Python 3.12 reference code for the autonomous closed-source EVM audit pipeline.
For the concept overview, the method diagram, and the live demo, see the
[repository README](../README.md).

> ⚠️ Research/educational concept. Ships with no credentials and no target lists; live
> discovery is **opt-in**. Use only on testnet or authorized targets. See
> [SECURITY.md](../SECURITY.md).

## Pipeline stages

| Stage | What it does |
|-------|--------------|
| **TRIAGE** | Filter contracts by balance, age, code size, verification status |
| **RESOLVE** | Detect proxy patterns (EIP-1167/1967/2535), resolve implementation, recover selectors |
| **DECOMPILE** | Bytecode → Solidity via Dedaub, with a bytecode/disassembly fallback |
| **AUTORESEARCH** | Artifact bundle → Researcher/Skeptic hypotheses → consensus gate → validators → evidence-gated internal report |
| **VALIDATE** | Foundry pinned-fork test → ItyFuzz → symbolic → economic checks |
| **REPORT / DISCLOSURE** | Markdown/JSON report; local-only, manually-approved disclosure package |

## Requirements

- Python 3.12+ and [uv](https://docs.astral.sh/uv/)
- Your own API keys (RPC, block-explorer, Voyage AI for RAG; optional Dedaub, Telegram, OpenAI-compatible models)
- External tools: [Foundry](https://getfoundry.sh/); optionally [ItyFuzz](https://github.com/fuzzland/ityfuzz)

## Quick start

```bash
uv sync                      # install dependencies
cp .env.example .env         # then fill in your own keys
uv run audit db init         # initialize the SQLite database

# Single-target, evidence-gated, offline-capable run:
uv run audit autoresearch 0x... --chain bsc --block 48123456 --iterations 8 --skip-dedaub

# Generate two-model Researcher/Skeptic hypotheses, then gate them deterministically:
uv run audit propose-hypotheses audits/bsc_0x.../artifacts/artifact_bundle.json
uv run audit autoresearch 0x... --chain bsc --hypotheses-file audits/bsc_0x.../autoresearch/model_handoff/hypotheses.json
```

Discovery is opt-in and defaults to a harmless `simulate` mode; live block-explorer
scanning must be requested explicitly and is for authorized/testnet use only.

## Testing

```bash
uv run pytest            # full suite
uv run pytest --cov=src  # with coverage
```

## Layout

```
audit-agents/
├── cli/main.py          # Typer CLI
├── src/
│   ├── autoresearch/    # artifact bundle, research loop, consensus gate, validators, report
│   ├── stages/          # triage, resolve, decompile, autoresearch, verify, report
│   ├── discovery/       # target discovery (opt-in) + chain adapters
│   ├── rag/             # exploit-corpus vector search (DeFiHackLabs)
│   ├── benchmark/       # corpus planning & scoring
│   ├── price/           # DeFiLlama price feeds
│   ├── disclosure.py    # local-only, manually-approved disclosure
│   ├── daemon.py        # queue processor
│   └── telegram_bot.py  # optional PoC-button notifications
├── prompts/             # anchored / open audit prompts
└── tests/               # pytest suite
```
