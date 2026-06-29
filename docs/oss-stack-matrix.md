# OSS stack matrix

**Date**: 2026-05-18
**Status**: initial selection matrix

## Decision

There is no off-the-shelf OSS project for the entire closed-source EVM autoresearch pipeline. We take individual components and fix the contract between them via the artifact bundle, loop state, and verification package.

## Orchestration

- `karpathy/autoresearch`: take the short iterations, immutable eval harness, attempt log, stop conditions. Do not use as a security auditor directly.
- Ralph-like loop: take iteration/cost/time budgets, receipts, stuck triggers.
- `KeygraphHQ/shannon`: take phase contracts, queue-gated validation, no validated evidence -> no report.
- `cc-goal-stack`: take goal charter, disk-backed state, parent/worker split, completion audit. Use only after adapting to Pi.dev.
- Pi.dev: the target execution layer for the bounded parent/worker loop, tool calls, and verification worker.

## EVM input and recovery

- Dedaub: the primary decompiler for closed contracts.
- Heimdall: fallback for disassembly/CFG/decompiler output.
- EVMole: selector/interface inference; already in the project.
- WhatsABI: candidate for interface/proxy recovery.
- `storage-layout-extractor`: candidate for storage layout hints.
- `acuarica/evm`: candidate for bytecode analysis.
- `abi-decompiler`: candidate for ABI/selector recovery.

## Validation

- Foundry/Anvil: baseline pinned fork validator.
- ItyFuzz: bytecode-level exploit search after the Foundry baseline.
- Mythril/Manticore: bounded symbolic checks.
- Halmos: property/symbolic validation when harnessable.
- Echidna/Medusa: property fuzzing when invariant can be generated.

## Benchmark/evidence sources

- DeFiHackLabs: exploit transaction references and Foundry-style seeds.
- SmartBugs Curated: older labeled vulnerability classes.
- DeFiVulnLabs: DeFi-specific examples.
- SCONE-bench: optional benchmark task source if it maps cleanly to EVM workflow.
- Solodit/public reports: reference memory only, not validation oracle.

## Rejected as primary foundation

- Source-first LLM audit projects: useful patterns only; closed-source bytecode workflow differs.
- Prompt collections: not a durable asset.
- Single scalar score optimizers: unsuitable for sparse, high-cost security evidence.
- Fully autonomous disclosure: out of scope; manual approval only.
