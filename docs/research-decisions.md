# Research decisions: EVM closed-source autoresearch

**Date**: 2026-05-18
**Status**: working decisions after initial research
**Scope**: closed / unverified EVM contracts, BSC as the first chain

## Key decision

No off-the-shelf OSS solution was found that takes the decompiled bytecode of a closed EVM contract, runs a Ralph/Autoresearch-style loop, validates hypotheses on a fork, and produces an evidence-gated report.

This means the approach must be a composite stack:

- a custom orchestration loop;
- Dedaub as the primary decompiler;
- bytecode/disasm/storage fallback;
- Pi.dev-style bounded agents;
- Foundry/Anvil as the baseline validator;
- ItyFuzz and symbolic/property tools as a second layer;
- a benchmark corpus as the criterion for choosing models and tools.

## What we take from Autoresearch/Ralph/Shannon

`karpathy/autoresearch` is useful not as a ready-made security researcher, but as an operating model:

- short iterations;
- an immutable benchmark/eval harness;
- a narrow mutable surface;
- a log of attempts and reject reasons;
- stop conditions based on budget, stagnation, and result.

A Ralph-like loop is useful for managing the agent:

- iteration budget;
- cost/time budget;
- retry/stuck triggers;
- receipts after each iteration;
- explicit termination conditions.

The Shannon approach is useful as a security workflow:

- staged phases;
- artifact contract;
- queue-gated exploitation;
- no exploit / no validated evidence -> no report;
- checkpoint/resume;
- narrow roles instead of a large, unmanageable multi-agent organization.

The main adaptation: instead of a scalar metric, an evidence gate is needed. `keep` means validated evidence, `discard` means a rejected hypothesis with a reason.

The phase contract must be strict:

- the analysis phase writes only to the candidate queue;
- the validation phase reads the candidate queue and writes validation results;
- the report phase reads only validated evidence;
- rejected hypotheses remain in research memory with a reject reason;
- the final report does not see reasoning-only findings.

## What we take from `cc-goal-stack`

`cc-goal-stack` cannot be used as a drop-in. It should be adapted to Pi.dev and EVM auditing:

- a goal charter before starting work on a target;
- disk-backed state instead of holding everything in the context window;
- scratchpad sections `worked`, `failed`, `next`, `blocked`;
- a parent/worker split;
- bounded worker scope;
- a per-iteration receipt;
- a stuck trigger after repeated failures;
- a completion audit before disclosure.

In the EVM pipeline, the parent agent owns the target goal, budgets, model pair, hypothesis memory, and validator decisions. The worker receives one consensus hypothesis and assembles one verification package. The worker does not decide that a vulnerability is proven.

Specialist domains are better implemented as bounded goals rather than as persistent independent agents:

- auth and upgradeability;
- proxy, storage, and delegatecall;
- accounting, share math, and rounding;
- oracle, price, and liquidity;
- state machine and lifecycle;
- external calls, reentrancy, and callbacks.

## Bytecode/input layer

Dedaub remains the first decompilation layer, because the source case is closed and decompiled code is needed by the models as the primary material.

A fallback layer is mandatory, because the names and structure from the decompiler output are not facts:

- Heimdall-style disassembly, CFG, trace/calldata decoding;
- storage layout extraction;
- selector recovery;
- proxy/implementation resolution;
- bytecode hash / clone-family grouping;
- raw storage reads and storage diffs;
- recent tx/log/trace context where RPC allows it.

Candidates for the auxiliary layer:

- Heimdall for disassembly/CFG/decompiler fallback;
- `storage-layout-extractor` for layout hints;
- WhatsABI for interface/proxy recovery;
- `acuarica/evm` for bytecode analysis;
- `abi-decompiler` for ABI/selector recovery;
- EVMole-style selector/interface inference, if its quality on the corpus is confirmed.

A hypothesis must reference selectors, bytecode, storage, traces, or fork behavior, not only decompiled names.

## Validation stack

Adoption order:

1. Foundry/Anvil pinned fork test as a mandatory baseline.
2. ItyFuzz for bytecode-level exploit search.
3. Mythril/Manticore for bounded symbolic checks.
4. Halmos/Echidna/Medusa only when a property or harness can be generated.
5. Economic checks for profit after gas, liquidity, slippage, fee-on-transfer, rebase behavior, and oracle manipulation cost.

A reasoning-only finding must not reach an external report. High/critical findings require fork/fuzz/symbolic evidence.

## Network coverage

The pipeline must be EVM-first, not BSC-only.

BSC remains the first chain for implementation and benchmarking, because the following are relevant there:

- BEP20 quirks;
- Pancake liquidity;
- fee-on-transfer tokens;
- proxy-heavy contracts;
- weaker trace availability;
- old bytecode;
- a large number of clone families.

After BSC, it is logical to add Ethereum, Base, Arbitrum, Optimism, Polygon, Avalanche, Fantom, Gnosis, Linea, Scroll, and other EVM chains via chain adapters.

The current code baseline already covers chain adapters for Ethereum, BSC, Base, Polygon, and Arbitrum. The next EVM chains should be added with the same contract: chain id, RPC env var, explorer URL/API metadata, and native currency.

Non-EVM chains are not in the first scope. Aptos/Revela, Solana, TON, CosmWasm, and Cardano require a separate artifact model and a separate validator stack.

Solana/Aptos remain deferred roadmap items, not part of the current EVM plan. The old observation about Aptos as a “unique opportunity” is not rejected in substance, but deferred until a separate non-EVM artifact/validator design. The README line about Solana/additional chains should be treated as deferred, not as Phase 1/2 work.

## Discovery/value filters

There is no reliable universal API of the form “all contracts with total value > X” for all EVM chains.

A practical discovery layer must combine:

- RPC/snapshot ingestion;
- token/native balance scans;
- price feeds via DeFiLlama or an equivalent;
- Dune/BigQuery as initial snapshot/backfill sources;
- Bitquery/top-holder APIs for token-specific seed lists;
- Envio/Subsquid or a custom indexer later, if real-time scale is needed;
- DeFiLlama, Chainlink, and DEX liquidity checks for USD/value sanity;
- clone-family grouping by bytecode hash;
- labels/deployer/recent-tx signals.

The value score must be a heuristic, not absolute truth.

## Model decisions

You cannot choose the “best model for auditing” in advance without a benchmark corpus. The model matrix must measure:

- validated findings;
- false positives;
- cost per target;
- time per target;
- reproducibility;
- the ability to argue with another model rather than agree with it.

Roles:

- `Researcher`: a strong reasoning model, searches for attack hypotheses.
- `Skeptic`: a different model family, checks preconditions, access control, and impact.
- `goal_planner`: cheaper, selects bounded goals from the artifact bundle.
- `scout/summarizer`: cheap models, including an NVIDIA NIM/OpenAI-compatible backend, only for context and preliminary sorting.

Cheap/open models can be used for scout/summarizer, but not as a final judge until benchmark results are in.

From the old prompt notes we carry over only the process requirements, not the templates themselves:

- decomposition must be expressed as bounded goals and verification packages;
- self-consistency is replaced by a Researcher/Skeptic consensus gate and rejected-hypothesis memory;
- the critic phase is replaced by a validator/report gate, where a reasoning-only hypothesis does not become a finding;
- few-shot and inline RAG are allowed only as retrieved context/materials, if the benchmark shows they are useful;
- prompt text is not considered an asset and is not carried over without benchmark evidence of quality.

Autoresearch-style hill-climbing can be applied to infrastructure, but not directly to “finding criticals.”

Suitable mutable targets:

- detector heuristics;
- fuzzer seeds;
- symbolic execution configs;
- decompiler post-processing;
- agent policy;
- severity calibration.

## Explicitly rejected

- Do not carry over irrelevant autoresearch projects from other domains: that is not our class of task.
- Do not carry over old query-template notes as an asset: they are not strong enough and may entrench a mediocre process.
- Do not build a large multi-agent org before a reliable validator loop exists.
- Do not rely on decompiler names as facts.
- Do not treat worker self-assessment as proof.
- Do not use git commit/revert as the primary mechanism for each audit hypothesis.
- Do not publish the old repository history.

## Sources

- https://github.com/karpathy/autoresearch
- https://github.com/vercel-labs/ralph-loop-agent
- https://github.com/KeygraphHQ/shannon
- https://github.com/DefaultPerson/cc-goal-stack
- https://github.com/paradigmxyz/evmbench
- https://github.com/fuzzland/ityfuzz
- https://github.com/Jon-Becker/heimdall-rs
- https://github.com/duneanalytics/storage-layout-extractor
- https://github.com/acuarica/evm
- https://github.com/ConsenSysDiligence/mythril
- https://github.com/trailofbits/manticore
- https://github.com/a16z/halmos
- https://github.com/crytic/echidna
- https://github.com/crytic/medusa
