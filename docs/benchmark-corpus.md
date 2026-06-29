# Benchmark corpus: EVM closed-source audit loop

**Date**: 2026-05-18
**Status**: initial candidate list

Machine-readable seed corpus: `docs/benchmark-corpus.json`.

## Goal

A benchmark corpus is needed not for a pretty report, but for choosing models, the tool surface, and the validator stack based on facts.

Each case must be fixed as an immutable bundle:

- chain id;
- target address;
- implementation address, if there is a proxy;
- pinned block before exploit or benign snapshot block;
- bytecode hash;
- decompiler outputs;
- storage/selector/trace context;
- expected vulnerability class or expected benign outcome;
- validation oracle: which fork/fuzz/symbolic/property result counts as success.

Seed datasets:

- DeFiHackLabs for reproducible exploit transactions and Foundry-style references;
- SmartBugs Curated for older but labeled vulnerability classes;
- DeFiVulnLabs for DeFi-specific patterns;
- SCONE-bench as an additional source of benchmark tasks, if the format fits the EVM workflow;
- Solodit/public audit reports only as reference memory, not as a validation oracle.

## Metrics

- validated findings;
- false positives;
- false negatives on known exploited contracts;
- cost per target;
- time per target;
- number of rejected hypotheses;
- reproducibility from clean state;
- quality of evidence package.

## Candidates with known exploit cases

The exact addresses and blocks must be confirmed before running the benchmark. This list fixes categories, not the final dataset.

- PancakeBunny, BSC: price/oracle manipulation.
- Uranium Finance, BSC: AMM invariant / pool math issue.
- Belt Finance, BSC: strategy/accounting manipulation.
- Cream Finance, Ethereum/BSC cases: lending/accounting and oracle-related classes.
- bZx, Ethereum: oracle / flash-loan driven exploit class.
- Harvest Finance, Ethereum: Curve/price manipulation class.
- Nomad bridge, Ethereum: message verification / initialization failure class.
- Poly Network, multi-chain EVM side: privileged verification / cross-chain control logic.
- Euler Finance, Ethereum: lending invariant / donation/liquidation path.
- Curve/Vyper reentrancy incident, Ethereum: compiler/runtime interaction and reentrancy class.

## Benign false-positive traps

Needed so that models do not turn every odd branch of decompiled code into a finding.

- verified OpenZeppelin proxy/token with normal admin controls;
- fee-on-transfer token without an exploitable drain;
- rebasing token with expected balance drift;
- paused proxy where the dangerous path is unreachable;
- owner-only rescue function with explicit access control;
- low-liquidity pool where the theoretical profit disappears after slippage/gas;
- honeypot/anti-bot branch that does not affect the contract owner's funds;
- diamond proxy with expected facet routing;
- minimal clone with immutable args;
- bytecode-identical clone family with different storage and different risk;
- privileged functions with non-standard but correct auth;
- overloaded selectors without an exploitable dispatch collision;
- fork-liquidity mismatch that creates false profit.

## Decompiler/proxy edge cases

- proxy implementation changed after snapshot;
- non-standard proxy slots;
- diamond proxies;
- `delegatecall` to external implementation;
- overloaded selectors and unknown ABI;
- decompiler invented names;
- storage packed fields;
- `CREATE2` or metamorphic deployment patterns;
- BSC RPC trace gaps;
- contracts where source is verified but runtime bytecode differs materially from expected artifact.

## Acceptance criteria

The first benchmark run is considered useful if it:

- reproducibly assembles an artifact bundle for each target;
- supports offline fixtures in the corpus (`bytecodePath`, `decompileDir`, `dedaubFile`, `selectors`), so that smoke/eval runs do not depend on RPC/Dedaub;
- finds at least some of the known exploited cases via validated evidence, not via a retelling of a public writeup;
- shows the false-positive rate on benign traps;
- compares at least two `Researcher/Skeptic` pairs;
- logs rejected hypotheses with a reason;
- saves validator artifacts sufficient for manual review.

## What not to include in the first corpus

- Non-EVM contracts.
- Cases without a pinned block.
- Cases where “success” is defined only by matching a public description.
- Contracts where it is not legally or technically possible to obtain runtime bytecode/artifacts.
