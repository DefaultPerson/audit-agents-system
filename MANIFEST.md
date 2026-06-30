# Workflow Manifest

A detailed walk through the autonomous audit workflow this repo demonstrates: how a closed-source EVM contract goes from a raw on-chain snapshot to a testnet-proven proof of concept, without a human reading the bytecode first.

This is a **research/educational concept**. It is evidence-gated by design – a model's opinion is never a finding – and disclosure is always manual. See [SECURITY.md](SECURITY.md).

The core idea: the loop optimizes for *reproducible evidence*, not for a confident-sounding answer. Every stage either produces a fact or kills the lead.

---

## 1. Snapshot & select

Pin an EVM chain at a specific block and pull a snapshot, then rank contracts by value and risk. The signal that matters most:

- **Closed-source (unverified) bytecode** – no published source, so no human and almost no tool has really looked at it.
- **Old** – deployed years ago, on a compiler nobody would ship today, with assumptions that have since broken.
- **Holding value** – a balance or TVL large enough to be worth the compute.

Contracts are grouped into **clone families** by bytecode hash, so one finding can fan out across every identical deployment. Proxies are resolved to their implementation before anything else.

> Truebit (Jan 2026, ~$26M) is the archetype: a ~5-year-old, unverified, unaudited contract still holding 8,540 ETH.

## 2. Decompile & bundle

Recover something readable from the bytecode. **Dedaub** is the primary decompiler today; behind it sit fallbacks so the loop never depends on one tool's guesses:

- disassembly / control-flow recovery,
- selector & interface recovery,
- storage-layout extraction,
- raw storage reads, recent traces, logs, balances.

All of this is frozen into an **immutable artifact bundle** – the single source of truth for the rest of the run. Hard rule: **decompiled names are hints, not facts.** A hypothesis must point at a selector, a storage slot, a trace, or on-fork behavior – never at a function name the decompiler invented.

## 3. Research – the long, parallel part

This is where the agents run. A cheap **goal planner** carves the contract into bounded objectives, one per specialist domain:

- auth & upgradeability,
- proxy, storage & delegatecall,
- accounting, share math & rounding,
- oracle, price & liquidity,
- state machine & lifecycle,
- external calls, callbacks & reentrancy.

For each goal, two **different model families** argue instead of agree:

- a **Researcher** proposes 1–3 concrete attack hypotheses, each tied to a selector and a precondition;
- a **Skeptic** attacks them – missing access-control checks, wrong state assumptions, impact that doesn't actually pay after gas.

They iterate, long-running and in parallel across goals. Cheap context tools (selector lookup, storage read, `cast call`, trace read) are allowed *before* consensus to settle arguments. Dead ends are written to a **rejected-hypothesis memory** so later runs don't re-explore them.

## 4. The consensus gate

A hypothesis only leaves the debate when it is concrete enough to build validation code. The gate is **deterministic** – plain code, not a model vote – and promotes a hypothesis only when **all five** hold:

1. an affected **selector** (or fallback path),
2. explicit **preconditions**,
3. a concrete **expected impact**,
4. a **validation method**,
5. at least one **supporting fact** that actually exists in the artifact bundle.

Miss any one and the hypothesis goes back to the loop with the reason attached. This is the line between "interesting idea" and "candidate worth money."

## 5. Validate

The creative stage – confirm or kill each candidate with *evidence*, escalating only as needed:

1. **Foundry pinned-fork test** – reproduce the exploit against real state at the snapshot block (baseline, mandatory).
2. **ItyFuzz** – bytecode-level exploit search.
3. **Symbolic** (Mythril / Halmos) – bounded proofs where a property can be expressed.
4. **Economic checks** – profit after gas, liquidity, slippage, fee-on-transfer, oracle-manipulation cost.

A passing empty test is not evidence. Reasoning-only hypotheses never become findings; only fork/fuzz/symbolic/economic results survive into a report.

## 6. Build, deploy & prove (testnet)

For the candidates that survive validation, write the reproduction/exploit code, deploy it, and exercise it **on a testnet** (or a pinned fork) to prove impact end to end – **never against live third-party funds.**

## 7. Disclosure

Findings worth reporting are disclosed **manually** and responsibly: a human decides what to do with the evidence. The pipeline produces the evidence package; it never contacts an owner on its own.

---

### Stop conditions

A target run ends when it hits the iteration / cost / time budget, when several rounds produce no new hypotheses, when a validated high/critical finding is found, or when the target is marked low-signal after enough cheap checks.

### Why it scales

The whole thing is chain-agnostic (EVM adapters) and the Researcher ⇄ Skeptic loop is domain-agnostic – the same shape that, in May 2026, let Opus 4.8 autonomously find a four-year-old soundness bug in Zcash's Orchard pool.

→ Interactive walkthrough: <https://defaultperson.github.io/audit-agents-system/>
