# Workflow Manifest

A detailed walk through the autonomous audit workflow this repo demonstrates: how a closed-source EVM contract goes from a raw on-chain snapshot to a testnet-proven proof of concept, without a human reading the bytecode first.

The stages below map 1:1 to the **[interactive demo](https://defaultperson.github.io/audit-agents-system/)** – same names, same order. The whole thing optimizes for *reproducible evidence*, not a confident-sounding answer: every stage either produces a fact or kills the lead.

This is a **research/educational concept** – testnet only, and disclosure is always manual. See [SECURITY.md](SECURITY.md).

---

## 01 · Snapshot & Filter — Target Sourcing

Sync a full EVM snapshot, then mine it for the most promising prey: closed-source contracts, old and untouched, that still hold real funds.

- **Full-node snapshot** – the whole chain, local and queryable offline, so every deployed contract can be scanned without rate limits.
- **Criteria filter** – rank by *closed-source (unverified)* + *age* + *idle TVL*. Old and unaudited scores highest: nobody has the source, the compiler is years stale, and nobody is watching.
- **Candidate queue** – the narrowed set is streamed downstream; proxies are resolved to their implementation and identical bytecode is grouped into clone families so one finding can fan out.

Illustrative funnel: ~18M indexed contracts → closed-source + age > 3y → ~215k → idle TVL > $50k → **~1,900 candidates**.

## 02 · Decompile — Dedaub Recovery

Push each candidate through **Dedaub**, the strongest EVM decompiler today, and recover code that often reads almost like the original source.

- **Dedaub engine** – lifts raw bytecode into high-level, typed, named pseudo-Solidity with control flow recovered.
- **Selectors + storage** – function signatures and storage layout are reconstructed; external functions become the list of entrypoints to attack.
- **Clean enough to read** – the output is good enough for an agent to reason over directly. Hard rule: recovered names are *hints, not facts* – a real finding must point at a selector, a storage slot, or on-fork behavior.

## 03 · Agent Swarm — Parallel Auto-Research

Spawn a swarm of long-running agents across **Opus, GLM and Codex**. They hammer every function in parallel, and cross-check each other, so only findings that more than one model reaches survive.

- **Fan-out per function** – one or more agents are assigned to every entrypoint.
- **Multi-model** – the same target is probed by different model families at once; they argue rather than agree.
- **Long-horizon loop** – agents keep forming, testing and discarding hypotheses on a long budget.
- **Peer-verify** – a hypothesis only counts when a *second* model independently reaches it. Example: Opus flags `price()` overflowing to `0`, GLM re-derives the same bug, Codex writes a PoC and attacks it – and it holds.

This cross-model agreement is the quality gate: a single model's hunch is not yet a finding.

## 04 · Validate — Creative Triage

The creative step. Promising hypotheses get pressure-tested every which way and the noise is thrown out.

- **Multiple angles** – static recheck, fresh reasoning from scratch, quick simulation probes.
- **Cross-model vote** – findings that several models reach independently rank highest.
- **Keep / discard** – only the survivors move on, and most don't. Illustrative: 41 candidate hypotheses → 38 discarded as noise/unreachable → **3 survive** into the exploit queue.

There is no single recipe here – it is deliberately a judgement-heavy stage – but reasoning alone never survives it.

## 05 · Exploit & Testnet — PoC on Testnet

For the best survivors, write the actual exploit, deploy it, and fire it on a testnet fork to prove the bug is real – safely, before anything touches mainnet.

- **Write the exploit** – an agent drafts a runnable PoC for each kept finding.
- **Deploy to testnet** – a fork reproduces real state at the target block, so there is no mainnet risk.
- **Prove impact** – run it, measure the attacker's balance delta, and confirm the contract actually drains. A finding is "confirmed" only with a measured, testnet-only result.

---

### After the loop

A target run ends when it hits its iteration / cost / time budget, when rounds stop producing new hypotheses, when a confirmed finding lands, or when the target is marked low-signal. Anything worth reporting is disclosed **manually and responsibly** – the pipeline produces the evidence package; a human decides what to do with it.

### Why it scales

The pipeline is chain-agnostic (EVM adapters) and the swarm is domain-agnostic – the same shape of autonomous research that, in May 2026, let Opus 4.8 independently find a four-year-old soundness bug in Zcash's Orchard pool.

→ Interactive walkthrough: <https://defaultperson.github.io/audit-agents-system/>
