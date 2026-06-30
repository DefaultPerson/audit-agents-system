# Workflow Manifest

A concise description of the autonomous audit workflow this repo demonstrates. Research/educational concept only — see [SECURITY.md](SECURITY.md).

## The pipeline

1. **Snapshot & select.** Pull a snapshot of an EVM chain and extract contracts by value/risk criteria. The most promising targets are **closed-source (unverified) and old** – high balances, no published source, nobody watching.

2. **Decompile.** Run the bytecode through a decompiler (Dedaub gives the best output today) to recover readable, often-usable pseudo-Solidity. Recovered names are hints, not facts.

3. **Research – the long, parallel part.** Spin up autoresearch-style agents that generate and stress-test attack hypotheses, running long and in parallel across the contract's functions, using a couple of different models that argue rather than agree.

4. **Validate.** The creative stage: confirm or kill each hypothesis with *evidence* – pinned-fork tests, fuzzing, symbolic execution, economic checks. There is no single recipe, and reasoning alone is never enough.

5. **Build & test the PoC.** For the candidates that survive, write the reproduction/exploit code, deploy it, and exercise it **on a testnet** (or a pinned fork) to prove impact – never against live third-party funds.

Anything worth reporting is disclosed **manually** and responsibly.

→ Interactive walkthrough: <https://defaultperson.github.io/audit-agents-system/>
