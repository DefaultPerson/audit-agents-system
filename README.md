# Autonomous Audit Agents

**An AI agent pipeline that autonomously researches vulnerabilities in closed-source EVM smart contracts — a concept demonstration.**

[**▶ Live demo — how it works**](https://defaultperson.github.io/audit-agents-system/) · [Reference code](src/)

> ⚠️ Research & educational concept. Ships with no credentials, no target lists, and with the offensive defaults disabled. Use only on testnet or contracts you are authorized to assess; disclosure is manual.

## Why

Crypto exploits have surged — **~$3.4B stolen in 2025** — and the hits keep coming:

- **Truebit Protocol** — Jan 2026, **~$26M** (8,535 ETH). An integer overflow in a bonding-curve pricing function returned a *zero* price for a crafted mint, so the attacker minted tokens for free and drained the reserves. The contract was **~5 years old, unverified, and unaudited**.
- **Balancer V2** — Nov 2025, **~$128M**. A rounding error in stable-pool invariant math, compounded dozens of times in a single transaction to skew pool prices.
- **Solv Protocol** — Jan 2026. A reentrancy *double-mint* turned 135 real tokens into **~567M** counterfeit ones.

How are so many bugs being found and drained so fast — often in *old, closed-source* contracts nobody had looked at in years?

This repo is **one hypothesis about how**: that part of the wave is automated, AI-driven vulnerability research — agents that pull unverified bytecode, decompile it, generate and argue attack hypotheses, and validate them on a fork, at scale. *([Speculation] — a concept demonstration of a plausible method, not a claim about any specific attacker.)*

The capability is clearly real: in May 2026, Anthropic's Opus 4.8, running an autonomous auditing agent, independently found a four-year-old soundness bug in Zcash's Orchard pool. This repo points that same autonomous-research loop at closed-source EVM contracts.

How each stage works — snapshot & triage → Dedaub decompile → immutable artifact bundle → a Researcher ⇄ Skeptic loop gated by hard evidence → fork / fuzz / symbolic validation → manual disclosure — is laid out interactively in the demo:

### → [defaultperson.github.io/audit-agents-system](https://defaultperson.github.io/audit-agents-system/)

## Explore

- **[Live demo →](https://defaultperson.github.io/audit-agents-system/)** — interactive walkthrough of the method.
- **[`src/`](src/)** — the reference implementation (Python 3.12), shown as illustration.

## License

[MIT](LICENSE) · responsible-use policy in [SECURITY.md](SECURITY.md).

## Sources

- Truebit Protocol exploit — [Rekt](https://rekt.news/truebit-rekt), [SlowMist](https://slowmist.medium.com/26-44-million-stolen-truebit-protocol-smart-contract-vulnerability-analysis-e44fe7becd8a), [CoinDesk](https://www.coindesk.com/markets/2026/01/09/truebit-token-tru-crashes-99-9-after-usd26-6m-exploit-drains-8-535-eth)
- Balancer V2 & 2025 review — [Halborn](https://www.halborn.com/blog/post/year-in-review-the-biggest-defi-hacks-of-2025)
- Exploit corpus & data — [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs), [Chainalysis 2025](https://www.chainalysis.com/blog/crypto-hacking-stolen-funds-2026/)
