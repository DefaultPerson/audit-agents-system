# Security & Responsible-Use Policy

This project is a **research and educational concept demonstration** of an autonomous
vulnerability-research methodology for closed-source EVM smart contracts. Please read
this before running anything.

## Scope of use

- **Authorized targets only.** Run the pipeline only against contracts you own, contracts
  on a public **testnet**, or contracts you have **explicit written authorization** to assess
  (e.g. an in-scope bug-bounty program or a paid engagement).
- **Not a turnkey tool.** This repository ships with **no credentials**, **no live target
  lists**, and with the live-scanning / auto-queue defaults **disabled**. Standing it up
  for live use requires your own API keys and deliberate opt-in flags.
- **No exploitation.** The pipeline stops at fork simulation and an internal, evidence-gated
  report. It does not deploy exploits against live contracts and does not move funds.

## Responsible disclosure

- Disclosure is **manual and human-gated**. The tooling never contacts a contract owner
  automatically. Owner lookup is read-only and only produces a routing hint.
- If you find a real, validated vulnerability in a third-party contract, follow responsible
  disclosure: contact the owner/maintainers privately, give them reasonable time to remediate,
  and do not publish exploitable details before a fix is deployed.

## Reporting an issue in *this* repository

If you find a security problem in this codebase itself (for example, a way it could leak
credentials or be misused beyond its intended scope), please open an issue describing the
concern without including any secrets, or contact the maintainer privately.

## Legal

You are solely responsible for complying with all applicable laws and with the terms of
service of any RPC provider, block explorer, or decompiler you use. Unauthorized access to
or interference with computer systems is illegal in most jurisdictions.
