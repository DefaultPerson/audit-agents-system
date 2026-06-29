# Model/backend matrix

**Date**: 2026-05-18
**Status**: benchmark-driven selection policy

## Decision

Do not choose the “best model for auditing” in advance. For this task, disagreement quality and validator pass rate matter more than a general leaderboard.

## Roles

- `goal_planner`: a cheap model, turns the artifact bundle into bounded goals.
- `Researcher`: a strong reasoning model, proposes 1-3 attack hypotheses per goal.
- `Skeptic`: a different model family, checks preconditions, access control, storage assumptions, traces, and impact.
- `verification_worker`: a code model, writes the Foundry/fuzz/symbolic harness only after consensus.
- `summarizer`: a cheap model, compresses artifacts, receipts, and rejected hypotheses.
- `scout`: a cheap model or a local heuristic for selector/storage/trace triage.

## Backend candidates

- Frontier hosted models: candidates for `Researcher`, `Skeptic`, `verification_worker`.
- Different-family pairing: preferred for `Researcher/Skeptic`, to reduce shared blind spots.
- NVIDIA NIM/OpenAI-compatible free/cheap endpoints: candidates for `scout`, `summarizer`, and initial model research.
- Local/open models: candidates for cheap roles, if the benchmark confirms a low false-positive cost.

## Scoring

- validated high/critical findings on known exploited targets;
- false positives on benign traps;
- false negatives on known exploited targets;
- cost per target;
- time per target;
- reproducibility from clean state;
- number and quality of rejected hypotheses;
- verification package compile/run rate;
- evidence quality after validator execution.

## Promotion policy

- A model hypothesis is not a finding.
- `Researcher` cannot promote a finding on its own.
- `Skeptic` cannot replace the validator.
- `verification_worker` cannot assess success on its own.
- Final status is set by the validator + manual evidence review.

## First benchmark matrix

- Pair A: strong hosted `Researcher` + different-family strong hosted `Skeptic`.
- Pair B: strong hosted `Researcher` + cheaper hosted/open `Skeptic`.
- Pair C: cheaper/open `Researcher` + strong hosted `Skeptic`.
- Pair D: same-family baseline, only to measure the penalty from a lack of disagreement.

The final choice is fixed only after runs on `docs/benchmark-corpus.md`.
