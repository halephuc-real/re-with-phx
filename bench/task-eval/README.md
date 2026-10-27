# Task-quality evaluation protocol

This evaluates whether a model can answer reverse-engineering questions with
PhxRE. It is separate from `benchmark:mcp-context`, which measures only catalog
transfer and `tools/list` latency.

## Arms

Run each task with the same model, model settings, client, machine, base OS
tools, provider versions where relevant, and target copy in these arms:

1. `no-skill`: no RE skill and no PhxRE CLI/MCP; ordinary preinstalled OS tools
   remain available.
2. `phxre-skill-cli`: PhxRE skill and CLI, with MCP disabled.
3. `phxre-skill-mcp`: PhxRE skill and the PhxRE MCP server.

Use the same PhxRE build in both PhxRE arms. Give both arms equivalent provider
availability and permissions; the interface (CLI or MCP) is the variable being
compared.

Add another skill only when its owner permits the evaluation and its exact
version and tool access can be recorded. Randomize arm order. Start each run in
a fresh target copy and a clean conversation. Do not let one arm see another
arm's transcript or result.

## Task set and repetitions

Use at least four distinct tasks: a package/build inventory, a feature trace, a
native function/data-flow question, and a version or protocol comparison. Use
real artifacts with pinned hashes and manually reviewed answer keys. Run at
least five repetitions per task and arm before comparing aggregate scores; keep
per-task results visible so one easy task cannot hide a failure on another.

Do not construct tasks around a tool's output format. Ask the same user-facing
question in every arm. Include required claims, acceptable variants, known
unknowns, and the minimum evidence that supports each claim in the task file.

## Scoring

Two reviewers should score anonymized answers against the key. Resolve
disagreements before unblinding the arm. Score each category 0–2:

- **Factual correctness:** 0 wrong/unsupported, 1 partly right, 2 all required
  claims correct.
- **Evidence traceability:** 0 no usable source, 1 partial citations, 2 each
  material claim tied to an artifact location or Evidence record.
- **Uncertainty calibration:** 0 presents unknowns as facts, 1 mixed, 2 clearly
  separates observed, inferred, and unknown.
- **Coverage:** 0 misses the requested question, 1 partial, 2 addresses all
  required claims without unrelated exploration.

Record harmful false certainty separately; do not let a high total score hide
it. Report correctness and evidence scores as separate metrics, plus medians for
turns, input/output tokens, wall time, tool calls, and cost when the client
exposes them. Do not claim "absolute accuracy" from a finite sample.

## Reproducibility record

For every run, save the task ID, arm, anonymized transcript, raw tool/CLI
outputs, target SHA-256, model and settings, client version, PhxRE/provider
versions, OS/CPU, start/end time, token/cost data, reviewer scores, and any
timeouts or environment failures. Mark failed setup separately from an
incorrect answer.

`task-template.json` defines the task and result fields. This repository does
not yet include a pinned cross-format target corpus or reviewed answer keys, so
the protocol is ready but no task-quality score is claimed here.
