# Intent-based investigation recipes

Use the recipe that answers the user's question. These are starting paths, not
mandatory full inventories. Check the connected server's current tool schemas;
skip any step whose evidence is already available in the same session.

## Identify an unknown application or artifact

1. For a directory or application bundle, call `inspect_desktop_application`
   and use its concrete candidates and next probes to choose one lane.
2. For a file, call `open_binary`, then `binary_overview` for observed identity,
   segments, and inventory counts. Use the format-specific inspector when the
   target is an APK, firmware image, capture, archive, or other supported
   container; do not force a native provider onto a data file.
3. State the detected format, evidence source, coverage, and unresolved
   classification. An extension or filename alone is not proof of format.

## Trace a feature or behavior

### Native target with a literal seed

1. `open_binary` on the exact target.
2. `trace_feature` with the exact string, path fragment, protocol label, or
   other literal the user supplied. Treat its matches and xrefs as candidates;
   it does not prove a complete feature path.
3. Resolve a promising address with `resolve_containing_procedure`, then call
   `analyze_function` with `detail: "summary"`. Inspect only the needed facet
   through `inspect_analysis_view`; use `trace_native_values` only when the
   question needs data flow or parameter/return relationships.
4. If the path reaches an OS or library boundary, use `inspect_native_api` on
   that function. Report unresolved indirect calls and unavailable coverage.

### Electron or JavaScript application

1. `analyze_javascript_application` with `detail: "summary"`; retain and reuse
   its parent Evidence rather than rerunning the graph analysis.
2. `trace_application_feature` with the exact seed. Follow only returned graph
   relations and selected source paths. For a static data-flow or call/return
   question, use `trace_javascript_semantics` instead of treating string
   matches as execution.
3. Use `reconcile_javascript_runtime` only when runtime behavior is part of
   the question and compatible runtime Evidence already exists or the user
   requested observation. Static graph reachability is not proof of execution.

If no useful literal seed exists, first inspect the relevant inventory, exports,
routes, or function names; do not invent a seed and run a broad trace.

## Explain one native function

1. Start from a function symbol/address already returned by the provider. If it
   is unknown, search the relevant names/strings or follow xrefs from observed
   evidence before decompiling.
2. Call `analyze_function` with `detail: "summary"`.
3. Request just the missing facet: pseudocode for high-level behavior, assembly
   for exact instruction/calling-convention details, callers/callees for local
   relationships, or `trace_native_values` for bounded value flow.
4. Base the conclusion on the returned body ranges and provider limitations.
   Do not equate pseudocode with original source or a direct call graph with all
   runtime paths.

## Compare versions

- JavaScript/Electron: produce authenticated application graphs for both exact
  versions, then call `compare_application_versions`. Review ambiguous matches
  and residual unknowns; do not call a missing graph node a deleted feature.
- Native: inventory both exact artifacts first. Use `compare_artifacts` for
  file-level identity, then `match_native_functions` and `compare_functions`
  for explicitly matched function Evidence. A changed function is not by itself
  proof that a user-visible behavior changed.
- Always record both artifact identities/hashes and separate observed changes
  from inferred behavioral effects.

## When to stop and how to report

Stop when every requested claim has supporting Evidence or is explicitly marked
unknown. For each claim, provide a short conclusion, its Evidence ID/symbol/path
or offset, authority (static or runtime), and the limitation that could change
the conclusion. Continue paging retained Evidence only when the answer needs
facts omitted from the summary. Do not export complete Evidence by default.

## CLI fallback

When MCP cannot be reached but shell access exists, use the installed CLI. Keep
the output bounded and save complete Evidence only when a later CLI command
needs it. Replace the angle-bracket placeholders with actual paths/seeds.

```sh
# Confirm the installed commands and provider capabilities.
phxre --help
phxre capabilities --format toon --token-limit 1200

# Fast overview of one executable or application.
phxre analyze "<target>" --format toon --token-limit 1600

# Trace one exact native feature string.
phxre trace "<target>" --query "<literal-seed>" --format toon --token-limit 1600

# Analyze an Electron/JavaScript application and retain complete Evidence.
phxre analyze-javascript-application "<app.asar-or-directory>" --detail summary --evidence_output "<evidence.json>" --format toon --token-limit 1600
```

If a command or flag is absent in the installed version, inspect that command's
`--help`; do not guess syntax. A CLI fallback uses the same installed provider
requirements as MCP and does not make a missing provider available. If `phxre`
is not installed, use a tool already present in the environment only when its
format and version are known; otherwise report the blocker instead of silently
switching to an unverified workflow.
