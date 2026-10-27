---
name: reverse-engineer-anything
description: Reverse engineer native, managed, Electron/JavaScript, packaged, firmware, and browser targets with PhxRE. Use for shipped-artifact or runtime evidence, comparisons, and reconstruction; skip it for ordinary source-repository analysis.
metadata:
  version: "1.0.1"
---

# PhxRE fast path

Use PhxRE when the question depends on a shipped artifact, decompilation, or
runtime observation. For source-only architecture work, use normal repository
tools. Start with the smallest operation that answers the question; expand only
when its evidence leaves a specific gap.

## Route by target

Use the connected server's actual tool list and schemas; skill instructions do
not add tools to an older server.

| Target                                             | First route                                                                 |
| -------------------------------------------------- | --------------------------------------------------------------------------- |
| Native binary or archive                           | `open_binary`, then the relevant inventory or analysis tool                 |
| Electron, ASAR, JavaScript bundle                  | `analyze_javascript_application`                                            |
| Android package                                    | `inspect_android_package`                                                   |
| Managed PE/CLI                                     | `inspect_managed_artifact`                                                  |
| Firmware                                           | `inspect_firmware_regions`                                                  |
| Browser page or scenario                           | `list_browser_targets` or `capture_browser_scenario`                        |
| PCAP, HAR, SAZ, qlog                               | `inspect_web_network_capture` or the advertised capture summary tool        |
| Go, Rust, IL2CPP, WASM, SQLite, APK signature      | Use the matching format-specific inspection tool                            |
| Live process, Electron, Android or native behavior | Read `references/runtime-observation.md`; choose the exact runtime workflow |

For a known feature seed, prefer `trace_application_feature`. For a function,
use `analyze_function` before requesting procedure facets. Read only the
provider guide that matches the observed target; see the [guide index](#guides).

Choose the route from the question as well as the file type. Use the
[intent recipes](references/intent-recipes.md) for feature tracing, function
analysis, version comparison, and CLI fallback. Each recipe names the smallest
useful first call and the evidence that should justify a follow-up.

## Keep the first pass cheap

For an unfamiliar local file, use the CLI-only intake command before selecting
an engine:

```sh
phxre triage-artifact /absolute/path/to/file --json
```

It reads a bounded header sample, reports whether its SHA-256 covers the prefix
or complete file, and proposes existing tools without executing the target.
Validate the format with the selected parser. A suffix, signature match, or high
sample entropy is not proof of the complete format, encryption, or packing.
`triage-artifact` is not an MCP tool and does not create retained Evidence.

1. Identify target type and exact path or session. Reuse an open session and
   matching Evidence; do not repeat an identical analysis.
2. Use default output for small questions. For a large or uncertain inventory,
   request `detail: "summary"` and continue through its retained
   `parent_evidence_id` with `inspect_analysis_view`.
3. Ask for only the needed fields, section, function, or page. Export complete
   Evidence only when the task needs the whole record.
4. Batch related probes around one hypothesis. Stop when each requested claim
   has evidence; do not run broad inventories “just in case.”

PhxRE defaults to compact input schemas and omits advertised output schemas to
reduce MCP context. The server still validates successful results against its
canonical contracts and returns complete structured content. Set
`PHXRE_MCP_OUTPUT_SCHEMA_PROFILE=full` only when the client needs advertised
output schemas. Both profiles keep the complete tool set.

## Evidence and limits

- Label claims as **observed**, **inferred**, or **unknown**. Cite Evidence IDs,
  symbols, file offsets, or source paths where available.
- A bounded search that found no match is not proof of absence. Preserve the
  reported coverage and limitations.
- Static evidence does not prove runtime behavior. Use runtime tools only for
  the user's requested action and declared target; do not broaden execution.
- If output is paged or truncated, continue from the supplied cursor or retained
  Evidence. Do not treat a preview as the canonical full result.
- If a provider or tool is missing, continue with supported analysis and read
  [connection and recovery](references/connection-and-recovery.md). Do not rerun
  unchanged work after a timeout or uncertain mutation.

## If MCP is unavailable

Use the installed `phxre` CLI directly when shell access is available; it uses
the same local providers without MCP setup. Start with `phxre --help` or
`phxre capabilities` if the installed version or provider support is unclear.
The [intent recipes](references/intent-recipes.md#cli-fallback) give bounded
commands for common questions. If neither MCP nor shell is available, state
which required capability is unavailable and ask for the relevant output or
artifact; do not imply that analysis ran.

## Guides

- [Native formats, artifacts, Ghidra and analysis limits](references/native-and-artifacts.md)
- [JavaScript and bundle analysis](references/javascript-applications.md)
- [Runtime observation](references/runtime-observation.md)
- [Android](references/android-applications.md)
- [Evidence, investigations and reporting](references/evidence-workflows.md)
- [Intent-based investigation recipes and CLI fallback](references/intent-recipes.md)
- [Browser environments](references/environments.md)
- [Connection and recovery](references/connection-and-recovery.md)
- [Full routing matrix and advanced reconstruction, patching, Unity/Unreal,
  mobile and anti-analysis workflows](references/full-guide.md)

For CLI use, prefer an existing `phxre` binary. When package acquisition is in
scope, `npx -y phx-re@latest` is the fallback. MCP setup and provider recovery
are separate tasks; do not run setup before every investigation.
