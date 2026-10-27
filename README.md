# PhxRE: Reverse Engineer Anything

PhxRE 1.0.1 is a reverse-engineering toolkit exposed as the `phxre` MCP server.
It includes native, managed, web, firmware, and runtime analysis tools.

## What is included

- `phxre` MCP server entrypoint: `scripts/phxre.mjs mcp`
- 229 MCP tools for native, managed, JavaScript, Android, web, firmware,
  browser, artifact, and runtime analysis (generated from canonical contracts)
- Upgraded `reverse-engineer-anything` skill with full source reconstruction,
  call-stack backtrace, parameter mapping, VTable mapping, offset mapping,
  internal-call testing, patcher workflow, and protection-check analysis
- Windows native helper source and reproducible build instructions
- Cleaned runtime-focused repository layout

## Quick start

```bash
git clone https://github.com/halephuc-real/re-with-phx.git
cd re-with-phx
npm ci
npm run build:windows-native  # requires Linux and MinGW-w64
npm run build:cached
```

Run the MCP server directly:

```bash
node scripts/phxre.mjs mcp
```

OpenCode MCP configuration example:

```json
{
  "mcp": {
    "phxre": {
      "type": "local",
      "command": [
        "C:\\\\Program Files\\\\nodejs\\\\node.exe",
        "C:\\\\path\\\\to\\\\PhxRE\\\\scripts\\\\phxre.mjs",
        "mcp"
      ],
      "enabled": true,
      "environment": {
        "GHIDRA_INSTALL_DIR": "C:\\\\tools\\\\ghidra_12.1.4_PUBLIC",
        "JAVA_HOME": "C:\\\\Program Files\\\\Eclipse Adoptium\\\\jdk-21.0.12.101-hotspot"
      }
    }
  }
}
```

## Patcher templates

Ready-to-use patcher starting points live in:

```text
templates/patchers/
```

- `pe_patcher.py` — PE patching by RVA, file offset, or pattern
- `elf_patcher.py` — ELF patching by virtual address, file offset, or pattern
- `frida_hook_template.js` — runtime hook template

The end-user workflow skill is located at:

```text
skills/reverse-engineer-anything/SKILL.md
```

Its authored source is:

```text
.agents/skills/reverse-engineer-anything/SKILL.md
```

Regenerate generated skill metadata after editing the authored source:

```bash
npm run artifacts:skills
```

## Notes

- The npm package identity is `phx-re`.
- The local MCP server name and tool namespace are `phxre`.
- The `phxre` command alias is available through `npm link` or `npx` when the
  package is installed locally.
- MCP advertises compact input schemas and omits output schemas by default to
  reduce context. Canonical output validation and complete structured results
  remain enabled. Set `PHXRE_MCP_OUTPUT_SCHEMA_PROFILE=full` for clients that
  need output schemas in `tools/list`.
- Native Windows build output is generated locally; see `native/windows/README.md`.

Measure the local MCP catalog payload and `tools/list` latency with
`npm run benchmark:mcp-context` after building. This is a transport microbenchmark,
not an end-to-end model accuracy benchmark. The latest recorded run is in
[`bench/results/mcp-context-2026-10-27.json`](bench/results/mcp-context-2026-10-27.json).
The repeatable task-quality evaluation protocol and task template are in
[`bench/task-eval/`](bench/task-eval/README.md); no task-quality score is claimed
until pinned targets and reviewed answer keys are added.

## License

See `LICENSE` and `licenses/` for project and third-party license terms.
