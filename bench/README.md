# MCP context benchmark

Run `npm run build:cached`, then `npm run benchmark:mcp-context` to compare the
compact input catalog with full output schemas against the compact catalog
without advertised output schemas. The benchmark uses the in-memory MCP
transport, excludes two warm-up rounds, and reports median `tools/list` time and
serialized payload bytes. Set `PHXRE_BENCH_ROUNDS` to change the number of
measured rounds.

This measures catalog transfer only. It does not count model tokens or measure
task accuracy, provider analysis, process startup, or end-to-end latency. The
full output-schema profile remains available through
`PHXRE_MCP_OUTPUT_SCHEMA_PROFILE=full`.

The leanrea end-to-end benchmark requires macOS, its target apps/binaries, and
Claude Code. Do not compare this local transport microbenchmark with those task
scores as if they were the same experiment.
