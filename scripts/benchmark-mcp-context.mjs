#!/usr/bin/env node

import { readFile, stat, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";

import { DeferredEvidenceMcpServer } from "../dist/server/DeferredEvidenceMcpServer.js";
import { ToolResultDelivery } from "../dist/server/ToolResultDelivery.js";

const roundsText = process.env.PHXRE_BENCH_ROUNDS ?? "10";
if (!/^[1-9]\d{0,2}$/u.test(roundsText))
  throw new Error("PHXRE_BENCH_ROUNDS must be between 1 and 999");
const rounds = Number(roundsText);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const warmups = 2;
const profiles = [
  { name: "compact-full", file: "mcp-catalog.json" },
  { name: "compact-off", file: "mcp-catalog-off.json" },
];

const median = (values) => {
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
};

const measure = async ({ name, file }) => {
  const path = resolve(root, "dist", file);
  const catalog = JSON.parse(await readFile(path, "utf8"));
  const times = [];
  let payloadBytes = 0;
  let outputSchemas = 0;

  for (let index = 0; index < warmups + rounds; index++) {
    const server = new DeferredEvidenceMcpServer(
      catalog,
      new ToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE),
      async () => {},
    );
    const client = new Client({ name: `phxre-context-${name}`, version: "1" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const started = performance.now();
      const response = await client.listTools();
      const elapsed = performance.now() - started;
      if (index >= warmups) times.push(elapsed);
      const encoded = JSON.stringify(response.tools);
      payloadBytes = Buffer.byteLength(encoded);
      outputSchemas = response.tools.filter((tool) => tool.outputSchema !== undefined).length;
    } finally {
      await Promise.allSettled([client.close(), server.close()]);
    }
  }

  return {
    profile: name,
    tools: catalog.tools.length,
    outputSchemas,
    catalogBytes: (await stat(path)).size,
    toolsListPayloadBytes: payloadBytes,
    toolsListMedianMs: Number(median(times).toFixed(2)),
    measuredRounds: rounds,
    warmups,
  };
};

const measured = [];
for (const profile of profiles) measured.push(await measure(profile));
const [reference, fast] = measured;
const referenceCatalog = JSON.parse(
  await readFile(resolve(root, "dist", "mcp-catalog.json"), "utf8"),
);
const fastCatalog = JSON.parse(
  await readFile(resolve(root, "dist", "mcp-catalog-off.json"), "utf8"),
);
const stableProjection = (catalog) =>
  catalog.tools.map(({ name, description, inputSchema }) => ({
    name,
    description,
    inputSchema,
  }));
const catalogPreserved =
  JSON.stringify(stableProjection(referenceCatalog)) ===
  JSON.stringify(stableProjection(fastCatalog));
if (!catalogPreserved)
  throw new Error("Fast catalog changed tool names, guidance, or input schemas");
const coreSkillBytes = (
  await stat(resolve(root, ".agents/skills/reverse-engineer-anything/SKILL.md"))
).size;
const onDemandGuideBytes = (
  await stat(resolve(root, ".agents/skills/reverse-engineer-anything/references/full-guide.md"))
).size;
const report = {
  benchmark: "PhxRE MCP tools/list catalog microbenchmark",
  node: process.version,
  platform: `${process.platform}-${process.arch}`,
  timestamp: new Date().toISOString(),
  caveat:
    "Measures in-memory MCP catalog delivery only; it does not measure model tokens, task accuracy, provider analysis, or end-to-end latency.",
  preserved: {
    sameToolNames: catalogPreserved,
    sameDescriptions: catalogPreserved,
    sameInputSchemas: catalogPreserved,
  },
  skillBytes: { core: coreSkillBytes, fullGuideOnDemand: onDemandGuideBytes },
  results: [reference, fast],
  reduction: {
    catalogBytesPercent: Number(
      ((1 - fast.catalogBytes / reference.catalogBytes) * 100).toFixed(1),
    ),
    toolsListPayloadBytesPercent: Number(
      ((1 - fast.toolsListPayloadBytes / reference.toolsListPayloadBytes) * 100).toFixed(1),
    ),
    toolsListMedianMsPercent: Number(
      ((1 - fast.toolsListMedianMs / reference.toolsListMedianMs) * 100).toFixed(1),
    ),
  },
};
const resultPath = resolve(
  root,
  "bench",
  "results",
  `mcp-context-${report.timestamp.slice(0, 10)}.json`,
);
await writeFile(resultPath, `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
