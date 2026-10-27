import assert from "node:assert/strict";
import { isAbsolute, resolve } from "node:path";
import { test } from "node:test";
import { buildLocalMcpConfig } from "./print-mcp-config.mjs";

test("default registration launches this checkout", () => {
  const server = buildLocalMcpConfig([]).mcpServers.phxre;
  assert.equal(server.command, process.execPath);
  assert.ok(isAbsolute(server.args[0]));
  assert.equal(server.args[0], resolve("scripts/phxre.mjs"));
  assert.deepEqual(server.args.slice(1), ["mcp"]);
  assert.equal(server.env, undefined);
});

test("explicit target and loader arguments remain structured data", () => {
  const server = buildLocalMcpConfig([
    "file with spaces.bin",
    "--kind",
    "database",
    "--loader-args",
    '["-l","Mach-O","--aarch64"]',
  ]).mcpServers.phxre;
  assert.deepEqual(server.env, {
    HOPPER_TARGET_PATH: resolve("file with spaces.bin"),
    HOPPER_TARGET_KIND: "database",
    HOPPER_LOADER_ARGS_JSON: '["-l","Mach-O","--aarch64"]',
  });
});

for (const args of [
  ["--kind"],
  ["--kind", "database"],
  ["x", "--kind", "bad"],
  ["x", "--loader-args", "{}"],
  ["x", "--loader-args", "[1]"],
  ["--unknown"],
  ["x", "y"],
])
  test(`rejects invalid config arguments: ${JSON.stringify(args)}`, () => {
    assert.throws(() => buildLocalMcpConfig(args));
  });
