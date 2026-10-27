#!/usr/bin/env node
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Generate local registration only; never fetch a package or change a client file. */
export const buildLocalMcpConfig = (args, executable = process.execPath) => {
  let target;
  let kind;
  let loaderArgs;
  const seen = new Set();
  for (let index = 0; index < args.length; index++) {
    const token = args[index];
    if (token === "--kind" || token === "--loader-args") {
      if (seen.has(token)) throw new Error(`Duplicate option: ${token}`);
      seen.add(token);
      const value = args[++index];
      if (value === undefined || value.startsWith("--"))
        throw new Error(`Missing value for ${token}`);
      if (token === "--kind") {
        if (value !== "executable" && value !== "database")
          throw new Error("--kind must be executable or database");
        kind = value;
      } else {
        const parsed = JSON.parse(value);
        if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === "string"))
          throw new Error("--loader-args must be a JSON array of strings");
        loaderArgs = JSON.stringify(parsed);
      }
    } else if (token.startsWith("-")) {
      throw new Error(`Unknown option: ${token}`);
    } else if (target === undefined) {
      if (token.length === 0 || token.includes("\0"))
        throw new Error("Target must be a nonempty local path without NUL");
      target = resolve(token);
    } else throw new Error("Only one target path may be supplied");
  }
  if (target === undefined && (kind !== undefined || loaderArgs !== undefined))
    throw new Error("--kind and --loader-args require a target path");
  const environment =
    target === undefined
      ? {}
      : {
          HOPPER_TARGET_PATH: target,
          HOPPER_TARGET_KIND: kind ?? "executable",
          ...(loaderArgs === undefined ? {} : { HOPPER_LOADER_ARGS_JSON: loaderArgs }),
        };
  return {
    mcpServers: {
      phxre: {
        command: executable,
        args: [resolve(root, "scripts", "phxre.mjs"), "mcp"],
        ...(Object.keys(environment).length === 0 ? {} : { env: environment }),
      },
    },
  };
};

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.slice(2).includes("--help"))
      process.stdout.write(
        "Usage: node scripts/print-mcp-config.mjs [target-path] [--kind executable|database] [--loader-args JSON]\nPrints local phxre registration. Omitting target starts a target-free session.\n",
      );
    else
      process.stdout.write(
        `${JSON.stringify(buildLocalMcpConfig(process.argv.slice(2)), null, 2)}\n`,
      );
  } catch (cause) {
    process.stderr.write(`${cause instanceof Error ? cause.message : String(cause)}\n`);
    process.exitCode = 1;
  }
}
