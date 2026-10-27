import { z } from "incur";
import type { Logger } from "pino";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { localPathStringSchema } from "../domain/localPath.js";
import { triageArtifact } from "../filesystem/triageArtifact.js";
import { withCommandCancellation } from "./commandCancellation.js";
import type { CliInstance } from "./types.js";

export const registerTriageCommands = (cli: CliInstance, logger: Logger): void => {
  cli.command(CLI_COMMANDS.triageArtifact, {
    description:
      "Identify a local artifact from bounded header bytes and propose analysis tools without executing it",
    args: z.object({ path: localPathStringSchema.describe("Local regular file") }),
    options: z.object({
      hash: z
        .enum(["sample", "full"])
        .default("sample")
        .describe("Hash the sampled prefix or stream the complete file"),
      maxBytes: z
        .number()
        .int()
        .safe()
        .min(1)
        .default(64 * 1024 * 1024)
        .describe("Maximum bytes read, including full hashing (default 64 MiB)"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.triageArtifact, () =>
          triageArtifact(args.path, { ...options, signal }),
        ),
      ),
  });
};
