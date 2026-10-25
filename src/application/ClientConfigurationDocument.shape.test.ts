import { describe, expect, it } from "vitest";

import {
  parseClientConfiguration,
  shadowedClientServers,
} from "./ClientConfigurationDocument.js";

describe("parseClientConfiguration shape diagnostics", () => {
  it.each([
    ["null", "null"],
    ["array", "[]"],
    ["string", '"x"'],
  ] as const)("names a non-object JSON root (%s)", (_label, text) => {
    expect(() => parseClientConfiguration(text, "json")).toThrow(
      new TypeError("The configuration root must be an object"),
    );
  });

  it.each([
    ["null", "null"],
    ["array", "[]"],
    ["string", '"x"'],
  ] as const)(
    'names a non-object "mcpServers" value (%s)',
    (_label, servers) => {
      expect(() =>
        parseClientConfiguration(`{"mcpServers":${servers},"keep":1}`, "json"),
      ).toThrow(new TypeError('"mcpServers" must be an object'));
    },
  );

  it("still rejects unparsable JSON with SyntaxError", () => {
    expect(() => parseClientConfiguration("not-json", "json")).toThrow(
      SyntaxError,
    );
  });

  it("reports only duplicates in the effective server object", () => {
    const owned = '{"command":"phxre","args":["mcp"]}';
    const activeTable = `{"mcpServers":{"phxre":null,"phxre":${owned}}}`;
    const active = parseClientConfiguration(activeTable, "json");
    expect(shadowedClientServers(activeTable, active, "phxre")).toEqual({
      servers: [null],
      legacyServers: [],
    });

    // Removing from the effective parent leaves an earlier repeated parent
    // inactive. Its members are not registrations the client would reveal.
    const inactiveParent =
      `{"mcpServers":{"phxre":{"command":"/usr/bin/false"}},` +
      `"mcpServers":{"phxre":${owned}}}`;
    const parsed = parseClientConfiguration(inactiveParent, "json");
    expect(shadowedClientServers(inactiveParent, parsed, "phxre")).toEqual({
      servers: [],
      legacyServers: [],
    });
  });
});
