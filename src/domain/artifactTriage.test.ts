import { describe, expect, it } from "vitest";
import { identifyArtifactHeader, sampleEntropy } from "./artifactTriage.js";

describe("artifact intake signatures", () => {
  it.each([
    ["7f454c4602010100", "elf"],
    ["0061736d01000000", "wasm"],
    ["504b0304", "zip"],
    ["53514c69746520666f726d6174203300", "sqlite"],
    ["4747554603000000", "gguf"],
    ["47445043", "godot-pck"],
    ["6465780a30333500", "dex"],
    ["464f5231000000084245414d", "erlang-beam"],
    ["d00dfeed", "devicetree"],
    ["d4c3b2a1", "pcap"],
    ["0a0d0d0a", "pcapng"],
    ["feedfacf", "mach-o"],
    ["cafebabe00000002", "mach-o-universal"],
    ["cafebabe00000034", "java-class-candidate"],
    ["377abcaf271c", "7z"],
    ["1f8b0800", "gzip"],
    ["fd377a585a00", "xz"],
    ["", "unknown"],
    ["504b", "unknown"],
  ])("routes %s as %s", (hex, format) => {
    expect(identifyArtifactHeader(Buffer.from(hex, "hex")).format).toBe(format);
  });

  it("checks PE32 and PE32+ CLI data directories", () => {
    for (const [magic, size, directoryOffset] of [
      [0x10b, 224, 96],
      [0x20b, 240, 112],
    ] as const) {
      const pe = Buffer.alloc(512);
      pe.write("MZ");
      pe.writeUInt32LE(128, 0x3c);
      pe.write("PE\0\0", 128);
      pe.writeUInt16LE(size, 148);
      pe.writeUInt16LE(magic, 152);
      const directories = 152 + directoryOffset;
      pe.writeUInt32LE(16, directories - 4);
      expect(identifyArtifactHeader(pe).format).toBe("pe");
      pe.writeUInt32LE(0x2000, directories + 14 * 8);
      pe.writeUInt32LE(72, directories + 14 * 8 + 4);
      expect(identifyArtifactHeader(pe).format).toBe("pe-cli");
    }
  });

  it("handles every truncation without out-of-range reads", () => {
    const header = Buffer.alloc(1024, 255);
    header.write("MZ");
    for (let length = 0; length < header.length; length++)
      expect(() => identifyArtifactHeader(header.subarray(0, length))).not.toThrow();
  });

  it("reports entropy without a packing verdict", () => {
    expect(sampleEntropy(Buffer.alloc(0))).toBe(0);
    expect(sampleEntropy(Buffer.alloc(100, 42))).toBe(0);
    expect(sampleEntropy(Buffer.from(Array.from({ length: 256 }, (_, index) => index)))).toBe(8);
  });
});
