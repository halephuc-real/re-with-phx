/** Header observations are routing hints, never a substitute for format validation. */
export interface ArtifactIdentification {
  readonly format: string;
  readonly basis: string;
  readonly tools: readonly string[];
  readonly limitations: readonly string[];
}

export const identifyArtifactHeader = (bytes: Buffer): ArtifactIdentification => {
  const has = (hex: string, at = 0) =>
    bytes.subarray(at, at + hex.length / 2).toString("hex") === hex;
  const identified = (
    format: string,
    basis: string,
    tools: readonly string[],
    limitations: readonly string[] = [],
  ): ArtifactIdentification => ({ format, basis, tools, limitations });
  const native = ["open_binary"];
  const archive = ["open_binary", "inspect_artifact"];

  if (has("4d5a")) {
    if (bytes.length < 64) return identified("dos-mz", "MZ prefix; incomplete DOS header", native);
    const pe = bytes.readUInt32LE(0x3c);
    if (pe < 64 || pe + 24 > bytes.length || !has("50450000", pe))
      return identified("dos-mz", "MZ prefix; PE signature not established in sample", native, [
        "This may be a DOS executable, a malformed PE, or a PE header outside the sample.",
      ]);
    const optional = pe + 24;
    const optionalSize = bytes.readUInt16LE(pe + 20);
    const end = optional + optionalSize;
    const magic = optional + 2 <= bytes.length ? bytes.readUInt16LE(optional) : 0;
    const directories =
      magic === 0x10b ? optional + 96 : magic === 0x20b ? optional + 112 : undefined;
    if (
      directories !== undefined &&
      end <= bytes.length &&
      directories + 15 * 8 <= end &&
      bytes.readUInt32LE(directories - 4) >= 15 &&
      bytes.readUInt32LE(directories + 14 * 8) !== 0 &&
      bytes.readUInt32LE(directories + 14 * 8 + 4) >= 72
    )
      return identified(
        "pe-cli",
        "PE signature and nonempty CLI data directory",
        ["inspect_managed_artifact", ...native],
        ["CLI directory contents and metadata validity have not been checked."],
      );
    return identified(
      "pe",
      "PE signature following DOS e_lfanew",
      ["inspect_pe_imports", "inspect_native_exports", ...native],
      [
        "NativeAOT and embedded runtimes require further inspection; absence of a sampled CLI directory is inconclusive.",
      ],
    );
  }
  if (has("7f454c46"))
    return identified("elf", "ELF magic", [
      "inspect_elf_notes",
      "inspect_native_exports",
      ...native,
    ]);
  if (["feedface", "cefaedfe", "feedfacf", "cffaedfe"].some((magic) => has(magic)))
    return identified("mach-o", "Thin Mach-O magic", ["inspect_macho", ...native]);
  if (has("cafebabe")) {
    if (bytes.length >= 8 && bytes.readUInt16BE(6) >= 45)
      return identified(
        "java-class-candidate",
        "CAFEBABE with a Java-compatible major version",
        [],
        [
          "Magic overlaps universal Mach-O. Validate the constant pool with a Java class parser; no built-in Java class decompiler is asserted.",
        ],
      );
    return identified(
      "mach-o-universal",
      "Universal Mach-O magic",
      ["list_architectures", ...native],
      ["Slice records have not been validated."],
    );
  }
  if (["bebafeca", "cafebabf", "bfbafeca"].some((magic) => has(magic)))
    return identified("mach-o-universal", "Universal Mach-O magic", [
      "list_architectures",
      ...native,
    ]);
  if (has("0061736d")) return identified("wasm", "WebAssembly magic", ["inspect_wasm_artifact"]);
  if (["504b0304", "504b0506", "504b0708"].some((magic) => has(magic)))
    return identified("zip", "ZIP record signature", archive, [
      "APK, IPA, JAR and other ZIP subtypes require member inspection; suffixes alone do not identify them.",
    ]);
  if (bytes.length >= 8 && /^dex\n\d{3}\0$/u.test(bytes.subarray(0, 8).toString("latin1")))
    return identified(
      "dex",
      "DEX magic and version field",
      [],
      [
        "Use a DEX-capable bytecode reader. inspect_android_package requires a standalone APK; raw DEX is not that input contract.",
      ],
    );
  if (has("53514c69746520666f726d6174203300"))
    return identified(
      "sqlite",
      "SQLite format 3 header",
      ["inspect_sqlite_database"],
      ["Use a quiescent database/WAL snapshot; this report fingerprints only the selected file."],
    );
  if (has("47475546")) return identified("gguf", "GGUF magic", ["inspect_model_artifact"]);
  if (has("47445043")) return identified("godot-pck", "Godot PCK magic", archive);
  if (has("464f5231") && has("4245414d", 8))
    return identified("erlang-beam", "FOR1 container with BEAM type", ["inspect_erlang_beam"]);
  if (has("d00dfeed"))
    return identified("devicetree", "Flattened device tree magic", ["inspect_devicetree"]);
  if (["d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d"].some((magic) => has(magic)))
    return identified("pcap", "Classic PCAP magic", [
      "inspect_pcap_capture",
      "inspect_packet_capture",
    ]);
  if (has("0a0d0d0a"))
    return identified("pcapng", "PCAPNG section block magic", ["inspect_pcap_capture"]);
  if (has("377abcaf271c"))
    return identified(
      "7z",
      "7-Zip magic",
      [],
      ["Extract with a compatible archive tool, then inspect selected members."],
    );
  if (has("1f8b"))
    return identified(
      "gzip",
      "gzip magic",
      [],
      ["Decompress into a separate output before routing the payload."],
    );
  if (has("fd377a585a00"))
    return identified(
      "xz",
      "XZ magic",
      [],
      ["Decompress into a separate output before routing the payload."],
    );
  if (has("7573746172", 257))
    return identified(
      "tar",
      "ustar marker",
      [],
      ["Archive headers and member paths still require validation before extraction."],
    );
  return identified(
    "unknown",
    bytes.length === 0 ? "Empty file" : "No recognized signature in sampled prefix",
    [],
    [
      "Unknown is not evidence of encryption or packing. Raw firmware, ASAR, safetensors, scripts and other formats may lack a distinctive prefix.",
    ],
  );
};

export const sampleEntropy = (bytes: Buffer): number => {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte] = (counts[byte] ?? 0) + 1;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / bytes.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};
