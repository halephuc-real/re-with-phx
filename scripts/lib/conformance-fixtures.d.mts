export const LARGE_FIXTURE_COUNT: number;
export const HOPPER_C_ORACLE: Readonly<{
  mainProcedure: "main";
  entryProcedure: "phxre_entry";
  branchProcedure: "phxre_branch";
  leafProcedure: "phxre_leaf";
  entryString: "PHXRE_C_ENTRY";
  leafString: "PHXRE_C_LEAF";
  globalName: "phxre_c_global";
}>;
export function sha256(value: string | Uint8Array): string;
export function generateLargeFixture(): string;
export function sourceDigest(
  sources: readonly { readonly path: string; readonly content: string }[],
): string;
