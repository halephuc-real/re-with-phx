import { z } from "zod";
// Ghidra language IDs are four colon-separated fields; variants may contain
// spaces ("x86:LE:16:Real Mode") but never leading or trailing whitespace.
export const ghidraLanguageIdSchema = z
    .string()
    .regex(/^[A-Za-z0-9_.+-]+:(?:LE|BE):[1-9]\d*:[A-Za-z0-9_.+-](?:[A-Za-z0-9_.+ -]*[A-Za-z0-9_.+-])?$/u, "must be a Ghidra language ID such as x86:LE:32:default");
export const ghidraCompilerSpecIdSchema = z
    .string()
    .regex(/^[A-Za-z0-9_.+-]+$/u, "must be a Ghidra compiler-spec ID such as default or borlandcpp");
