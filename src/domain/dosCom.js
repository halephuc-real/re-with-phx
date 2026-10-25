import { z } from "zod";
import { err, ok } from "./result.js";
/** Headerless executable interpretation explicitly selected by the caller. */
export const executableFormatHintSchema = z.enum(["dos-com", "raw-binary"]);
/** Validate the single 64 KiB COM segment, excluding its 256-byte PSP prefix. */
export const validateDosComLength = (length) => Number.isSafeInteger(length) && length >= 1 && length <= 0xff00
    ? ok(null)
    : err("DOS COM requires 1..65280 file bytes (64 KiB segment minus the 256-byte PSP prefix)");
