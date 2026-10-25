import { compareUnicodeCodePoints } from "./unicodeCodePointOrder.js";
/** Deduplicate and sort strings with canonical code-point ordering. */
export const uniqueSorted = (values) => [...new Set(values)].sort(compareUnicodeCodePoints);
