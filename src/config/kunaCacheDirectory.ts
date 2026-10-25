import { isAbsolute, join } from "node:path";

/** Per-user cache directory that PhxRE owns for Kuna on this host. */
export const defaultKunaCacheDirectory = (
  home: string,
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform,
): string => {
  if (platform === "darwin")
    return join(home, "Library", "Caches", "phxre", "kuna");
  const xdg = environment.XDG_CACHE_HOME;
  return join(
    xdg !== undefined && isAbsolute(xdg) ? xdg : join(home, ".cache"),
    "phxre",
    "kuna",
  );
};
