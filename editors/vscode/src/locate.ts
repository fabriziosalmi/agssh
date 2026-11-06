// Binary lookup, free of the vscode API so it can be tested with node --test.
// Order: the agssh.binaryPath setting, then the usual install directories, then
// the bare name (resolved by PATH at spawn time).
import * as path from "path";

export function candidatePaths(home: string, platform: NodeJS.Platform): string[] {
  const exe = platform === "win32" ? "agssh.exe" : "agssh";
  const dirs = [
    home ? path.join(home, ".local", "bin") : "",
    "/opt/homebrew/bin",
    "/usr/local/bin",
    home ? path.join(home, "go", "bin") : "",
  ].filter((d) => d !== "");
  return dirs.map((d) => path.join(d, exe));
}

export function resolveBinary(
  setting: string | undefined,
  home: string,
  platform: NodeJS.Platform,
  exists: (p: string) => boolean,
): string {
  const s = (setting ?? "").trim();
  if (s) return s;
  for (const c of candidatePaths(home, platform)) if (exists(c)) return c;
  return platform === "win32" ? "agssh.exe" : "agssh";
}
