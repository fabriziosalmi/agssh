// Thin shell over the agssh CLI: execFile, no shell, JSON from stdout or from the
// -out file. Exit codes (cmd/agssh): 0 conformant, 1 non-conformant, 3 unscannable
// all carry a record; 2 is a usage/internal error. No vscode import.
import { execFile } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ConformanceRecord, parseRecords } from "./record";

export class BinaryNotFoundError extends Error {
  constructor(public readonly bin: string) {
    super(`agssh binary not found at '${bin}'`);
    this.name = "BinaryNotFoundError";
  }
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export function run(bin: string, args: string[], cwd?: string, signal?: AbortSignal): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    execFile(bin, args, { cwd, signal, maxBuffer: 64 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      if (err && (err as NodeJS.ErrnoException).code === "ENOENT") {
        reject(new BinaryNotFoundError(bin));
        return;
      }
      if (err && (err as Error).name === "AbortError") {
        reject(new Error("scan cancelled"));
        return;
      }
      const code = err ? (typeof (err as { code?: unknown }).code === "number" ? (err as { code: number }).code : -1) : 0;
      if (code === -1) {
        reject(err);
        return;
      }
      resolve({ code, stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

function carriesRecord(code: number): boolean {
  return code === 0 || code === 1 || code === 3;
}

function failure(what: string, r: RunResult): Error {
  const tail = (r.stderr || r.stdout).trim().split("\n").slice(-6).join("\n");
  return new Error(`${what} failed (exit ${r.code})${tail ? `: ${tail}` : ""}`);
}

export async function scanUrl(bin: string, url: string, profile: string, level: string,
  timeoutSeconds: number, signal?: AbortSignal): Promise<{ records: ConformanceRecord[]; log: string }> {
  const args = ["scan", "-json", "-profile", profile, "-level", level, "-timeout", `${timeoutSeconds}s`, url];
  const r = await run(bin, args, undefined, signal);
  if (!carriesRecord(r.code)) throw failure("agssh scan", r);
  return { records: parseRecords(r.stdout), log: r.stderr };
}

export async function scanConfig(bin: string, configPath: string, timeoutSeconds: number,
  signal?: AbortSignal): Promise<{ records: ConformanceRecord[]; log: string }> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agssh-vscode-"));
  const out = path.join(dir, "record.json");
  try {
    const args = ["-config", path.basename(configPath), "-out", out, "-timeout", `${timeoutSeconds}s`];
    const r = await run(bin, args, path.dirname(configPath), signal);
    if (!carriesRecord(r.code) || !fs.existsSync(out)) throw failure("agssh -config", r);
    return { records: parseRecords(fs.readFileSync(out, "utf8")), log: r.stdout + r.stderr };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export async function ruleText(bin: string, id: string): Promise<string> {
  const r = await run(bin, ["rule", id]);
  if (r.code !== 0) throw failure(`agssh rule ${id}`, r);
  return r.stdout;
}

export async function version(bin: string): Promise<string> {
  const r = await run(bin, ["-version"]);
  return r.stdout.trim();
}
