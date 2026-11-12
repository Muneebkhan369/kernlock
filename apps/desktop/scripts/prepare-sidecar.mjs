import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const desktopDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(desktopDir, "../..");
const release = process.argv.includes("--release");

const rustcInfo = execFileSync("rustc", ["-vV"], { encoding: "utf8" });
const hostLine = rustcInfo
  .split(/\r?\n/)
  .find((line) => line.startsWith("host:"));
if (!hostLine) {
  throw new Error("Could not determine Rust host target triple from `rustc -vV`");
}
const targetTriple = hostLine.slice("host:".length).trim();
const ext = targetTriple.includes("windows") ? ".exe" : "";

const cargoArgs = ["build", "--bin", "kernlock"];
if (release) {
  cargoArgs.push("--release");
}
execFileSync("cargo", cargoArgs, { cwd: repoRoot, stdio: "inherit" });

const profileDir = release ? "release" : "debug";
const srcBin = path.join(repoRoot, "target", profileDir, `kernlock${ext}`);
if (!fs.existsSync(srcBin)) {
  throw new Error(`Expected built daemon binary at ${srcBin}`);
}

const binariesDir = path.join(desktopDir, "src-tauri", "binaries");
fs.mkdirSync(binariesDir, { recursive: true });
const dstBin = path.join(binariesDir, `kernlock-${targetTriple}${ext}`);
fs.copyFileSync(srcBin, dstBin);
if (!targetTriple.includes("windows")) {
  fs.chmodSync(dstBin, 0o755);
}

console.log(`Prepared Tauri sidecar: ${dstBin}`);
