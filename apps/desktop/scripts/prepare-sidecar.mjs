import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const desktopDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(desktopDir, "../..");
const binariesDir = path.join(desktopDir, "src-tauri", "binaries");

function getHostTargetTriple() {
  const rustcInfo = execFileSync("rustc", ["-vV"], { encoding: "utf8" });
  const hostLine = rustcInfo
    .split(/\r?\n/)
    .find((line) => line.startsWith("host:"));
  if (!hostLine) {
    throw new Error("Could not determine Rust host target triple from `rustc -vV`");
  }
  return hostLine.slice("host:".length).trim();
}

function parseTargetTriple() {
  const targetIdx = process.argv.indexOf("--target");
  if (targetIdx !== -1 && process.argv[targetIdx + 1]) {
    return process.argv[targetIdx + 1].trim();
  }
  if (process.env.TAURI_ENV_TARGET_TRIPLE) {
    return process.env.TAURI_ENV_TARGET_TRIPLE.trim();
  }
  return getHostTargetTriple();
}

export function validateBinaryArchitecture(filePath, expectedTriple) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Binary file does not exist: ${filePath}`);
  }
  const fd = fs.openSync(filePath, "r");
  const buf = Buffer.alloc(1024);
  const bytesRead = fs.readSync(fd, buf, 0, 1024, 0);
  fs.closeSync(fd);

  if (bytesRead < 64) {
    throw new Error(`Binary file ${filePath} is too small (${bytesRead} bytes)`);
  }

  if (expectedTriple.includes("linux")) {
    // Linux ELF validation
    if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
      throw new Error(`Expected ELF binary for ${expectedTriple}, but ${filePath} lacks ELF magic`);
    }
    const is64 = buf[4] === 2;
    const isLe = buf[5] === 1;
    const machine = isLe ? buf.readUInt16LE(18) : buf.readUInt16BE(18);

    if (expectedTriple.startsWith("x86_64")) {
      if (!is64 || machine !== 0x3e) {
        throw new Error(
          `Architecture mismatch: binary at ${filePath} (is64=${is64}, machine=0x${machine.toString(16)}) does not match x86_64 for ${expectedTriple}`
        );
      }
    } else if (expectedTriple.startsWith("aarch64")) {
      if (!is64 || machine !== 0xb7) {
        throw new Error(
          `Architecture mismatch: binary at ${filePath} (is64=${is64}, machine=0x${machine.toString(16)}) does not match aarch64 for ${expectedTriple}`
        );
      }
    }
  } else if (expectedTriple.includes("windows")) {
    // Windows PE validation
    if (buf[0] !== 0x4d || buf[1] !== 0x5a) {
      throw new Error(`Expected PE binary for ${expectedTriple}, but ${filePath} lacks MZ magic`);
    }
    const peOffset = buf.readUInt32LE(0x3c);
    if (peOffset + 6 > bytesRead) {
      throw new Error(`PE header offset 0x${peOffset.toString(16)} out of bounds in ${filePath}`);
    }
    const peSig = buf.subarray(peOffset, peOffset + 4).toString("ascii");
    if (peSig !== "PE\0\0") {
      throw new Error(`Expected PE signature, found '${peSig}' in ${filePath}`);
    }
    const machine = buf.readUInt16LE(peOffset + 4);
    if (expectedTriple.startsWith("x86_64")) {
      if (machine !== 0x8664) {
        throw new Error(
          `Architecture mismatch: binary at ${filePath} machine=0x${machine.toString(16)} does not match x86_64 for ${expectedTriple}`
        );
      }
    } else if (expectedTriple.startsWith("aarch64")) {
      if (machine !== 0xaa64) {
        throw new Error(
          `Architecture mismatch: binary at ${filePath} machine=0x${machine.toString(16)} does not match aarch64 for ${expectedTriple}`
        );
      }
    }
  } else if (expectedTriple.includes("apple") || expectedTriple.includes("darwin")) {
    // macOS Mach-O validation
    const magic = buf.readUInt32LE(0);
    // 0xfeedfacf (64-bit LE) or 0xcffaedfe (64-bit BE)
    if (magic !== 0xfeedfacf && magic !== 0xcffaedfe) {
      throw new Error(`Expected 64-bit Mach-O binary for ${expectedTriple}, but magic=0x${magic.toString(16)} in ${filePath}`);
    }
    const cpuType = buf.readUInt32LE(4);
    if (expectedTriple.startsWith("x86_64")) {
      if (cpuType !== 0x01000007) {
        throw new Error(
          `Architecture mismatch: Mach-O binary cpuType=0x${cpuType.toString(16)} does not match x86_64 for ${expectedTriple}`
        );
      }
    } else if (expectedTriple.startsWith("aarch64")) {
      if (cpuType !== 0x0100000c) {
        throw new Error(
          `Architecture mismatch: Mach-O binary cpuType=0x${cpuType.toString(16)} does not match aarch64 for ${expectedTriple}`
        );
      }
    }
  }
}

function runCheck() {
  if (!fs.existsSync(binariesDir)) {
    throw new Error(`Binaries directory does not exist: ${binariesDir}`);
  }
  const files = fs.readdirSync(binariesDir);
  const sidecars = files.filter((f) => f.startsWith("kernlock-"));
  if (sidecars.length === 0) {
    throw new Error(`No sidecar binaries found in ${binariesDir}`);
  }
  for (const file of sidecars) {
    const filePath = path.join(binariesDir, file);
    const tripleWithExt = file.slice("kernlock-".length);
    const triple = tripleWithExt.replace(/\.exe$/, "");
    console.log(`Checking ${file} against triple ${triple}...`);
    validateBinaryArchitecture(filePath, triple);
    console.log(`  ✓ Architecture verified for ${triple}`);
  }
}

function buildAndPrepare() {
  const hostTriple = getHostTargetTriple();
  const targetTriple = parseTargetTriple();
  const release = process.argv.includes("--release");
  const profileDir = release ? "release" : "debug";
  const isWindows = targetTriple.includes("windows");
  const ext = isWindows ? ".exe" : "";

  console.log(`Target triple: ${targetTriple} (Host: ${hostTriple})`);

  let srcBin;
  if (targetTriple === hostTriple) {
    const cargoArgs = ["build", "--bin", "kernlock"];
    if (release) cargoArgs.push("--release");
    execFileSync("cargo", cargoArgs, { cwd: repoRoot, stdio: "inherit" });
    srcBin = path.join(repoRoot, "target", profileDir, `kernlock${ext}`);
  } else {
    // Cross-compiling for a different target triple
    const cargoArgs = ["build", "--bin", "kernlock", "--target", targetTriple];
    if (release) cargoArgs.push("--release");
    execFileSync("cargo", cargoArgs, { cwd: repoRoot, stdio: "inherit" });
    srcBin = path.join(repoRoot, "target", targetTriple, profileDir, `kernlock${ext}`);
  }

  if (!fs.existsSync(srcBin)) {
    throw new Error(`Expected built daemon binary at ${srcBin}`);
  }

  // Validate the binary architecture before copying.
  // Never label a host binary as another architecture!
  validateBinaryArchitecture(srcBin, targetTriple);

  fs.mkdirSync(binariesDir, { recursive: true });
  const dstBin = path.join(binariesDir, `kernlock-${targetTriple}${ext}`);
  fs.copyFileSync(srcBin, dstBin);
  if (!isWindows) {
    fs.chmodSync(dstBin, 0o755);
  }

  // Verify the copied binary in place
  validateBinaryArchitecture(dstBin, targetTriple);
  console.log(`Successfully verified and installed sidecar: ${dstBin}`);
}

const isDirectRun =
  process.argv[1] &&
  path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1]);

if (isDirectRun) {
  if (process.argv.includes("--check")) {
    runCheck();
  } else {
    buildAndPrepare();
  }
}
