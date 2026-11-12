import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  SUPPORTED_TARGET_TRIPLES,
  validateBinaryArchitecture,
  checkSidecar,
} from "./prepare-sidecar.mjs";

console.log("Running Sidecar Architecture Validator Tests...");

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sidecar-test-"));

function createMockElf({ is64 = true, isLe = true, machine = 0x3e } = {}) {
  const buf = Buffer.alloc(1024);
  // ELF Magic
  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = is64 ? 2 : 1;
  buf[5] = isLe ? 1 : 2;
  buf[6] = 1; // version
  if (isLe) {
    buf.writeUInt16LE(machine, 18);
  } else {
    buf.writeUInt16BE(machine, 18);
  }
  return buf;
}

function createMockPe({ machine = 0x8664 } = {}) {
  const buf = Buffer.alloc(1024);
  // MZ magic
  buf[0] = 0x4d;
  buf[1] = 0x5a;
  // PE offset at 0x3c
  const peOffset = 0x80;
  buf.writeUInt32LE(peOffset, 0x3c);
  // PE\0\0 signature
  buf.write("PE\0\0", peOffset, "ascii");
  // Machine at peOffset + 4
  buf.writeUInt16LE(machine, peOffset + 4);
  return buf;
}

function createMockMachO({ isLe = true, cpuType = 0x01000007 } = {}) {
  const buf = Buffer.alloc(1024);
  if (isLe) {
    buf.writeUInt32LE(0xfeedfacf, 0);
    buf.writeUInt32LE(cpuType, 4);
  } else {
    buf.writeUInt32BE(0xfeedfacf, 0); // or 0xcffaedfe in LE
    buf.writeUInt32BE(cpuType, 4);
  }
  return buf;
}

try {
  // 1. Unsupported target triple fails closed
  assert.throws(
    () => validateBinaryArchitecture("/dev/null", "mips-unknown-linux-gnu"),
    /Unsupported target triple/
  );

  // 2. Non-existent file fails
  assert.throws(
    () =>
      validateBinaryArchitecture(
        path.join(tempDir, "does-not-exist"),
        "x86_64-unknown-linux-gnu"
      ),
    /Binary file does not exist/
  );

  // 3. Truncated file fails
  const smallFile = path.join(tempDir, "small.bin");
  fs.writeFileSync(smallFile, Buffer.alloc(32));
  assert.throws(
    () => validateBinaryArchitecture(smallFile, "x86_64-unknown-linux-gnu"),
    /too small/
  );

  // 4. Linux ELF x86_64 and aarch64 tests
  const elfX86File = path.join(tempDir, "elf_x86_64");
  fs.writeFileSync(elfX86File, createMockElf({ machine: 0x3e }));
  // Passes for x86_64-unknown-linux-gnu
  validateBinaryArchitecture(elfX86File, "x86_64-unknown-linux-gnu");
  validateBinaryArchitecture(elfX86File, "x86_64-unknown-linux-musl");
  // Rejects when expected is aarch64
  assert.throws(
    () => validateBinaryArchitecture(elfX86File, "aarch64-unknown-linux-gnu"),
    /Architecture mismatch/
  );
  // Rejects when expected is windows
  assert.throws(
    () => validateBinaryArchitecture(elfX86File, "x86_64-pc-windows-msvc"),
    /lacks MZ magic/
  );

  const elfArmFile = path.join(tempDir, "elf_aarch64");
  fs.writeFileSync(elfArmFile, createMockElf({ machine: 0xb7 }));
  validateBinaryArchitecture(elfArmFile, "aarch64-unknown-linux-gnu");
  validateBinaryArchitecture(elfArmFile, "aarch64-unknown-linux-musl");
  assert.throws(
    () => validateBinaryArchitecture(elfArmFile, "x86_64-unknown-linux-gnu"),
    /Architecture mismatch/
  );

  // 5. Windows PE x86_64 and aarch64 tests
  const peX86File = path.join(tempDir, "pe_x86_64.exe");
  fs.writeFileSync(peX86File, createMockPe({ machine: 0x8664 }));
  validateBinaryArchitecture(peX86File, "x86_64-pc-windows-msvc");
  validateBinaryArchitecture(peX86File, "x86_64-pc-windows-gnu");
  assert.throws(
    () => validateBinaryArchitecture(peX86File, "aarch64-pc-windows-msvc"),
    /Architecture mismatch/
  );
  assert.throws(
    () => validateBinaryArchitecture(peX86File, "x86_64-unknown-linux-gnu"),
    /lacks ELF magic/
  );

  const peArmFile = path.join(tempDir, "pe_aarch64.exe");
  fs.writeFileSync(peArmFile, createMockPe({ machine: 0xaa64 }));
  validateBinaryArchitecture(peArmFile, "aarch64-pc-windows-msvc");
  assert.throws(
    () => validateBinaryArchitecture(peArmFile, "x86_64-pc-windows-msvc"),
    /Architecture mismatch/
  );

  // 6. macOS Mach-O LE and BE tests for x86_64 and aarch64
  const machLeX86 = path.join(tempDir, "mach_x86_le");
  fs.writeFileSync(machLeX86, createMockMachO({ isLe: true, cpuType: 0x01000007 }));
  validateBinaryArchitecture(machLeX86, "x86_64-apple-darwin");
  assert.throws(
    () => validateBinaryArchitecture(machLeX86, "aarch64-apple-darwin"),
    /Architecture mismatch/
  );

  const machBeX86 = path.join(tempDir, "mach_x86_be");
  fs.writeFileSync(machBeX86, createMockMachO({ isLe: false, cpuType: 0x01000007 }));
  validateBinaryArchitecture(machBeX86, "x86_64-apple-darwin");
  assert.throws(
    () => validateBinaryArchitecture(machBeX86, "aarch64-apple-darwin"),
    /Architecture mismatch/
  );

  const machLeArm = path.join(tempDir, "mach_arm_le");
  fs.writeFileSync(machLeArm, createMockMachO({ isLe: true, cpuType: 0x0100000c }));
  validateBinaryArchitecture(machLeArm, "aarch64-apple-darwin");
  assert.throws(
    () => validateBinaryArchitecture(machLeArm, "x86_64-apple-darwin"),
    /Architecture mismatch/
  );

  const machBeArm = path.join(tempDir, "mach_arm_be");
  fs.writeFileSync(machBeArm, createMockMachO({ isLe: false, cpuType: 0x0100000c }));
  validateBinaryArchitecture(machBeArm, "aarch64-apple-darwin");
  assert.throws(
    () => validateBinaryArchitecture(machBeArm, "x86_64-apple-darwin"),
    /Architecture mismatch/
  );

  // 7. checkSidecar validation tests
  const mockBinDir = path.join(tempDir, "binaries");
  fs.mkdirSync(mockBinDir);

  // 7a. Missing target binary throws
  assert.throws(
    () =>
      checkSidecar({
        targetTriple: "x86_64-unknown-linux-gnu",
        customBinariesDir: mockBinDir,
      }),
    /Missing required sidecar binary/
  );

  // 7b. Unsupported target triple throws
  assert.throws(
    () =>
      checkSidecar({
        targetTriple: "riscv64-unknown-linux-gnu",
        customBinariesDir: mockBinDir,
      }),
    /Unsupported target triple/
  );

  // 7c. checkAll with empty directory throws
  assert.throws(
    () =>
      checkSidecar({
        targetTriple: "x86_64-unknown-linux-gnu",
        checkAll: true,
        customBinariesDir: mockBinDir,
      }),
    /No sidecar binaries found/
  );

  // 7d. Valid target sidecar succeeds
  const validHostBin = path.join(
    mockBinDir,
    "kernlock-x86_64-unknown-linux-gnu"
  );
  fs.writeFileSync(validHostBin, createMockElf({ machine: 0x3e }));
  assert.strictEqual(
    checkSidecar({
      targetTriple: "x86_64-unknown-linux-gnu",
      customBinariesDir: mockBinDir,
    }),
    true
  );

  // 7e. Architecture mismatch in sidecar throws
  const badArmBin = path.join(
    mockBinDir,
    "kernlock-aarch64-unknown-linux-gnu"
  );
  fs.writeFileSync(badArmBin, createMockElf({ machine: 0x3e })); // x86_64 machine code labeled as aarch64
  assert.throws(
    () =>
      checkSidecar({
        targetTriple: "aarch64-unknown-linux-gnu",
        customBinariesDir: mockBinDir,
      }),
    /Architecture mismatch/
  );

  // 7f. checkAll succeeds when all present sidecars are valid
  fs.writeFileSync(badArmBin, createMockElf({ machine: 0xb7 })); // fix to real aarch64
  assert.strictEqual(
    checkSidecar({
      targetTriple: "x86_64-unknown-linux-gnu",
      checkAll: true,
      customBinariesDir: mockBinDir,
    }),
    true
  );

  console.log("✓ All sidecar architecture validator tests passed successfully!");
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true });
}
