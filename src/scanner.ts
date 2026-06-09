import { ProjectFile, StaticVulnerability, ScanResult } from "./types";

// Static vulnerability scanning rules for disassemblies/code
export interface ScanningRule {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  category: string;
  title: string;
  description: string;
  remediation: string;
  // Rule matcher logic
  test: (instruction: { address: string; opcode: string; instruction: string; comment?: string }) => boolean;
}

export const SECURE_SCAN_RULES: ScanningRule[] = [
  {
    id: "VULN_001_GETS",
    severity: "CRITICAL",
    category: "Buffer Overflow",
    title: "Unbounded Stream Input (gets)",
    description: "The deprecated and unsafe standard library function 'gets()' does not perform any array boundary verification, allowing unlimited user input to override adjacent stack frames, return pointers, and control execution flows.",
    remediation: "Migrate instantly to safer bounds-enforcing APIs such as fgets() or read() with restrictive buffer length parameters.",
    test: (item) => {
      const op = item.opcode.toLowerCase();
      const inst = item.instruction.toLowerCase();
      const comm = (item.comment || "").toLowerCase();
      return (
        (op === "call" && inst === "gets") ||
        (op === "call" && inst.includes("gets@")) ||
        comm.includes("gets()") ||
        comm.includes("unbounded stack")
      );
    }
  },
  {
    id: "VULN_002_HARDCODED_KEY",
    severity: "HIGH",
    category: "Information Exposure",
    title: "Hardcoded Cryptographic Token or Plaintext Credential",
    description: "A hardcoded security credential, password literal, private key, or master authorization variable was identified explicitly embedded inside static data/text executable blocks.",
    remediation: "Store secrets in secure offline environment configurations, read them dynamically from hardware security modules (HSMs), or utilize robust key derivation schemas like PBKDF2/argon2.",
    test: (item) => {
      const inst = item.instruction.toLowerCase();
      const comm = (item.comment || "").toLowerCase();
      return (
        comm.includes("hardcoded password") ||
        comm.includes("secret key") ||
        inst.includes("adminmasterkeys") ||
        comm.includes("plaintext AdminMasterKeys")
      );
    },
  },
  {
    id: "VULN_003_FORMAT_STRING",
    severity: "MEDIUM",
    category: "Format Injection",
    title: "Unchecked Format String Hazard (printk/printf)",
    description: "Calling logging or layout routines (`printk`, `printf`, `sprintf`) where the formatting parameter is driven directly by untrusted memory boundaries or payload elements without static format descriptors leads directly to memory leakage.",
    remediation: "Always provide solid static formatting arguments, such as: printk(KERN_INFO '%s', user_buffer) instead of printk(user_buffer).",
    test: (item) => {
      const op = item.opcode.toLowerCase();
      const inst = item.instruction.toLowerCase();
      const comm = (item.comment || "").toLowerCase();
      return (
        (op === "call" && inst === "printk") ||
        (op === "call" && inst === "printf") ||
        comm.includes("format string leak")
      );
    }
  },
  {
    id: "VULN_004_INSECURE_STRLEN",
    severity: "LOW",
    category: "Improper Validation",
    title: "Non-NULL Terminated String Manipulation",
    description: "Manipulating raw string buffers using routines that depend on matching a trailing NULL null terminator byte can trigger read access violations or bypass password matches when input characters are not cleanly terminated.",
    remediation: "Verify buffers are strictly null-terminated, or switch to safer bounded string libraries like strncat or strncpy.",
    test: (item) => {
      const comm = (item.comment || "").toLowerCase();
      return comm.includes("null terminator") || comm.includes("strcmp");
    }
  },
  {
    id: "VULN_005_UNRESTRICTED_JUMP",
    severity: "HIGH",
    category: "Control Flow Integrity",
    title: "Insecure Conditional Bypass Offset",
    description: "An isolated conditional jump structure relies strictly on immediate raw register compare flags that could be altered via electromagnetic glitches or memory injection, skipping authentication validations entirely.",
    remediation: "Implement dual-phase checks or continuous software loop assertions mapping authentication tokens before rendering critical operational components.",
    test: (item) => {
      const op = item.opcode.toLowerCase();
      const comm = (item.comment || "").toLowerCase();
      return op === "jne" && comm.includes("auth_failed");
    }
  }
];

export function performStaticAnalysis(file: ProjectFile): ScanResult {
  const vulnerabilities: StaticVulnerability[] = [];

  // Iterate over each instruction and run all scanning rules
  file.disassembly.forEach((line) => {
    SECURE_SCAN_RULES.forEach((rule) => {
      if (rule.test(line)) {
        // Prevent adding exact duplicates for the same line/rule combination
        const exists = vulnerabilities.some(v => v.id === rule.id && v.address === line.address);
        if (!exists) {
          vulnerabilities.push({
            id: rule.id,
            severity: rule.severity,
            category: rule.category,
            address: line.address,
            title: rule.title,
            matchPattern: `${line.opcode} ${line.instruction}`,
            explanation: rule.description,
            remediation: rule.remediation
          });
        }
      }
    });
  });

  // Let's also check symbols for safety indicators
  file.symbols.forEach((sym) => {
    if (sym.name.toLowerCase() === "gets") {
      const exists = vulnerabilities.some(v => v.id === "VULN_001_GETS");
      if (!exists) {
        vulnerabilities.push({
          id: "VULN_001_GETS",
          severity: "CRITICAL",
          category: "Buffer Overflow",
          address: sym.address,
          title: "Vulnerable Shared Library Import ('gets')",
          matchPattern: `Symbol Import: ${sym.name}`,
          explanation: "The shared symbol imports 'gets' routine. Because gets() reads from standard input until a newline is found without length limiting, stack parameters are immediately susceptible to exploitation.",
          remediation: "Re-compile binary assets specifying -D_FORTIFY_SOURCE=2 or substitute buffer parsing libraries."
        });
      }
    }
    if (sym.name.toLowerCase().includes("key") || sym.name.toLowerCase().includes("master") || sym.name.toLowerCase().includes("secret")) {
      const exists = vulnerabilities.some(v => v.id === "VULN_002_HARDCODED_KEY" && v.address === sym.address);
      if (!exists) {
        vulnerabilities.push({
          id: "VULN_002_HARDCODED_KEY",
          severity: "HIGH",
          category: "Information Exposure",
          address: sym.address,
          title: `Sensitive Asset Symbol Exposed: '${sym.name}'`,
          matchPattern: `Symbol Reference: ${sym.name}`,
          explanation: `A potentially highly-sensitive variable or static data array '${sym.name}' is explicitly searchable / exposed in public ELF raw headers and symbols database.`,
          remediation: "Strip symbols block during production builds employing 'strip --strip-all' utility procedures."
        });
      }
    }
  });

  // Calculate scores and categories
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  vulnerabilities.forEach((v) => {
    if (v.severity === "CRITICAL") criticalCount++;
    else if (v.severity === "HIGH") highCount++;
    else if (v.severity === "MEDIUM") mediumCount++;
    else if (v.severity === "LOW") lowCount++;
  });

  // Dynamic code-health calculations. Base is 100, subtracting severity weights.
  const totalDeductions = (criticalCount * 25) + (highCount * 15) + (mediumCount * 8) + (lowCount * 3);
  const securityScore = Math.max(5, 100 - totalDeductions);

  return {
    fileId: file.id,
    fileName: file.name,
    scanTime: new Date().toISOString(),
    metrics: {
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      securityScore
    },
    vulnerabilities
  };
}
