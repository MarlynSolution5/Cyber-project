// Shared Type declarations for Binary Analysis Workspace

export interface DisassemblyInstruction {
  address: string;
  opcode: string;
  instruction: string;
  comment?: string;
  bytes: string;
}

export interface FunctionSymbol {
  name: string;
  address: string;
  size: number;
  type: "Function" | "Import" | "Export" | "String";
}

export interface RegisterState {
  name: string;
  value: string;
  description: string;
  changed?: boolean;
}

export interface RiskFinding {
  riskType: "High" | "Medium" | "Low";
  location: string;
  finding: string;
  resolution: string;
}

export interface AnalysisResponse {
  pseudocode: string;
  analysis: string;
  technicalDebtScore: number;
  highRiskPaths: RiskFinding[];
  remediationCode: string;
}

export interface ProjectFile {
  id: string;
  name: string;
  size: string;
  type: string;
  symbolCount: number;
  disassembly: DisassemblyInstruction[];
  symbols: FunctionSymbol[];
}

export interface StaticVulnerability {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  category: string;
  address?: string; // target assembly memory location if mapping can refer
  title: string;
  matchPattern: string; // what triggered the rule
  explanation: string;
  remediation: string;
}

export interface ScanResult {
  fileId: string;
  fileName: string;
  scanTime: string;
  metrics: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    securityScore: number; // 0-100 code safety percentage
  };
  vulnerabilities: StaticVulnerability[];
}

