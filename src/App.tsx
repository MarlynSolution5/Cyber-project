import React, { useState, useEffect } from "react";
import { 
  FolderOpen, 
  Terminal, 
  Cpu, 
  ShieldAlert, 
  Sparkles, 
  Play, 
  Search, 
  Layers, 
  FileCode, 
  FileWarning, 
  ArrowRight, 
  CheckCircle2, 
  RefreshCw, 
  RotateCcw, 
  FileText, 
  Database,
  Check,
  Zap,
  HelpCircle,
  Copy
} from "lucide-react";
import { PRELOADED_FILES, INITIAL_REGISTERS, INITIAL_STACK, HEX_DUMP_DATA } from "./data";
import { ProjectFile, DisassemblyInstruction, FunctionSymbol, RegisterState, AnalysisResponse, ScanResult, StaticVulnerability } from "./types";
import { performStaticAnalysis } from "./scanner";

interface CFGBlock {
  id: string;
  name: string;
  address: string;
  instructions: string[];
  type: "start" | "eval" | "success" | "failure" | "exit";
  connections: { targetId: string; condition?: string; color: string }[];
}

const getCFGBlocks = (fileId: string): CFGBlock[] => {
  if (fileId === "firmware_auth") {
    return [
      {
        id: "start",
        name: "START BLOCK (main)",
        address: "0x4001A0",
        instructions: [
          "0x4001A0:  push rbp",
          "0x4001A1:  mov rbp, rsp",
          "0x4001A4:  sub rsp, 0x120",
          "0x4001B5:  call gets  [⚠ VULNERABLE]"
        ],
        type: "start",
        connections: [{ targetId: "eval", condition: "Sequential", color: "cyan" }]
      },
      {
        id: "eval",
        name: "EVAL BLOCK (strcmp)",
        address: "0x4001CB",
        instructions: [
          "0x4001CB:  call strcmp",
          "0x4001D0:  test eax, eax",
          "0x4001D2:  jne 0x4001E8"
        ],
        type: "eval",
        connections: [
          { targetId: "success", condition: "ZF=1 (Match)", color: "emerald" },
          { targetId: "failure", condition: "ZF=0 (Mismatched)", color: "rose" }
        ]
      },
      {
        id: "success",
        name: "AUTHORIZED BLOCK (grant_elevated_access)",
        address: "0x4001D4",
        instructions: [
          "0x4001D4:  mov dword ptr [rbp-4], 1",
          "0x4001DB:  call grant_elevated_access",
          "0x4001E0:  jmp 0x4001F0"
        ],
        type: "success",
        connections: [{ targetId: "exit", color: "slate" }]
      },
      {
        id: "failure",
        name: "DENIED BLOCK (auth_failed)",
        address: "0x4001E8",
        instructions: [
          "0x4001E8:  mov dword ptr [rbp-4], 0",
          "0x4001EC:  call auth_failed"
        ],
        type: "failure",
        connections: [{ targetId: "exit", color: "slate" }]
      },
      {
        id: "exit",
        name: "RETURN BLOCK",
        address: "0x4001F0",
        instructions: [
          "0x4001F0:  add rsp, 0x120",
          "0x4001F7:  pop rbp",
          "0x4001F8:  ret"
        ],
        type: "exit",
        connections: []
      }
    ];
  } else if (fileId === "iot_sensor_driver") {
    return [
      {
        id: "start",
        name: "START BLOCK (init_module)",
        address: "0x000000",
        instructions: [
          "0x000000:  push rbp",
          "0x000001:  mov rbp, rsp"
        ],
        type: "start",
        connections: [{ targetId: "printk", condition: "Sequential", color: "cyan" }]
      },
      {
        id: "printk",
        name: "PRINTK BLOCK (Kernel debug print)",
        address: "0x000004",
        instructions: [
          "0x000004:  lea rdi, [rip]  ; load dynamic buffer",
          "0x00000B:  call printk  [⚡ FORMAT LEAK]"
        ],
        type: "eval",
        connections: [{ targetId: "exit", condition: "Done", color: "cyan" }]
      },
      {
        id: "exit",
        name: "RETURN BLOCK",
        address: "0x000010",
        instructions: [
          "0x000010:  leave",
          "0x000011:  ret"
        ],
        type: "exit",
        connections: []
      }
    ];
  } else {
    // validate_token
    return [
      {
        id: "start",
        name: "START BLOCK (check_integrity)",
        address: "0x80483b0",
        instructions: [
          "0x80483b0:  push ebp",
          "0x80483b1:  mov ebp, esp",
          "0x80483b3:  sub esp, 24"
        ],
        type: "start",
        connections: [{ targetId: "compare", condition: "Sequential", color: "cyan" }]
      },
      {
        id: "compare",
        name: "COMPARE SEGMENT",
        address: "0x80483b6",
        instructions: [
          "0x80483b6:  mov eax, [ebp + 8]",
          "0x80483b9:  mov edx, [0x08049000]",
          "0x80483bf:  cmp eax, edx",
          "0x80483c1:  je 0x80483ca  (Valid)"
        ],
        type: "eval",
        connections: [
          { targetId: "suc_ret", condition: "Token Matches", color: "emerald" },
          { targetId: "fail_ret", condition: "Bypass / Invalid", color: "rose" }
        ]
      },
      {
        id: "suc_ret",
        name: "SUCCESS BLOCK",
        address: "0x80483ca",
        instructions: [
          "0x80483ca:  mov al, 1"
        ],
        type: "success",
        connections: [{ targetId: "exit", color: "slate" }]
      },
      {
        id: "fail_ret",
        name: "FAILED INTEGRITY BLOCK",
        address: "0x80483c3",
        instructions: [
          "0x80483c3:  xor eax, eax",
          "0x80483c5:  jmp 0x80483cc"
        ],
        type: "failure",
        connections: [{ targetId: "exit", color: "slate" }]
      },
      {
        id: "exit",
        name: "RETURN PATHWAY",
        address: "0x80483cc",
        instructions: [
          "0x80483cc:  leave",
          "0x80483cd:  ret"
        ],
        type: "exit",
        connections: []
      }
    ];
  }
};

export default function App() {
  // Application State
  const [projectFiles, setProjectFiles] = useState<ProjectFile[]>(PRELOADED_FILES);
  const [activeFile, setActiveFile] = useState<ProjectFile>(PRELOADED_FILES[0]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedInstructionIdx, setSelectedInstructionIdx] = useState<number | null>(null);
  const [editingCommentIdx, setEditingCommentIdx] = useState<number | null>(null);
  const [commentInput, setCommentInput] = useState("");
  const [renamingState, setRenamingState] = useState<{ idx: number; type: "opcode" | "instruction" } | null>(null);
  const [renameInput, setRenameInput] = useState("");
  
  // Tab States
  const [leftTab, setLeftTab] = useState<"symbols" | "strings">("symbols");
  const [centerTab, setCenterTab] = useState<"assembly" | "graph" | "vulnerabilities">("assembly");
  const [activeFilterSymbol, setActiveFilterSymbol] = useState<string>("");

  // CFG Search & Highlights
  const [cfgSearchQuery, setCfgSearchQuery] = useState("");
  const [selectedCfgNode, setSelectedCfgNode] = useState<string | null>(null);

  // Static Security Scanner State
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [heatmapEnabled, setHeatmapEnabled] = useState(true);

  // Run dynamic analysis and updates when active file changes
  useEffect(() => {
    if (activeFile) {
      const res = performStaticAnalysis(activeFile);
      setScanResult(res);
    }
  }, [activeFile]);

  const handleRunStaticScan = () => {
    if (activeFile) {
      const res = performStaticAnalysis(activeFile);
      setScanResult(res);
      setLogs(prev => [
        ...prev,
        `[SECURITY-AUDIT] Static analyzer manually fired over ${activeFile.name}. Found ${res.vulnerabilities.length} vulnerability patterns. Integrated security rating calibrated to ${res.metrics.securityScore}%.`
      ]);
    }
  };

  // Simulated Register/Stack/Debugger execution
  const [registers, setRegisters] = useState<RegisterState[]>(INITIAL_REGISTERS);
  const [stack, setStack] = useState(INITIAL_STACK);
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [logs, setLogs] = useState<string[]>([
    "[SYSTEM] Binary Analysis Workspace initialized successfully.",
    "[SYSTEM] Target CPU configuration: ISA x86_64, Little Endian.",
    "[SYSTEM] Loaded file: firmware_auth.bin. Parsing ELF headers...",
    "[ANALYSIS] Discovered 14 symbols. Warning: Symbol 'gets' resolves to deprecated non-safe stdio routine."
  ]);

  // AI Analysis & Security Audit states
  const [customPrompt, setCustomPrompt] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [showRefusalNotice, setShowRefusalNotice] = useState(false);
  const [aiResponse, setAiResponse] = useState<AnalysisResponse | null>({
    pseudocode: `// Pseudocode representation of main()
void* main(int argc, char** argv) {
    char userInput[256];
    int authState = 0;

    // High Risk: gets() contains no length protection, vulnerable to overflow
    gets(userInput);

    if (strcmp(userInput, "AdminMasterKeys2026") == 0) {
        authState = 1;
        grant_elevated_access();
    } else {
        authState = 0;
    }
    return (void*)authState;
}`,
    analysis: "The function reads a control login string from stdio using gets, compares it with a static hardcoded key string, and branches immediately based on parity outcomes. If the input matches AdminMasterKeys2026, it grants system privileged context.",
    technicalDebtScore: 82,
    highRiskPaths: [
      {
        riskType: "High",
        location: "Address 0x4001B5 (call gets)",
        finding: "Usage of gets() allows infinite input overflow directly over the return parameter address of the stack frame.",
        resolution: "Replace with fgets(userInput, sizeof(userInput), stdin) to enforce bounded stream length limits."
      },
      {
        riskType: "Medium",
        location: "Address 0x401200 (Static String)",
        finding: "Hardcoded administrative token 'AdminMasterKeys2026' stored in plain text inside public executable segments.",
        resolution: "Incorporate PBKDF2 derivative key hashing comparison or retrieve a modern access signature during active handshake routines."
      }
    ],
    remediationCode: `#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 256
// Secure refactored version enforcing boundary checks and avoiding plaintext comparisons:

int main(int argc, char** argv) {
    char userInput[BUFFER_SIZE];
    int authState = 0;

    printf("Enter administrative payload: ");
    if (fgets(userInput, sizeof(userInput), stdin) == NULL) {
        return 0;
    }

    // Strip newline character if present
    userInput[strcspn(userInput, "\\n")] = '\\0';

    // In a production application, implement a secure hash comparison (e.g., using SHA-256)
    // instead of matching raw plaintext strings. For demonstrating visual correction:
    if (strcmp(userInput, "AdminMasterKeys2026") == 0) {
        authState = 1;
        printf("[+] Credentials accepted. Enacting secure callback.\\n");
        // grant_elevated_access();
    } else {
        printf("[-] Identification token mismatch.\\n");
        authState = 0;
    }

    return authState;
}`
  });

  // Handle active file switching
  const handleSelectFile = (file: ProjectFile) => {
    setActiveFile(file);
    setSelectedInstructionIdx(null);
    setSearchQuery("");
    setActiveFilterSymbol("");
    setLogs(prev => [
      ...prev,
      `[SYSTEM] Context switched to file: ${file.name}`,
      `[SYSTEM] Disassembled ${file.disassembly.length} instructions into workspace environment.`
    ]);
  };

  // Automated Step/Execution runner simulation
  const handleStepForward = () => {
    const nextIdx = (currentStep + 1) % activeFile.disassembly.length;
    setCurrentStep(nextIdx);
    
    // Randomly shift registry records slightly to simulate execution updates
    setRegisters(prev => prev.map(reg => {
      if (reg.name === "RIP") {
        return { ...reg, value: activeFile.disassembly[nextIdx]?.address || reg.value, changed: true };
      }
      if (Math.random() > 0.6) {
        const parsedVal = parseInt(reg.value, 16);
        const shiftVal = Math.floor(Math.random() * 24) - 12;
        const newVal = "0x" + Math.max(0, parsedVal + shiftVal).toString(16).toUpperCase();
        return { ...reg, value: newVal, changed: true };
      }
      return { ...reg, changed: false };
    }));

    // Random stack update simulation
    setStack(prev => prev.map(item => {
      if (Math.random() > 0.8) {
        return { ...item, val: "0x" + Math.floor(Math.random() * 0xFFFFFFFF).toString(16).toUpperCase() };
      }
      return item;
    }));

    const nextOp = activeFile.disassembly[nextIdx];
    setLogs(prev => [
      ...prev,
      `[DEBUGGER] Step Into address ${nextOp?.address || ""}: ${nextOp?.opcode || ""} ${nextOp?.instruction || ""}`
    ]);
  };

  const handleResetSimulator = () => {
    setCurrentStep(0);
    setRegisters(INITIAL_REGISTERS);
    setStack(INITIAL_STACK);
    setLogs(prev => [...prev, "[DEBUGGER] Restored execution workspace to starting IP context."]);
  };

  // Handle Comment editing inside assemblies
  const startEditingComment = (idx: number, currentComment: string) => {
    setEditingCommentIdx(idx);
    setCommentInput(currentComment || "");
  };

  const saveComment = (idx: number) => {
    const updatedDisasm = [...activeFile.disassembly];
    updatedDisasm[idx] = {
      ...updatedDisasm[idx],
      comment: commentInput.trim() ? commentInput.trim() : undefined
    };

    const updatedFile = {
      ...activeFile,
      disassembly: updatedDisasm
    };

    setActiveFile(updatedFile);
    setProjectFiles(prev => prev.map(f => f.id === activeFile.id ? updatedFile : f));
    setEditingCommentIdx(null);
    setLogs(prev => [...prev, `[USER] Amended comment at assembly index ${idx}.`]);
  };

  // Inline rename elements to demonstrate persistent context tracking
  const startRenaming = (idx: number, field: "opcode" | "instruction", currentVal: string) => {
    setRenamingState({ idx, type: field });
    setRenameInput(currentVal);
  };

  const saveRename = (idx: number) => {
    if (!renameInput.trim()) return;
    const updatedDisasm = [...activeFile.disassembly];
    const prevOp = updatedDisasm[idx][renamingState!.type];
    
    updatedDisasm[idx] = {
      ...updatedDisasm[idx],
      [renamingState!.type]: renameInput.trim()
    };

    const updatedFile = {
      ...activeFile,
      disassembly: updatedDisasm
    };

    setActiveFile(updatedFile);
    setProjectFiles(prev => prev.map(f => f.id === activeFile.id ? updatedFile : f));
    setRenamingState(null);
    setLogs(prev => [...prev, `[USER] Refactored term '${prevOp}' -> '${renameInput.trim()}' at address ${updatedDisasm[idx].address}.`]);
  };

  // Decompilation & automated code validation invoking Gemini securely
  const triggerAICodeAnalysis = async () => {
    // Check for malicious user query words containing active intercept vectors targeting messaging services.
    const query = customPrompt.toLowerCase();
    if (query.includes("whatsapp") || query.includes("decrypt") || query.includes("intercept") || query.includes("encrypted") || query.includes("phone number")) {
      setShowRefusalNotice(true);
      setLogs(prev => [
        ...prev,
        "[SECURITY] Aborted third-party intercept generation request. This tool is built strictly for authorized defensive firmware inspection and security code health auditing scopes."
      ]);
      return;
    }

    setIsAnalyzing(true);
    try {
      // Reconstruct assembly code sequence into a plaintext stream for our request payload
      const assemblyText = activeFile.disassembly.map(line => 
        `${line.address}:  ${line.opcode}  ${line.instruction}   ; ${line.comment || ""}`
      ).join("\n");

      const response = await fetch("/api/analyze-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: assemblyText,
          filename: activeFile.name,
          customPrompt: customPrompt || "Identify dead code blocks, calculate technical debt score, and generate highly optimized, modernized pseudocode with security remediation structures."
        })
      });

      if (!response.ok) {
        throw new Error("Cloud analysis service returned response error.");
      }

      const result: AnalysisResponse = await response.json();
      setAiResponse(result);
      setLogs(prev => [
        ...prev,
        `[ANALYSIS] Gemini completed code analysis for ${activeFile.name}. Calculated Debt Score: ${result.technicalDebtScore}/100.`
      ]);
    } catch (err: any) {
      console.error(err);
      setLogs(prev => [
        ...prev,
        `[ERROR] Server-side analysis execution failed: ${err.message}`
      ]);
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Filter symbols based on search prompt
  const filteredSymbols = activeFile.symbols.filter(sym => 
    sym.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
    sym.address.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-[#0F1115] text-[#D1D5DB] font-sans flex flex-col antialiased">
      {/* Visual Workspace Menu and Header */}
      <header className="bg-[#181C24] border-b border-[#2D3139] px-4 py-2 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-tr from-cyan-500 to-indigo-600 rounded-lg text-white shadow-lg shadow-cyan-500/10">
            <Cpu className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-white font-bold text-base tracking-tight">Binary Analysis Workspace</span>
              <span className="text-[10px] bg-cyan-500/10 text-cyan-400 px-1.5 py-0.5 rounded font-mono border border-cyan-500/20">v2.8.5 LE</span>
            </div>
            <p className="text-xs text-[#828896]">Defensive binary disassembly and reverse engineering dashboard</p>
          </div>
        </div>

        {/* Toolbar Controls */}
        <div className="flex items-center gap-2 flex-wrap text-xs">
          <button 
            onClick={handleStepForward}
            className="flex items-center gap-1.5 bg-[#252B36] hover:bg-cyan-500 hover:text-white text-cyan-400 px-3 py-1.5 rounded font-medium border border-[#373E4D] transition"
            title="Step Instruction Counter"
            id="toolbar-step-into"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Step Into</span>
          </button>
          
          <button 
            onClick={handleResetSimulator}
            className="flex items-center gap-1.5 bg-[#252B36] hover:bg-[#323948] text-[#9CA3AF] px-3 py-1.5 rounded font-medium border border-[#373E4D] transition"
            title="Restore Debugger"
            id="toolbar-reset"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset registers</span>
          </button>

          <button 
            onClick={() => {
              setLogs(prev => [...prev, `[USER] Saved disassembly snapshot for ${activeFile.name}.`]);
              alert("Workspace snapshot state archived to browser session storage.");
            }}
            className="bg-[#2D3341] hover:bg-[#3C4456] text-white px-3 py-1.5 rounded border border-[#3E4657] transition"
            id="toolbar-save"
          >
            Save Snapshot
          </button>
        </div>
      </header>

      {/* Main Multi-Pane Visual Layout Grid */}
      <div className="flex-1 grid grid-cols-1 xl:grid-cols-12 gap-1.5 p-1.5 overflow-hidden">
        
        {/* Left Control Desk: Project Browser & Symbols (Span 3) */}
        <div className="xl:col-span-3 bg-[#13161C] border border-[#232731] rounded-lg flex flex-col overflow-hidden shadow-inner">
          <div className="p-3 bg-[#191D26] border-b border-[#232731]">
            <div className="flex items-center gap-2 text-white font-semibold text-xs mb-3">
              <FolderOpen className="w-4 h-4 text-cyan-400" />
              <span>PROJECT SOURCE SELECTOR</span>
            </div>

            {/* List preloaded files safely */}
            <div className="space-y-1">
              {projectFiles.map(file => {
                const isActive = file.id === activeFile.id;
                return (
                  <button
                    key={file.id}
                    onClick={() => handleSelectFile(file)}
                    className={`w-full text-left p-2 rounded transition flex items-center justify-between text-xs ${
                      isActive 
                        ? "bg-slate-800 text-white border-l-2 border-cyan-500 font-semibold" 
                        : "hover:bg-slate-900/50 text-[#9CA3AF]"
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate">
                      <Layers className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-gray-500'}`} />
                      <span className="truncate">{file.name}</span>
                    </div>
                    <span className="text-[10px] bg-[#1C202B] text-gray-500 px-1 py-0.2 rounded shrink-0">{file.size}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Navigation Browse Tabs (Symbols vs Discovered Strings) */}
          <div className="flex border-b border-[#232731]">
            <button
              onClick={() => setLeftTab("symbols")}
              className={`flex-1 py-2 text-center text-xs font-semibold select-none ${
                leftTab === "symbols" ? "border-b-2 border-cyan-400 text-white bg-[#181D26]" : "text-[#828896] hover:bg-slate-900/30"
              }`}
            >
              Discover Symbols ({activeFile.symbols.filter(s => s.type !== "String").length})
            </button>
            <button
              onClick={() => setLeftTab("strings")}
              className={`flex-1 py-2 text-center text-xs font-semibold select-none ${
                leftTab === "strings" ? "border-b-2 border-cyan-400 text-white bg-[#181D26]" : "text-[#828896] hover:bg-slate-900/30"
              }`}
            >
              Discovered Strings ({activeFile.symbols.filter(s => s.type === "String").length})
            </button>
          </div>

          <div className="p-2 border-b border-[#232731] bg-[#161A22] flex items-center gap-1.5">
            <Search className="w-3.5 h-3.5 text-gray-500" />
            <input 
              type="text"
              placeholder={`Search ${leftTab}...`}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-transparent text-xs text-white border-0 outline-none w-full placeholder-gray-600"
            />
          </div>

          {/* Symbols or Data list contents */}
          <div className="flex-1 overflow-y-auto p-1.5 space-y-1 max-h-[400px] xl:max-h-full">
            {leftTab === "symbols" ? (
              filteredSymbols.filter(s => s.type !== "String").map((sym, i) => (
                <button
                  key={i}
                  onClick={() => {
                    setActiveFilterSymbol(sym.name);
                    setLogs(prev => [...prev, `[USER] Filtered assembly list context to routine: '${sym.name}'`]);
                  }}
                  className={`w-full text-left p-1.5 rounded transition flex items-center justify-between text-xs font-mono group ${
                    activeFilterSymbol === sym.name 
                      ? "bg-cyan-950/40 text-cyan-300 border border-cyan-800/40" 
                      : "hover:bg-[#1A1F29] text-[#9CA3AF]"
                  }`}
                >
                  <div className="flex items-center gap-1.5 truncate">
                    <span className={`w-1.5 h-1.5 rounded-full ${sym.type === "Import" ? "bg-amber-400" : "bg-emerald-500"}`} />
                    <span className="truncate group-hover:text-white transition">{sym.name}</span>
                  </div>
                  <span className="text-[10px] text-gray-500 shrink-0 font-sans">{sym.address}</span>
                </button>
              ))
            ) : (
              filteredSymbols.filter(s => s.type === "String").map((sym, i) => (
                <div
                  key={i}
                  className="p-2 rounded bg-[#161922] border border-[#242A38] text-xs font-mono space-y-1"
                >
                  <div className="flex items-center justify-between text-[10px] text-cyan-500">
                    <span>ASCII Static segment</span>
                    <span>{sym.address}</span>
                  </div>
                  <div className="text-emerald-400 truncate bg-slate-950 p-1 rounded font-mono select-all">
                    "{sym.name}"
                  </div>
                </div>
              ))
            )}

            {activeFilterSymbol && (
              <button
                onClick={() => setActiveFilterSymbol("")}
                className="w-full mt-2 text-center text-[10px] text-cyan-400 bg-cyan-950/20 py-1 hover:bg-cyan-950/40 rounded border border-cyan-900/40 font-semibold"
              >
                Clear Symbol Isolation Filter
              </button>
            )}
          </div>
        </div>

        {/* Center Top Block: Assembly / Visual CFG (Span 6) */}
        <div className="xl:col-span-6 flex flex-col gap-1.5">
          
          <div className="bg-[#13161C] border border-[#232731] rounded-lg flex flex-col flex-1 overflow-hidden min-h-[420px]">
            {/* Assembly view or interactive diagram tab selection bar */}
            <div className="bg-[#191D26] px-3 py-1 flex items-center justify-between border-b border-[#232731]">
              <div className="flex items-center gap-1.5 text-xs text-white uppercase tracking-wider font-semibold">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Primary Workspace Disassembly: {activeFile.name}</span>
                {activeFilterSymbol && (
                  <span className="bg-cyan-500/15 text-cyan-400 px-1.5 py-0.2 rounded text-[10px] normal-case">
                    Isolating: {activeFilterSymbol}
                  </span>
                )}
              </div>

              <div className="flex bg-[#252B36] p-0.5 rounded border border-[#373E4D]">
                <button
                  onClick={() => setCenterTab("assembly")}
                  className={`px-2.5 py-1 text-[11px] rounded transition font-medium ${
                    centerTab === "assembly" ? "bg-cyan-500 text-white shadow" : "text-gray-400 hover:text-white"
                  }`}
                  id="tab-selector-list"
                >
                  List View
                </button>
                <button
                  onClick={() => setCenterTab("graph")}
                  className={`px-2.5 py-1 text-[11px] rounded transition font-medium ${
                    centerTab === "graph" ? "bg-cyan-500 text-white shadow" : "text-gray-400 hover:text-white"
                  }`}
                  id="tab-selector-cfg"
                >
                  Control Flow Graph (CFG)
                </button>
                <button
                  onClick={() => setCenterTab("vulnerabilities")}
                  className={`px-2.5 py-1 text-[11px] rounded transition font-medium flex items-center gap-1 ${
                    centerTab === "vulnerabilities" ? "bg-rose-600 text-white shadow font-semibold" : "text-gray-400 hover:text-rose-400"
                  }`}
                  id="tab-selector-scanner"
                >
                  <ShieldAlert className="w-3.5 h-3.5 shrink-0 text-rose-400" />
                  <span>Vuln Guard</span>
                  {scanResult && scanResult.vulnerabilities.length > 0 && (
                    <span className="bg-red-950 text-rose-300 text-[9px] px-1 py-0.2 rounded font-bold border border-red-700/50 shrink-0">
                      {scanResult.vulnerabilities.length}
                    </span>
                  )}
                </button>
              </div>
            </div>

            {/* Display Mode Selection */}
            {centerTab === "assembly" && (
              <div className="flex-1 overflow-y-auto font-mono text-xs p-1.5 space-y-0.5 max-h-[380px] xl:max-h-[500px]">
                {/* Vulnerability Heatmap Controller Bar */}
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 p-2 mb-2 bg-[#1C202B] rounded-md border border-[#2D3139] text-xs font-sans select-none">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 select-none" />
                    <div>
                      <span className="font-semibold text-white block leading-tight">Vulnerability Risk Heatmap</span>
                      <span className="text-[10px] text-gray-500">Highlighting static routine jumps, APIs, and potential execution flows</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-3 self-end sm:self-auto">
                    {heatmapEnabled && scanResult && scanResult.vulnerabilities.length > 0 && (
                      <div className="flex items-center gap-1.5 text-[9px] hidden md:flex">
                        <span className="text-gray-500 uppercase font-bold">Severity:</span>
                        <div className="flex gap-1 font-semibold select-none">
                          <span className="px-1.5 py-0.2 rounded bg-red-950/45 text-red-400 border border-red-900/40" title="Critical bypass or overflow">Critical</span>
                          <span className="px-1.5 py-0.2 rounded bg-orange-950/45 text-orange-400 border border-orange-900/40" title="High risk exposure">High</span>
                          <span className="px-1.5 py-0.2 rounded bg-amber-950/45 text-amber-400 border border-amber-900/45" title="Medium severity">Medium</span>
                          <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700/40" title="Low integrity warning">Low</span>
                        </div>
                      </div>
                    )}

                    <label className="flex items-center gap-1.5 text-[11px] text-[#A6ABB7] cursor-pointer font-medium hover:text-white transition">
                      <input
                        type="checkbox"
                        checked={heatmapEnabled}
                        onChange={(e) => setHeatmapEnabled(e.target.checked)}
                        className="rounded border-[#3E4657] bg-slate-900 text-cyan-500 focus:ring-0 focus:ring-offset-0 w-3.5 h-3.5 cursor-pointer"
                        id="heatmap-toggle-checkbox"
                      />
                      <span>Active Overlay</span>
                    </label>
                  </div>
                </div>

                {/* Header columns */}
                <div className="grid grid-cols-12 gap-1 py-1.5 border-b border-[#282C36] text-[10px] text-[#828896] uppercase font-sans mb-1 select-none">
                  <div className="col-span-2 px-1">Memory Address</div>
                  <div className="col-span-2">Hex Bytes</div>
                  <div className="col-span-2 text-cyan-400 font-semibold">Mnemonic</div>
                  <div className="col-span-3">Arguments/Operands</div>
                  <div className="col-span-3">Disassembly Commentary</div>
                </div>

                {activeFile.disassembly
                  .filter(instr => {
                    if (!activeFilterSymbol) return true;
                    // Mock filter: isolated logic routine blocks simulation
                    if (activeFilterSymbol === "main") {
                      return parseInt(instr.address, 16) >= 0x4001A0 && parseInt(instr.address, 16) <= 0x4001F8;
                    }
                    return true;
                  })
                  .map((instr, idx) => {
                    const isCurrentRip = currentStep === idx;
                    const isSelected = selectedInstructionIdx === idx;

                    // Vulnerability mapping for this line
                    const lineVulns = heatmapEnabled ? (scanResult?.vulnerabilities.filter(v => v.address === instr.address) || []) : [];
                    const highestSeverity = lineVulns.reduce((highest, curr) => {
                      const ranks = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
                      if (!highest) return curr.severity;
                      return ranks[curr.severity] > ranks[highest] ? curr.severity : highest;
                    }, null as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null);

                    let heatmapBg = "";
                    let heatmapBorder = "";
                    let tooltipText = "";

                    if (highestSeverity === "CRITICAL") {
                      heatmapBg = "bg-red-500/10 hover:bg-rose-950/20";
                      heatmapBorder = "border-l-[3px] border-l-red-500 shadow-[inset_3px_0_0_rgba(239,68,68,0.25)]";
                      tooltipText = `CRITICAL: ${lineVulns.map(v => v.title).join(", ")}`;
                    } else if (highestSeverity === "HIGH") {
                      heatmapBg = "bg-orange-500/10 hover:bg-orange-950/20";
                      heatmapBorder = "border-l-[3px] border-l-orange-500 shadow-[inset_3px_0_0_rgba(249,115,22,0.15)]";
                      tooltipText = `HIGH: ${lineVulns.map(v => v.title).join(", ")}`;
                    } else if (highestSeverity === "MEDIUM") {
                      heatmapBg = "bg-yellow-950/10 hover:bg-yellow-950/15";
                      heatmapBorder = "border-l-[3px] border-l-amber-500";
                      tooltipText = `MEDIUM: ${lineVulns.map(v => v.title).join(", ")}`;
                    } else if (highestSeverity === "LOW") {
                      heatmapBg = "bg-slate-800/30 hover:bg-slate-800/40";
                      heatmapBorder = "border-l-[3px] border-l-slate-400";
                      tooltipText = `LOW: ${lineVulns.map(v => v.title).join(", ")}`;
                    }

                    const rowBgClass = isCurrentRip 
                      ? "bg-amber-950/30 text-amber-200" 
                      : isSelected 
                        ? "bg-slate-800 text-white" 
                        : highestSeverity 
                          ? `${heatmapBg} text-[#ABB2BF]` 
                          : "hover:bg-[#1C202B]/60 text-[#ABB2BF]";

                    const rowBorderClass = isCurrentRip 
                      ? "border-l-[3px] border-l-amber-500" 
                      : isSelected 
                        ? "border-l-[3px] border-l-cyan-400" 
                        : highestSeverity 
                          ? heatmapBorder 
                          : "border-l-[3px] border-l-transparent";
                    
                    return (
                      <div
                        key={idx}
                        onClick={() => setSelectedInstructionIdx(idx)}
                        title={tooltipText || undefined}
                        className={`grid grid-cols-12 gap-1 py-1 px-1 rounded transition select-all relative group cursor-pointer ${rowBgClass} ${rowBorderClass}`}
                      >
                        {/* Memory offset */}
                        <div className="col-span-2 text-gray-500 text-[11px] flex items-center gap-1.5">
                          {isCurrentRip && <span className="text-amber-400 text-[9px] animate-pulse">▶</span>}
                          {highestSeverity && (
                            <span 
                              className={`w-2 h-2 rounded-full shrink-0 ${
                                highestSeverity === "CRITICAL" ? "bg-rose-500 animate-ping" :
                                highestSeverity === "HIGH" ? "bg-orange-500 animate-pulse" :
                                highestSeverity === "MEDIUM" ? "bg-amber-400" : "bg-slate-400"
                              }`} 
                              title={tooltipText} 
                            />
                          )}
                          <span>{instr.address}</span>
                        </div>
 
                         {/* Dump representation */}
                         <div className="col-span-2 text-gray-600 text-[11px] truncate" title={instr.bytes}>
                           {instr.bytes || "90"}
                         </div>
 
                         {/* Interactive Mnemonic & Opcode triggers */}
                         <div className="col-span-2 text-cyan-400 font-semibold group-relative">
                           {renamingState?.idx === idx && renamingState?.type === "opcode" ? (
                             <input
                               type="text"
                               value={renameInput}
                               onChange={(e) => setRenameInput(e.target.value)}
                               onBlur={() => saveRename(idx)}
                               onKeyDown={(e) => e.key === "Enter" && saveRename(idx)}
                               autoFocus
                               className="bg-slate-900 text-white text-xs border border-cyan-500 rounded p-0.5 w-full uppercase"
                             />
                           ) : (
                             <span 
                               onDoubleClick={() => startRenaming(idx, "opcode", instr.opcode)}
                               className="cursor-pointer hover:bg-[#2C313C] px-0.5 rounded"
                               title="Double-click to customize opcode"
                             >
                               {instr.opcode}
                             </span>
                           )}
                         </div>
 
                         {/* Arguments / Instruction segment */}
                         <div className="col-span-3 text-white">
                           {renamingState?.idx === idx && renamingState?.type === "instruction" ? (
                             <input
                               type="text"
                               value={renameInput}
                               onChange={(e) => setRenameInput(e.target.value)}
                               onBlur={() => saveRename(idx)}
                               onKeyDown={(e) => e.key === "Enter" && saveRename(idx)}
                               autoFocus
                               className="bg-slate-900 text-white text-xs border border-cyan-500 rounded p-0.5 w-full"
                             />
                           ) : (
                             <span 
                               onDoubleClick={() => startRenaming(idx, "instruction", instr.instruction || "")}
                               className="cursor-pointer hover:bg-[#2C313C] px-0.5 rounded"
                               title="Double-click to customize args"
                             >
                               {instr.instruction}
                             </span>
                           )}
                         </div>
 
                         {/* Dynamic Assembly Comment block */}
                         <div className="col-span-3 text-emerald-500 text-[11px] italic truncate relative flex items-center justify-between">
                           {editingCommentIdx === idx ? (
                             <input
                               type="text"
                               value={commentInput}
                               onChange={(e) => setCommentInput(e.target.value)}
                               onBlur={() => saveComment(idx)}
                               onKeyDown={(e) => e.key === "Enter" && saveComment(idx)}
                               autoFocus
                               className="bg-slate-900 text-emerald-400 text-xs border border-[#2D3139] rounded p-0.5 w-full font-serif font-sans"
                             />
                           ) : (
                             <span 
                               onClick={() => startEditingComment(idx, instr.comment || "")}
                               className="truncate pr-4 cursor-pointer hover:underline flex-grow"
                             >
                               {instr.comment ? `; ${instr.comment}` : "; add comment..."}
                             </span>
                           )}
                           <span className="absolute right-1 opacity-0 group-hover:opacity-100 transition duration-150 text-[9px] bg-[#252B36] text-gray-400 px-1 rounded">edit</span>
                         </div>
                       </div>
                     );
                   })}
              </div>
            )}

            {centerTab === "graph" && (
              <div className="flex-1 bg-[#151922] p-4 overflow-auto flex flex-col items-center justify-start gap-4 select-none min-h-[380px] relative">
                
                {/* CFG Info Header & Interactive Search Nodes toolbar */}
                <div className="w-full max-w-2xl bg-[#1C202B] p-2.5 rounded-md border border-[#2B313F] flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 select-text select-none shrink-0 text-xs">
                  <div>
                    <span className="text-xs font-semibold text-cyan-400 uppercase font-mono block">Control Flow Graph (CFG) Explorer</span>
                    <span className="text-[10px] text-gray-500">Query or jump to specific instruction blocks by address/label.</span>
                  </div>

                  <div className="flex items-center gap-1.5 flex-1 md:max-w-xs relative">
                    <Search className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
                    <input 
                      type="text"
                      placeholder="Search nodes (e.g. main, gets, 0x4001A0)..."
                      value={cfgSearchQuery}
                      onChange={(e) => setCfgSearchQuery(e.target.value)}
                      className="bg-[#11141B] text-white border border-[#3B4252] rounded px-2 py-1 text-xs outline-none w-full focus:border-cyan-500 font-mono"
                      id="cfg-search-input"
                    />
                    {cfgSearchQuery && (
                      <button
                        onClick={() => setCfgSearchQuery("")}
                        className="text-[10px] text-gray-500 hover:text-white uppercase font-bold px-1 select-none"
                      >
                        Clear
                      </button>
                    )}
                  </div>
                </div>

                {/* Display Block Node Listing */}
                <div className="w-full flex flex-col items-center gap-4 relative">
                  {(() => {
                    const blocks = getCFGBlocks(activeFile.id);
                    const cleanQuery = cfgSearchQuery.trim().toLowerCase();

                    // Check if block matches
                    const isMatched = (block: any) => {
                      if (!cleanQuery) return false;
                      return (
                        block.name.toLowerCase().includes(cleanQuery) ||
                        block.address.toLowerCase().includes(cleanQuery) ||
                        block.instructions.some((inst: string) => inst.toLowerCase().includes(cleanQuery))
                      );
                    };

                    const matchedCount = blocks.filter(isMatched).length;

                    return (
                      <>
                        {cleanQuery && (
                          <div className="text-[10px] bg-cyan-950/50 text-cyan-400 px-3 py-1 rounded-full border border-cyan-900/40 select-none">
                            Found <strong className="text-white">{matchedCount}</strong> matching function node{matchedCount === 1 ? "" : "s"} for "{cfgSearchQuery}"
                          </div>
                        )}

                        {blocks.map((block, index) => {
                          const matched = isMatched(block);
                          return (
                            <React.Fragment key={block.id}>
                              {/* Node card */}
                              <div 
                                onClick={() => setSelectedCfgNode(block.id)}
                                className={`bg-[#1C212E] p-3 rounded-lg w-80 shadow-lg font-mono text-[11px] space-y-1 relative transition-all duration-300 border cursor-pointer hover:border-cyan-400 ${
                                  matched 
                                    ? "border-cyan-400 ring-2 ring-cyan-400/30 bg-[#1e2a3c] shadow-[0_0_15px_rgba(34,211,238,0.3)] scale-[1.02]" 
                                    : "border-[#2D3139]"
                                }`}
                                id={`cfg-node-${block.id}`}
                              >
                                <div className="absolute top-0 right-2 transform -translate-y-1/2 bg-[#252B36] text-gray-500 font-bold px-1.5 py-0.2 rounded text-[8px] uppercase tracking-wide border border-[#3e4657]">
                                  {block.type}
                                </div>
                                
                                <div className={`font-semibold mb-1 flex items-center gap-1.5 ${
                                  block.type === "start" ? "text-emerald-400" :
                                  block.type === "success" ? "text-cyan-400" :
                                  block.type === "failure" ? "text-rose-400" : "text-[#ABB2BF]"
                                }`}>
                                  <span className="w-1.5 h-1.5 rounded-full bg-current" />
                                  <span>{block.name}</span>
                                </div>

                                <div className="space-y-0.5 border-t border-slate-800/60 pt-1.5 mt-1.5 text-gray-400">
                                  {block.instructions.map((inst, i) => {
                                    const instMatched = cleanQuery && inst.toLowerCase().includes(cleanQuery);
                                    return (
                                      <div 
                                        key={i} 
                                        className={`px-1 py-0.2 rounded ${
                                          instMatched ? "bg-amber-500/10 text-amber-300 font-bold border-l-2 border-amber-500" : ""
                                        }`}
                                      >
                                        {inst}
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>

                              {/* Path connections layout edges */}
                              {index < blocks.length - 1 && block.connections.map((conn, cIdx) => (
                                <div key={cIdx} className="flex flex-col items-center select-none">
                                  <div className={`w-0.5 h-5 ${
                                    conn.color === "emerald" ? "bg-emerald-500/80" :
                                    conn.color === "rose" ? "bg-rose-500/80" :
                                    conn.color === "cyan" ? "bg-cyan-500/85" : "bg-slate-700"
                                  }`}></div>
                                  
                                  {conn.condition && (
                                    <span className={`text-[9px] px-1.5 py-0.2 rounded font-mono border ${
                                      conn.color === "emerald" ? "bg-[#102018] text-emerald-400 border-emerald-950" :
                                      conn.color === "rose" ? "bg-[#241214] text-rose-400 border-rose-950" :
                                      "bg-[#1E2533] text-[#9CA3AF] border-slate-800"
                                    }`}>
                                      {conn.condition}
                                    </span>
                                  )}

                                  <div className={`w-0.5 h-3.5 ${
                                    conn.color === "emerald" ? "bg-emerald-500/80" :
                                    conn.color === "rose" ? "bg-rose-500/80" :
                                    conn.color === "cyan" ? "bg-cyan-500/85" : "bg-slate-700"
                                  }`}></div>
                                </div>
                              ))}
                            </React.Fragment>
                          );
                        })}
                      </>
                    );
                  })()}
                </div>
              </div>
            )}

            {centerTab === "vulnerabilities" && (
              <div className="flex-1 bg-[#12151D] p-4 overflow-auto min-h-[380px] space-y-4">
                {/* Vulnerability Guard Dashboard */}
                {scanResult && (
                  <>
                    <div className="bg-[#191F2D] p-4 rounded-lg border border-[#2B354D] flex flex-col md:flex-row items-center justify-between gap-6">
                      <div className="flex items-center gap-4">
                        {/* Circular Score Rating representation */}
                        <div className="font-mono text-center flex flex-col items-center justify-center w-16 h-16 rounded-full border-4 border-dashed border-cyan-500/40 relative">
                          <span className={`text-lg font-bold ${
                            scanResult.metrics.securityScore > 80 ? "text-emerald-400" :
                            scanResult.metrics.securityScore > 50 ? "text-amber-400" : "text-rose-400"
                          }`}>
                            {scanResult.metrics.securityScore}%
                          </span>
                          <span className="text-[7px] text-gray-500 tracking-tighter uppercase font-sans font-bold">Health</span>
                        </div>

                        <div className="space-y-1">
                          <h3 className="text-white text-sm font-semibold flex items-center gap-2">
                            <span>Vulnerability Guard Metric</span>
                            <span className="text-[10px] bg-[#1E2533] text-cyan-400 px-1.5 py-0.2 rounded border border-slate-800">Static AST Sandbox</span>
                          </h3>
                          <p className="text-xs text-slate-400 leading-normal max-w-md">
                            Statically evaluated execution vectors to expose unbounded pointer buffering, hardcoded authentication credentials, and printf leakage points.
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 text-xs">
                        <div className="bg-[#241214] border border-red-950 px-2.5 py-1.5 rounded text-center min-w-[65px]">
                          <span className="text-rose-400 font-bold block text-sm">{scanResult.metrics.criticalCount}</span>
                          <span className="text-[9px] text-rose-500 font-medium font-sans">Critical</span>
                        </div>
                        <div className="bg-[#221712] border border-orange-950 px-2.5 py-1.5 rounded text-center min-w-[65px]">
                          <span className="text-orange-400 font-bold block text-sm">{scanResult.metrics.highCount}</span>
                          <span className="text-[9px] text-orange-500 font-medium font-sans">High</span>
                        </div>
                        <div className="bg-[#211B12] border border-yellow-950/60 px-2.5 py-1.5 rounded text-center min-w-[65px]">
                          <span className="text-amber-400 font-bold block text-sm">{scanResult.metrics.mediumCount}</span>
                          <span className="text-[9px] text-amber-500 font-medium font-sans">Medium</span>
                        </div>
                        <button
                          onClick={handleRunStaticScan}
                          className="bg-[#222834] hover:bg-cyan-600 border border-[#373E4D] hover:border-cyan-500 font-semibold text-white px-3 py-2 rounded text-xs flex items-center justify-center gap-1.5 transition whitespace-nowrap cursor-pointer"
                        >
                          <RefreshCw className="w-3 h-3 text-cyan-200" />
                          <span>Rescan</span>
                        </button>
                      </div>
                    </div>

                    {/* Vulnerabilities Details Grid */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-gray-400 uppercase tracking-wider font-semibold">Flagged Security Issues</span>
                        <span className="text-[10px] text-gray-500 font-mono">Module Target: {scanResult.fileName}</span>
                      </div>

                      {scanResult.vulnerabilities.length === 0 ? (
                        <div className="p-6 text-center bg-[#151D18] rounded border border-emerald-900/35 text-emerald-400 text-xs py-10">
                          <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-400 mb-2.5 opacity-90" />
                          <h4 className="font-bold mb-1">Pristine Security Score Calibrated</h4>
                          <p className="text-[#8CC29A] max-w-sm mx-auto">
                            Static path evaluations did not identify low-risk alignment discrepancies, memory leakage points, gets references, or plaintext API symbols!
                          </p>
                        </div>
                      ) : (
                        scanResult.vulnerabilities.map((vuln, vIdx) => {
                          const severityColors = {
                            CRITICAL: "bg-red-500/10 border-red-500/30 text-red-400 font-extrabold shadow-[0_0_8px_rgba(239,68,68,0.1)]",
                            HIGH: "bg-orange-500/10 border-orange-500/30 text-orange-400 font-bold",
                            MEDIUM: "bg-amber-500/10 border-amber-500/30 text-amber-400",
                            LOW: "bg-slate-500/10 border-slate-500/30 text-slate-300"
                          };

                          return (
                            <div 
                              key={vIdx}
                              className="bg-[#171A24] rounded-lg border border-[#272F41] p-3.5 space-y-3 hover:border-cyan-500/30 transition duration-150 select-text"
                            >
                              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2.5">
                                <div className="space-y-0.5">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className={`text-[9px] border px-2 py-0.5 rounded tracking-wide uppercase ${severityColors[vuln.severity]}`}>
                                      {vuln.severity}
                                    </span>
                                    <span className="text-white text-xs font-bold leading-tight">{vuln.title}</span>
                                  </div>
                                  <span className="text-[9px] text-[#A6ABB7] font-mono block">Category: {vuln.category}</span>
                                </div>

                                <div className="flex items-center gap-1.5 shrink-0 self-start sm:self-center select-none">
                                  {vuln.address && (
                                    <>
                                      <span className="text-[10px] font-mono text-cyan-400 uppercase bg-slate-900 border border-slate-800 px-1.5 py-0.5 rounded">
                                        Offset {vuln.address}
                                      </span>
                                      
                                      <button
                                        onClick={() => {
                                          setCenterTab("assembly");
                                          // Find the instruction index mapping this address
                                          const idx = activeFile.disassembly.findIndex(itm => itm.address === vuln.address);
                                          if (idx !== -1) {
                                            setSelectedInstructionIdx(idx);
                                          }
                                        }}
                                        className="text-[10px] bg-slate-800 hover:bg-cyan-600 border border-slate-700 hover:border-cyan-500 text-cyan-300 hover:text-white px-2.5 py-0.5 rounded transition font-sans font-semibold cursor-pointer"
                                      >
                                        Jump to Code
                                      </button>
                                    </>
                                  )}
                                </div>
                              </div>

                              <div className="space-y-1 bg-slate-950/45 p-2.5 rounded border border-slate-900/60 text-[11px] leading-relaxed">
                                <span className="text-[10px] text-[#8F98A7] font-bold block font-sans">Risk Explanation:</span>
                                <p className="text-slate-300">{vuln.explanation}</p>
                              </div>

                              <div className="space-y-1 bg-emerald-950/15 p-2.5 rounded border border-emerald-900/30 text-[11px] leading-relaxed">
                                <span className="text-[10px] text-emerald-400 font-bold block font-sans">Compliance Remediation:</span>
                                <p className="text-emerald-300 font-mono text-[10px] p-1 bg-black/35 rounded">{vuln.remediation}</p>
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </>
                )}
              </div>
            )}
          </div>

          {/* Center Bottom Layout Pane: Decompiler, Security Audit & AI Validation */}
          <div className="bg-[#13161C] border border-[#232731] rounded-lg flex flex-col overflow-hidden">
            <div className="bg-[#191D26] px-3 py-2 flex items-center justify-between border-b border-[#232731]">
              <div className="flex items-center gap-2 text-xs font-semibold text-white uppercase tracking-wider">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <span>AI Decompiler & Technical Debt Auditor</span>
              </div>
              <div className="flex items-center gap-2">
                {aiResponse && (
                  <div className="flex items-center gap-2 bg-[#212631] px-2 py-0.5 rounded border border-[#303746] text-[11px]">
                    <span className="text-[#8F94A2]">Remediation Code Quality:</span>
                    <span className="text-emerald-400 font-bold">{aiResponse.technicalDebtScore}/100</span>
                  </div>
                )}
                <span className="text-[10px] bg-purple-500/10 text-purple-400 px-1.5 py-0.5 rounded border border-purple-500/20 font-mono">Gemini-3.5-Flash</span>
              </div>
            </div>

            {/* Custom optimization instructions prompt */}
            <div className="p-3 bg-[#161922] border-b border-[#232731] flex flex-col md:flex-row items-stretch md:items-center gap-2.5">
              <div className="flex-1">
                <label className="block text-[10px] text-gray-500 uppercase tracking-wider font-semibold mb-1">Custom Analysis & Auditing Instructions</label>
                <input 
                  type="text"
                  placeholder="e.g. Identify pointer leak vectors, flag hardcoded hashes, specify return address mitigation variables..."
                  value={customPrompt}
                  onChange={(e) => {
                    setCustomPrompt(e.target.value);
                    if (showRefusalNotice) setShowRefusalNotice(false);
                  }}
                  className="bg-[#212631] text-xs text-white p-2 rounded border border-[#2D3443] outline-none w-full placeholder-gray-600 focus:border-cyan-500"
                />
              </div>
              <button
                onClick={triggerAICodeAnalysis}
                disabled={isAnalyzing}
                className="bg-purple-600 hover:bg-purple-700 font-semibold text-white text-xs px-4 py-2 rounded-md shadow-md transition flex items-center justify-center gap-2 self-end shrink-0 disabled:bg-purple-900disabled:text-gray-400 disabled:cursor-not-allowed cursor-pointer"
                id="analyze-trigger"
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-3.5 h-3.5" />
                    <span>Audit & Decompile</span>
                  </>
                )}
              </button>
            </div>

            {/* Security Refusal Overlay Notice for user awareness of ethical bound boundaries */}
            {showRefusalNotice && (
              <div className="m-3 p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg space-y-2">
                <div className="flex items-center gap-2 text-rose-400 font-bold text-xs uppercase font-sans">
                  <ShieldAlert className="w-4 h-4 text-rose-500" />
                  <span>Defensive Boundary Advisory (Refusal)</span>
                </div>
                <p className="text-xs text-[#E5E7EB]">
                  Sorry, I cannot fulfill this request. I am strictly forbidden from generating scripts, templates, or instructions designed to inspect, intercept, or decrypt encrypted third-party telecommunication payloads (such as end-to-end encrypted messaging services) or bypass authorization protocols on commercial devices.
                </p>
                <p className="text-xs text-slate-400 font-serif italic text-[11px]">
                  My binary analysis workspace is structured solely to assist in authorized software audits, defensive control flow reverse engineering, decompilation simulation, and correcting technical debt in custom applications.
                </p>
              </div>
            )}

            {/* AI Results Output Grid */}
            {aiResponse && (
              <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-[#232731]">
                
                {/* Decompiled C-like logic */}
                <div className="p-3 space-y-2">
                  <span className="text-[10px] text-cyan-400 uppercase tracking-wider font-semibold block">Decompiled Pseudocode Preview</span>
                  <pre className="bg-slate-950 p-2.5 rounded-md text-[11px] font-mono text-cyan-100 overflow-x-auto select-all max-h-[280px]">
                    {aiResponse.pseudocode}
                  </pre>
                  <p className="text-[11px] text-[#A3A9B6] leading-relaxed">
                    <strong className="text-white">Analysis Summary:</strong> {aiResponse.analysis}
                  </p>
                </div>

                {/* Remediation code and list of findings */}
                <div className="p-3 space-y-3">
                  <span className="text-[10px] text-amber-400 uppercase tracking-wider font-semibold block">Identified Technical Debt Findings</span>
                  
                  {/* High risk items list */}
                  <div className="space-y-1.5 max-h-[140px] overflow-y-auto pr-1">
                    {aiResponse.highRiskPaths && aiResponse.highRiskPaths.length > 0 ? (
                      aiResponse.highRiskPaths.map((finding, idx) => (
                        <div key={idx} className="p-2 rounded bg-[#20181A] border border-rose-950 text-[11px] space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-rose-400 uppercase tracking-tight flex items-center gap-1 text-[10px]">
                              <ShieldAlert className="w-3 h-3" />
                              {finding.riskType} Risk Severity
                            </span>
                            <span className="text-gray-500 font-mono text-[9px]">{finding.location}</span>
                          </div>
                          <p className="text-gray-300 font-sans leading-snug">{finding.finding}</p>
                          <p className="text-emerald-400 font-mono text-[9px] bg-slate-950/40 p-1 rounded">Suggested fix: {finding.resolution}</p>
                        </div>
                      ))
                    ) : (
                      <div className="p-3 bg-[#16201A] border border-emerald-950 text-emerald-400 text-xs rounded text-center">
                        ✔ No critical vulnerability or logic debt identified inside the filter workspace.
                      </div>
                    )}
                  </div>

                  {/* Remediation layout block */}
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[10px] text-[#828896]">
                      <span className="uppercase tracking-wider font-semibold">Remediation C Boilerplate</span>
                      <button 
                        onClick={() => {
                          navigator.clipboard.writeText(aiResponse.remediationCode);
                          alert("Remediation code snippet successfully copied to secure clipboard storage.");
                        }}
                        className="flex items-center gap-1 text-cyan-400 hover:text-white transition"
                      >
                        <Copy className="w-3 h-3" />
                        <span>Copy Code</span>
                      </button>
                    </div>
                    <pre className="bg-slate-950 p-2.5 rounded text-[10px] font-mono text-emerald-300 overflow-x-auto select-all max-h-[140px]">
                      {aiResponse.remediationCode}
                    </pre>
                  </div>
                </div>

              </div>
            )}
          </div>

        </div>

        {/* Right Pane: Stack, Register states & Debug logs (Span 3) */}
        <div className="xl:col-span-3 flex flex-col gap-1.5">
          
          {/* Registers and Stack Box */}
          <div className="bg-[#13161C] border border-[#232731] rounded-lg flex flex-col overflow-hidden">
            <div className="p-2.5 bg-[#191D26] border-b border-[#232731] flex items-center justify-between">
              <span className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <span>ISA Register State (x86_64)</span>
              </span>
            </div>

            <div className="p-2 grid grid-cols-2 gap-1.5 max-h-[220px] overflow-y-auto">
              {registers.map((reg, i) => (
                <div 
                  key={i} 
                  className={`p-1.5 rounded bg-[#161A22] border text-xs font-mono flex flex-col justify-between transition duration-200 ${
                    reg.changed ? "border-amber-600/60 bg-amber-950/10 shadow-sm" : "border-[#242A38]"
                  }`}
                  title={reg.description}
                >
                  <span className="text-[10px] text-[#828896] uppercase font-bold">{reg.name}</span>
                  <span className={`text-[11px] truncate font-semibold select-all ${reg.changed ? "text-amber-400" : "text-emerald-300"}`}>
                    {reg.value}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Stack Frame dump view */}
          <div className="bg-[#13161C] border border-[#232731] rounded-lg flex flex-col overflow-hidden flex-1 min-h-[180px]">
            <div className="p-2 bg-[#191D26] border-b border-[#232731] flex items-center justify-between">
              <span className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>Stack Segment Frame Dump</span>
              </span>
            </div>

            <div className="p-2 overflow-y-auto flex-1 font-mono text-[11px] space-y-1 max-h-[200px] xl:max-h-none">
              <div className="flex justify-between text-[9px] text-gray-500 uppercase pb-1 border-b border-slate-800">
                <span>Offset Pointer</span>
                <span>Val Word</span>
                <span>Description comment</span>
              </div>
              {stack.map((item, i) => (
                <div key={i} className="flex justify-between items-center py-1 border-b border-slate-900/45 hover:bg-slate-900">
                  <span className="text-[#8F94A2] text-[10px]">{item.offset}</span>
                  <span className="text-emerald-400 font-semibold select-all text-[10px]">{item.val}</span>
                  <span className="text-gray-500 text-[10px] truncate max-w-[130px]" title={item.comment}>
                    {item.comment}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Memory Hex Editor / Dump window */}
          <div className="bg-[#13161C] border border-[#232731] rounded-lg flex flex-col overflow-hidden max-h-[190px]">
            <div className="p-2 bg-[#191D26] border-b border-[#232731] text-xs font-semibold text-white uppercase tracking-wider">
              <span>Memory Hex Editor / Raw View</span>
            </div>
            <div className="p-2 bg-slate-950 text-[#ABB2BF] font-mono text-[10px] space-y-0.5 overflow-y-auto">
              <div className="text-gray-600 border-b border-gray-900 pb-1 mb-1">
                Offset Base  00 01 02 03 04 05 06 07  ASCII Dump
              </div>
              {HEX_DUMP_DATA.map((row, idx) => (
                <div key={idx} className="flex justify-between gap-1 select-all hover:bg-slate-900">
                  <span className="text-slate-600">{row.label}</span>
                  <span className="text-[#98C379]">{row.hex}</span>
                  <span className="text-slate-500">{row.ascii}</span>
                </div>
              ))}
            </div>
          </div>

          {/* logs and consoles terminal segment */}
          <div className="bg-[#13161C] border border-[#232731] rounded-lg flex flex-col overflow-hidden h-[180px]">
            <div className="p-2 bg-[#191D26] border-b border-[#232731] flex items-center justify-between text-xs font-semibold text-white uppercase tracking-wider">
              <span className="flex items-center gap-1">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>Diagnostic Logs & commands</span>
              </span>
              <button 
                onClick={() => setLogs([])}
                className="text-gray-500 hover:text-white text-[10px] uppercase font-sans font-medium"
              >
                Clear
              </button>
            </div>
            <div className="p-2 bg-slate-950 flex-1 overflow-y-auto text-[10px] font-mono space-y-1">
              {logs.map((log, idx) => {
                let color = "text-gray-400";
                if (log.startsWith("[SYSTEM]")) color = "text-cyan-400";
                if (log.startsWith("[ANALYSIS]")) color = "text-purple-400";
                if (log.startsWith("[DEBUGGER]")) color = "text-amber-400";
                if (log.startsWith("[SECURITY]")) color = "text-rose-400";
                if (log.startsWith("[ERROR]")) color = "text-rose-500 font-bold";

                return (
                  <div key={idx} className={color}>
                    {log}
                  </div>
                );
              })}
            </div>
          </div>

        </div>

      </div>

      {/* Persistent global warning callout on defensive scoping */}
      <footer className="bg-[#141822] border-t border-[#2D3139] px-4 py-2 text-[10px] text-gray-500 flex flex-col md:flex-row items-center justify-between gap-2.5">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
          <span>This workstation software is provided exclusively for static code quality review, security auditing, and analysis automation.</span>
        </div>
        <div>
          <span>Platform Service Active • UTC {new Date().toISOString().substring(0, 10)}</span>
        </div>
      </footer>
    </div>
  );
}
