import { ProjectFile, RegisterState, FunctionSymbol } from "./types";

export const PRELOADED_FILES: ProjectFile[] = [
  {
    id: "firmware_auth",
    name: "firmware_auth.bin",
    size: "48.2 KB",
    type: "ELF 64-bit LSB executable, x86-64",
    symbolCount: 14,
    disassembly: [
      { address: "0x4001A0", bytes: "55", opcode: "push", instruction: "rbp", comment: "Save frame pointer" },
      { address: "0x4001A1", bytes: "48 89 E5", opcode: "mov", instruction: "rbp, rsp", comment: "Create stack frame" },
      { address: "0x4001A4", bytes: "48 81 EC 20 01 00 00", opcode: "sub", instruction: "rsp, 0x120", comment: "Allocate buffer space: 288 bytes" },
      { address: "0x4001AB", bytes: "48 8D 85 E0 FE FF FF", opcode: "lea", instruction: "rax, [rbp - 0x120]", comment: "Load address of userInput buffer" },
      { address: "0x4001B2", bytes: "48 89 C7", opcode: "mov", instruction: "rdi, rax", comment: "First argument for gets(): dest buffer" },
      { address: "0x4001B5", bytes: "E8 B6 FE FF FF", opcode: "call", instruction: "gets", comment: "WARNING: gets() does not check bounds! High-risk stack overflow." },
      { address: "0x4001BA", bytes: "48 8D 85 E0 FE FF FF", opcode: "lea", instruction: "rax, [rbp - 0x120]", comment: "Load input buffer pointer" },
      { address: "0x4001C1", bytes: "48 8D 35 38 10 00 00", opcode: "lea", instruction: "rsi, [rip + 0x1038]", comment: "Load hardcoded password string literal: 'AdminMasterKeys2026'" },
      { address: "0x4001C8", bytes: "48 89 C7", opcode: "mov", instruction: "rdi, rax", comment: "First argument for strcmp: input buffer" },
      { address: "0x4001CB", bytes: "E8 A0 FE FF FF", opcode: "call", instruction: "strcmp", comment: "Compare input with secret key" },
      { address: "0x4001D0", bytes: "85 C0", opcode: "test", instruction: "eax, eax", comment: "Check if comparison matches" },
      { address: "0x4001D2", bytes: "75 14", opcode: "jne", instruction: "0x4001E8", comment: "Jump if not equal to auth_failed callback" },
      { address: "0x4001D4", bytes: "C7 45 FC 01 00 00 00", opcode: "mov", instruction: "dword ptr [rbp - 4], 1", comment: "Set authState = 1 (Authorized)" },
      { address: "0x4001DB", bytes: "E8 50 FD FF FF", opcode: "call", instruction: "grant_elevated_access", comment: "Success handler" },
      { address: "0x4001E0", bytes: "EB 0E", opcode: "jmp", instruction: "0x4001F0", comment: "Jump over auth failure handler" },
      { address: "0x4001E2", bytes: "90", opcode: "nop", instruction: "", comment: "Alignment padding" },
      { address: "0x4001E8", bytes: "C7 45 FC 00 00 00 00", opcode: "mov", instruction: "dword ptr [rbp - 4], 0", comment: "Set authState = 0" },
      { address: "0x4001EF", bytes: "90", opcode: "nop", instruction: "", comment: "Alignment padding" },
      { address: "0x4001F0", bytes: "48 81 C4 20 01 00 00", opcode: "add", instruction: "rsp, 0x120", comment: "Restore stack pointer" },
      { address: "0x4001F7", bytes: "5D", opcode: "pop", instruction: "rbp", comment: "Restore frame pointer" },
      { address: "0x4001F8", bytes: "C3", opcode: "ret", instruction: "", comment: "Return to caller" }
    ],
    symbols: [
      { name: "main", address: "0x4001A0", size: 90, type: "Function" },
      { name: "gets", address: "0x400510", size: 0, type: "Import" },
      { name: "strcmp", address: "0x400520", size: 0, type: "Import" },
      { name: "grant_elevated_access", address: "0x400320", size: 145, type: "Function" },
      { name: "auth_failed", address: "0x4004B0", size: 45, type: "Function" },
      { name: "AdminMasterKeys2026", address: "0x401200", size: 20, type: "String" },
      { name: "secret_config_hash", address: "0x401214", size: 32, type: "String" },
      { name: "_init", address: "0x400100", size: 40, type: "Function" },
      { name: "deregister_tm_clones", address: "0x400140", size: 35, type: "Function" },
      { name: "register_tm_clones", address: "0x400170", size: 38, type: "Function" }
    ]
  },
  {
    id: "iot_sensor_driver",
    name: "iot_sensor_driver.ko",
    size: "18.5 KB",
    type: "ELF 64-bit LSB relocatable, kernel module",
    symbolCount: 8,
    disassembly: [
      { address: "0x000000", bytes: "55", opcode: "push", instruction: "rbp" },
      { address: "0x000001", bytes: "48 89 E5", opcode: "mov", instruction: "rbp, rsp" },
      { address: "0x000004", bytes: "48 8D 3D 00 00 00 00", opcode: "lea", instruction: "rdi, [rip]", comment: "Load syslog format target string" },
      { address: "0x00000B", bytes: "E8 00 00 00 00", opcode: "call", instruction: "printk", comment: "Format string leak possibility in debug mode" },
      { address: "0x000010", bytes: "C9", opcode: "leave", instruction: "", comment: "Release stack frame" },
      { address: "0x000011", bytes: "C3", opcode: "ret", instruction: "", comment: "Return" }
    ],
    symbols: [
      { name: "init_module", address: "0x000000", size: 18, type: "Function" },
      { name: "cleanup_module", address: "0x000020", size: 22, type: "Function" },
      { name: "printk", address: "0x000000", size: 0, type: "Import" },
      { name: "sensor_read_channel", address: "0x000080", size: 120, type: "Function" },
      { name: "calibration_data_offset", address: "0x000400", size: 256, type: "String" }
    ]
  },
  {
    id: "validate_token",
    name: "validate_token.o",
    size: "12.1 KB",
    type: "ELF 32-bit LSB relocatable, Intel 80386",
    symbolCount: 5,
    disassembly: [
      { address: "0x80483b0", bytes: "55", opcode: "push", instruction: "ebp" },
      { address: "0x80483b1", bytes: "89 E5", opcode: "mov", instruction: "ebp, esp" },
      { address: "0x80483b3", bytes: "83 EC 18", opcode: "sub", instruction: "esp, 24" },
      { address: "0x80483b6", bytes: "8B 45 08", opcode: "mov", instruction: "eax, [ebp + 8]" },
      { address: "0x80483b9", bytes: "8B 15 00 90 04 08", opcode: "mov", instruction: "edx, [0x08049000]" },
      { address: "0x80483bf", bytes: "39 D0", opcode: "cmp", instruction: "eax, edx" },
      { address: "0x80483c1", bytes: "74 07", opcode: "je", instruction: "0x80483ca", comment: "Jump if token validates correctly" },
      { address: "0x80483c3", bytes: "31 C0", opcode: "xor", instruction: "eax, eax" },
      { address: "0x80483c5", bytes: "EB 05", opcode: "jmp", instruction: "0x80483cc" },
      { address: "0x80483ca", bytes: "B0 01", opcode: "mov", instruction: "al, 1" },
      { address: "0x80483cc", bytes: "C9", opcode: "leave", instruction: "", comment: "Release stack frame" },
      { address: "0x80483cd", bytes: "C3", opcode: "ret", instruction: "", comment: "Return" }
    ],
    symbols: [
      { name: "check_integrity", address: "0x80483b0", size: 30, type: "Function" },
      { name: "rsa_verify_signature", address: "0x8048400", size: 280, type: "Function" },
      { name: "trusted_public_modulus", address: "0x8049040", size: 128, type: "String" }
    ]
  }
];

export const INITIAL_REGISTERS: RegisterState[] = [
  { name: "RAX", value: "0x00000001", description: "Accumulator register (function return state)" },
  { name: "RBX", value: "0x7FFF9820", description: "Base register (source base indexing)" },
  { name: "RCX", value: "0x00000000", description: "Counter register (loop iterative counters)" },
  { name: "RDX", value: "0x4001D0F8", description: "Data register (argument extension/offsetting)" },
  { name: "RSI", value: "0x00401200", description: "Source Index pointer (points to 'AdminMasterKeys...')" },
  { name: "RDI", value: "0x7FFF9850", description: "Destination Index pointer (points to localBuffer)" },
  { name: "RBP", value: "0x7FFF9970", description: "Base Frame pointer" },
  { name: "RSP", value: "0x7FFF9840", description: "Stack top pointer" },
  { name: "RIP", value: "0x004001B5", description: "Instruction pointer (next instruction: gets)" },
  { name: "EFLAGS", value: "0x00000246", description: "CPU flags: PF (Parity), ZF (Zero), IF (Interrupt Enable)" }
];

export const INITIAL_STACK = [
  { offset: "+0x00", val: "0x7FFF99A0", comment: "Saved Previous RBP" },
  { offset: "+0x08", val: "0x004008FF", comment: "Return Address into __libc_start_main+120" },
  { offset: "+0x10", val: "0x00000001", comment: "argc value" },
  { offset: "+0x18", val: "0x7FFF9AA8", comment: "argv pointer array" },
  { offset: "+0x20", val: "0x41414141", comment: "'AAAA' buffer overflow target chunk" },
  { offset: "+0x28", val: "0x41414141", comment: "'AAAA' buffer overflow input stream segment" },
  { offset: "+0x30", val: "0x00000000", comment: "Null terminator buffer closure" }
];

export const HEX_DUMP_DATA = [
  { label: "0x004001A0", hex: "55 48 89 E5 48 81 EC 20 01 00 00 48 8D 85 E0 FE", ascii: "UH..H.. ...H..." },
  { label: "0x004001B0", hex: "FF FF 48 89 C7 E8 B6 FE FF FF 48 8D 85 E0 FE FF", ascii: "..H.......H...." },
  { label: "0x004001C0", hex: "FF 48 8D 35 38 10 00 00 48 89 C7 E8 A0 FE FF FF", ascii: ".H.58...H......" },
  { label: "0x004001D0", hex: "85 C0 75 14 C7 45 FC 01 00 00 00 E8 50 FD FF FF", ascii: "..u..E......P..." },
  { label: "0x004001E0", hex: "EB 0E 90 C7 45 FC 00 00 00 00 90 48 81 C4 20 01", ascii: "....E......H.. ." },
  { label: "0x004001F0", hex: "00 00 5D C3 00 00 00 00 00 00 00 00 00 00 00 00", ascii: "..]............" }
];
