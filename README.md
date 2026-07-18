# JarTight

JarTight is a proactive, low-overhead security daemon designed to isolate browser sessions, local databases, and sensitive runtime credentials from info-stealers, memory dumpers, and unauthorized user-space processes. By combining Windows kernel-level telemetry via eBPF with a high-performance Rust monitoring daemon, JarTight detects and restricts suspicious memory and file access patterns before data exfiltration occurs.

## Architecture

The project is split into two primary components:
1. **`jartight-daemon` (Rust)**: The user-space orchestrator that runs as a high-privilege Windows service. It enforces application policies, monitors system behavior using ToolHelp API snapshots, manages telemetry states, and interacts with the eBPF subsystem.
2. **`jartight-ebpf` (C / ebpf-for-windows)**: The kernel-space telemetry probe. It hooks critical system calls (such as file object creation via `NtCreateFile`) to intercept access requests to sensitive asset locations directly inside the Windows kernel context.

---

## Features

- **Kernel-Level Telemetry Hooking**: Utilizes standalone eBPF bytecode to monitor file access operations directly within the kernel boundary.
- **Proactive Process Guard**: Scans user-space process trees for known offensive patterns, memory injection indicators, and unauthorized handle duplication.
- **Zero-Trust Access Policies**: Enforces strict process whitelisting for critical local databases (e.g., Chromium Login Data, Cookies, Web Data).
- **Asynchronous Ring Buffer Communication**: Leverages high-performance BPF ring buffers for lockless data transfer from kernel to user-space.

---

## Technical Roadmap

### Phase 1: Core Subsystems & Tooling (Current)
- [x] Establish high-performance Rust user-space daemon architecture.
- [x] Configure standalone eBPF target generation compatible with LLVM/Clang on Windows.
- [x] Implement initial kernel-to-user-space data contract via ring buffer definitions.
- [x] Integrate basic process state validation via Windows API snapshots.

### Phase 2: Kernel Integration & Enforcement
- [ ] Connect the Rust daemon layer to load and bind `jartight.bpf.o` using `ebpf-for-windows` API.
- [ ] Implement full parsing of `NtCreateFile` arguments inside the eBPF hook.
- [ ] Dynamically pass access enforcement results between kernel ring buffers and the daemon logic.
- [ ] Develop proactive handle stripping for unauthorized tools requesting access to browser paths.

### Phase 3: Advanced Protection & Hardening
- [ ] Add memory signature verification for running processes to detect packed or obfuscated info-stealer variants.
- [ ] Implement system service persistence and self-protection mechanisms for the Rust daemon.
- [ ] Introduce real-time post-quantum encrypted audit logs for all blocked exfiltration attempts.

---

## Prerequisites & Compilation

To build JarTight from source, ensure you have the following toolchains installed:
- **Rust**: `nightly` or `stable` MSRV 1.75+ (configured via `cargo`)
- **LLVM/Clang**: Version 16.0.0+ (required for generating the `bpf` target architecture)
- **Windows SDK**: For access to native platform headers and internal system schemas

### 1. Compile Kernel-Space Bytecode
Navigate to the eBPF subdirectory and compile the C source into BPF object code:
```powershell
cd jartight-ebpf
clang -target bpf -g -O2 -Wall -c jartight.bpf.c -o jartight.bpf.o

```

### 2. Verify User-Space Daemon

Return to the root directory and verify the Rust workspace integrity:

```powershell
cd ..
cargo check

```

### 3. Execution

The daemon must run with elevated privileges to access process tokens and interact with eBPF execution contexts:

```powershell
# Run with administrative privileges
$env:RUST_LOG="info"
cargo run --bin jartight-daemon

```

---

## License

This project is licensed under the Apache License 2.0. See the `LICENSE` file for details.

```