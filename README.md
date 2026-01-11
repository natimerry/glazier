# [WinExploiter]

This is an experimental, work-in-progress framework designed to simplify binary exploitation, dynamic reverse engineering, and memory manipulation on Windows.

The goal is to build ergonomic abstractions over the raw Windows API to facilitate rapid tool development from basic memory patchers to symbolic executation and analysis.

> **WARNING: HEAVY WIP**
> This library is currently in the prototyping stage. APIs are unstable, features are missing, and breaking changes will occur with every commit. 

### Tier 1: The Foundation (WinAPI & Memory)
- [ ] **WinAPI Abstractions:** Idiomatic Wrappers and shortenings of common tasks in binary exploitation (IAT scanning, finding module base etc)
  - [ ] Implementing bypasses for common protection methods
- [ ] **Binary Scanning:** High-performance pattern matching (AOB/Sig scanning) to locate functions and data structures at runtime.
- [ ] **Memory Manipulation:** Enabling users to write to memory and various safety / verification around it.

### Tier 2: Advanced Analysis
- [ ] **Symbolic Execution:** Integration with SMT solvers (similar to `angr`) to solve constraints on binary paths.
- [ ] **Hooking Engine:** Detouring and trampling functions dynamically for analysis or redirection.

### Tier 3: The "Moonshot"
- [ ] **Binary Emulation:** A partial emulator/lifter capable of executing binary slices in isolation (inspired by projects like *sogen*).
- [ ] **Taint Analysis:** Tracking data flow through registers and memory during execution to analyse VM sections.


## AI Usage Disclaimer
This project utilizes LLMs to accelerate tedious tasks, but the engineering is human.
AI is used to write docstrings, port verbose C structs/headers to Rust definitions, and help format CLI output in `src/bin/` for fast prototyping.

The core logic, memory abstractions, and architectural design are NOT vibecoded. All critical functionality is handwritten, understood, and manually implemented
