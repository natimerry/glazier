# libwinexploit

An experimental Rust framework for Windows binary analysis and manipulation with a focus on stealthy API resolution and low-level system interactions.

> **WARNING: HEAVY WIP**  
> This library is in active development. APIs are unstable, features are incomplete, and breaking changes occur frequently. Testing coverage is limited, especially for syscall functionality.

## What It Does

**libwinexploit** provides Rust abstractions for working with Windows binaries at both static and runtime levels, with built-in support for evasive API calling techniques commonly used in security research and binary analysis.

### Current Features

#### PE Binary Analysis
- Parse and analyze PE (Portable Executable) file structures
- Extract and enumerate import/export tables
- Inspect section headers and metadata

#### Process Interaction
- Open and interact with running processes
- Read process memory and structures
- Query process information

#### Dynamic API Resolution (`obfuscation` feature)
Instead of static linking like the `windows-sys` crate, this feature enables **fully dynamic API resolution at runtime**:

- Automatically generates type-safe Rust bindings for WinAPI and NT functions
- Resolves function addresses dynamically without import table entries
- Locates source DLLs automatically (e.g., `kernel32.dll`, `ntdll.dll`)
- Finds `LoadLibrary` from the in-memory `kernel32.dll` image
- Loads required DLLs and scans for function pointers
- No manual typedef or signature definitions required from the user

This technique avoids leaving static import traces and makes API usage harder to detect through static analysis.

#### Direct Syscalls (`hells_gate` feature)
For maximum stealth when calling NT-level functions:

- Provides `*HellsGate` function variants for `Nt*` and `Zw*` APIs
- Automatically finds System Service Numbers (SSNs) at runtime
- Executes syscalls directly, bypassing user-mode hooks
- Uses the same type signatures as standard NT functions
- Includes hand-written assembly thunks for handling 5+ argument syscalls
- **Note:** Testing is very limited at this stage

## Feature Flags

- `obfuscation` - Enable dynamic API resolution instead of static imports
- `hells_gate` - Enable direct syscall execution for NT functions

## Usage Example

```rust
use libwinexploit::prelude::*;

// With obfuscation feature: dynamically resolves CreateFileW at runtime
#[cfg(feature = "obfuscation")]
let handle = CreateFileW(/* args */); 

// With hells_gate feature: calls NtCreateFile via direct syscall
#[cfg(feature = "hells_gate")]
let status = NtCreateFileHellsGate(/* args */);
```

## Architecture

The project uses compile-time code generation to produce Rust bindings based on enabled features. When `obfuscation` is enabled, generated code includes dynamic resolution logic. When `hells_gate` is enabled, SSN discovery and syscall invocation code is automatically woven into NT function wrappers.

## Git Submodules

This project depends on the [phnt](https://github.com/winsiderss/phnt) headers for accurate Windows internal structures:

```bash
git submodule update --init --recursive
```

## AI Usage Disclaimer

This project uses LLMs to accelerate repetitive tasks like generating docstrings, porting C struct definitions to Rust, and formatting CLI output. **Core logic, memory abstractions, API resolution mechanisms, and syscall handling are manually implemented and not AI-generated.**

## Roadmap

Future development may include:
- Hooking and function detouring
- Pattern scanning (AOB/signature search)
- Memory manipulation utilities
- Symbolic execution integration
- Binary emulation capabilities

## License

MIT most probably ig havent decided yet

***

**For research and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.**
