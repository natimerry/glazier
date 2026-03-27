# libwinexploit

`libwinexploit` is an experimental Rust library for Windows PE analysis, runtime process interaction, dynamic API resolution, and direct syscall-oriented research workflows.

> Warning
> This project is still heavy WIP. APIs are unstable, internal layouts may change quickly, and syscall-related paths still need broader validation.

## Current Scope

The crate currently covers four main areas:

- PE parsing for DOS headers, NT headers, section headers, and import/export analysis.
- Runtime helpers for process inspection, remote memory access, export walking, and in-memory PE work.
- Hooking and pattern-scanning utilities for locating code and patch targets.
- Stealth-oriented API access through dynamic resolution and `HellsGate` syscall wrappers.

## Notable Capabilities

### PE analysis

- Parse 64-bit PE structures from disk.
- Enumerate exports and imports.
- Inspect section metadata and headers.

### Runtime and memory work

- Open and inspect running processes.
- Read process memory and query process information.
- Patch memory in runtime PE helpers.
- Walk loaded module exports and runtime PE structures.

### Hooking and pattern scanning

- Scan memory with IDA-style byte patterns.
- Use hooking-oriented helpers from the `hooking` module.
- Benefit from recent pattern-scanning performance improvements and expanded docs in the runtime pattern code.

### Dynamic API resolution

With the `obfuscation` feature enabled, the crate generates bindings and resolves Win32 / NT APIs at runtime instead of relying only on static imports.

- Resolves function addresses dynamically.
- Locates source DLLs automatically.
- Reduces obvious import-table traces in the final binary.
- Reuses generated bindings for Win32 and NT calls.

`bindgen` does not carry over every Windows constant or preprocessor define, so pairing this crate with another source of Win32 constants can still be useful.

### Direct syscalls

With the `hells_gate` feature enabled, the crate exposes syscall-oriented wrappers for NT APIs.

- Provides `*HellsGate` variants for selected `Nt*` / `Zw*` functions.
- Resolves syscall numbers at runtime.
- Includes support for extended control-flow opcode handling in the export scanning path.
- Uses assembly helpers for calls with more than four arguments.

## Feature Flags

- `runtime`: enables runtime process and memory helpers.
- `obfuscation`: enables runtime API resolution and generated wrappers.
- `hells_gate`: enables direct syscall helpers.

Default features are `runtime`, `obfuscation`, and `hells_gate`.

## Project Layout

- `src/pe`: static PE parsing.
- `src/runtime`: runtime PE, process, export, and memory helpers.
- `src/hooking`: pattern scanning and hooking support.
- `src/consts.rs`: shared Windows-related constants exposed by the crate.
- `src/bin`: small examples and experiments for individual features.

## Getting Started

### Prerequisites

- Rust toolchain with `cargo`
- `x86_64` target environment
- The `phnt` submodule checked out

Initialize submodules before building:

```bash
git submodule update --init --recursive
```

### Build

```bash
cargo build
```

### Run examples

```bash
cargo run --bin read_pe_file
cargo run --bin hookpattern
cargo run --bin hells_gate
```

## Changelog

Recent project history is tracked in [CHANGELOG.md](CHANGELOG.md).

## AI Usage Disclaimer

LLMs are used to translate some C structs to Rust to save time and write tests and test binaries as code quality on those dont matter imo.

## License

License selection is not finalized yet.

## Safety

This project is for research and educational use. You are responsible for ensuring your usage complies with applicable law, policy, and authorization boundaries.
