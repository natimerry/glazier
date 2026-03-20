# Changelog

This changelog summarizes recent repository changes based on GitHub commit diffs.

## Unreleased

### Added

- Added `patch_memory` support in the runtime PE helpers.
- Added and exported a dedicated `src/consts.rs` module for shared constants.
- Added more control-flow opcode handling in the Halos Gate export scanning path.
- Added inline documentation across runtime PE and pattern-scanning code.

### Changed

- Improved pattern-scanning performance with substantial updates in `src/hooking/pattern.rs`.
- Updated pattern scanning to better respect `return_num` on the non-fast path.
- Continued refining shared constants after the constants-module split.

## 2026-03-18

- `4e85a20` Update constants in `src/consts.rs`.
- `b4f648a` Add more documentation in `src/hooking/pattern.rs`.
- `e5f3bbf` Add basic pattern-scanning docs and fix `return_num` handling on the non-fast path.
- `1a81f09` Add documentation in `src/runtime/pe64_runtime.rs`.
- `03122a0` Further constants updates.
- `6c8aae2` Move shared constants into the new `src/consts.rs` module and wire exports accordingly.
- `bd9a2fe` Add `patch_memory` in runtime PE support.

## 2026-03-16

- `d56d699` Expand Halos Gate handling for additional control-flow opcodes in `src/runtime/exports.rs`.

## 2026-03-15

- `46ff62c` Improve pattern-scanning performance and update related runtime memory support.
- `bb5c08c` Apply follow-up fixes related to the pattern-scanning path.

## Notes

The entries above were derived from recent GitHub commits and file-level diffs on `master`.
