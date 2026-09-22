//! Direct instruction references to addresses and strings in local or remote
//! memory.

use crate::hooking::pattern::Pattern;
use crate::hooking::pattern::PatternScanOption;
use crate::pe::image_section_header::ImageSectionHeader;
use crate::runtime::NativePeRuntime;
use crate::runtime::TargetArchitecture;
use crate::runtime::memory::MemoryView;
use crate::runtime::pe32_runtime::PE32Runtime;
use crate::runtime::pe64_runtime::PE64Runtime;
use iced_x86::Decoder;
use iced_x86::DecoderError;
use iced_x86::DecoderOptions;
use iced_x86::Instruction;
use iced_x86::Mnemonic;
use iced_x86::OpKind;
use iced_x86::Register;
use std::collections::HashSet;
use std::ops::Range;

const CHUNK: usize = 64 * 1024;
const MEM_EXECUTE: u32 = 0x2000_0000;
const MEM_READ: u32 = 0x4000_0000;
const MEM_DISCARDABLE: u32 = 0x0200_0000;

/// Scans a loaded PE module for direct x86/x64 references.
///
/// Construct from a borrowed [`PE32Runtime`], [`PE64Runtime`], or
/// [`NativePeRuntime`]. Architecture, memory, and section ranges come from the
/// runtime. Strings are searched in readable sections; instructions and
/// patterns in readable executable sections. Discardable sections are skipped,
/// and all ranges are clipped to the module's image size. Keep the module
/// loaded and its readable sections accessible while scanning with
/// `LocalMemory`.
///
/// Decodes linearly, skipping invalid bytes one at a time; embedded data may be
/// interpreted as instructions. Recognizes RIP/EIP-relative and absolute memory
/// operands, immediate addresses, and direct branches. Does not track register
/// values or follow pointer chains. A memory reference identifies the operand's
/// address, not the pointer stored there. FS/GS-relative memory is excluded.
/// Results are unique instruction start addresses, in ascending order. An
/// unreadable boundary stops that section's scan; other sections are still
/// scanned.
pub struct XrefScanner<'a, M: MemoryView> {
    memory: &'a M,
    code: Vec<Range<u64>>,
    data: Vec<Range<u64>>,
    architecture: TargetArchitecture,
}

impl<'a, M: MemoryView> XrefScanner<'a, M> {
    /// Uses the runtime's architecture and module sections automatically.
    ///
    /// ```no_run
    /// use glazier::hooking::{pattern::Pattern, xref::XrefScanner};
    /// use glazier::runtime::NativePeRuntime;
    ///
    /// let runtime = NativePeRuntime::from_current_module()?;
    /// let scanner = XrefScanner::new(&runtime);
    /// let xrefs = scanner.scan_string("Something happened\0");
    /// let pattern = Pattern::builder().pattern("E8 ?? ?? ?? ??")?.build();
    /// let closest = scanner.scan_closest(&pattern, &xrefs);
    /// # Ok::<(), glazier::ExpError>(())
    /// ```
    pub fn new(runtime: impl Into<Self>) -> Self { runtime.into() }

    fn from_image(
        memory: &'a M,
        base: u64,
        size: u32,
        sections: &[ImageSectionHeader],
        architecture: TargetArchitecture,
    ) -> Self {
        let mut scanner = Self {
            memory,
            code: Vec::new(),
            data: Vec::new(),
            architecture,
        };
        let Some(end) = base.checked_add(size as u64) else {
            return scanner;
        };
        if architecture == TargetArchitecture::X86 && end > u32::MAX as u64 + 1 {
            return scanner;
        }
        for section in sections {
            if section.characteristics & MEM_READ == 0
                || section.characteristics & MEM_DISCARDABLE != 0
            {
                continue;
            }
            let rva = section.virtual_address;
            if rva >= size {
                continue;
            }
            let length = section
                .virtual_size
                .max(section.size_of_raw_data)
                .min(size - rva);
            if length == 0 {
                continue;
            }
            let start = base + rva as u64;
            let range = start..start + length as u64;
            if section.characteristics & MEM_EXECUTE != 0 {
                scanner.code.push(range.clone());
            }
            scanner.data.push(range);
        }
        scanner.code.sort_unstable_by_key(|range| range.start);
        scanner.data.sort_unstable_by_key(|range| range.start);
        scanner
    }

    /// Finds direct references to a known address, independently of strings.
    pub fn scan(&self, target: *const u8) -> Vec<*const u8> {
        self.scan_targets(&HashSet::from([target as u64]))
    }

    /// Finds references to all occurrences of the UTF-8 bytes of `text`.
    ///
    /// Matches the supplied bytes exactly; no terminator is added. Include
    /// `\0` in `text` when a terminating NUL is required. Empty text has no
    /// hits.
    pub fn scan_string(&self, text: &str) -> Vec<*const u8> {
        self.scan_string_pattern(Pattern::builder().str(text).build())
    }

    /// Like [`Self::scan_string`], using little-endian UTF-16 bytes.
    pub fn scan_utf16(&self, text: &str) -> Vec<*const u8> {
        self.scan_string_pattern(Pattern::builder().utf16(text).build())
    }

    /// Finds the pattern start closest to any xref in the module's code
    /// sections.
    ///
    /// Uses byte distance in either direction, with ties choosing the lower
    /// match address. Ignores pattern result limits and returns `None` for
    /// empty xrefs or no matches. The result is a signature address, not a
    /// call target.
    pub fn scan_closest(&self, pattern: &Pattern, xrefs: &[*const u8]) -> Option<*const u8> {
        self.code
            .iter()
            .filter_map(|range| {
                pattern.scan_closest(
                    self.memory,
                    range.start as *const u8,
                    (range.end - range.start) as usize,
                    xrefs,
                )
            })
            .min_by_key(|address| {
                let address = *address as usize;
                (
                    xrefs
                        .iter()
                        .map(|xref| address.abs_diff(*xref as usize))
                        .min()
                        .unwrap(),
                    address,
                )
            })
    }

    fn scan_string_pattern(&self, mut pattern: Pattern) -> Vec<*const u8> {
        let mut targets = HashSet::new();
        for range in &self.data {
            targets.extend(
                pattern
                    .scan(
                        self.memory,
                        range.start as *const u8,
                        (range.end - range.start) as usize,
                        PatternScanOption::Begin,
                    )
                    .unwrap_or_default()
                    .into_iter()
                    .map(|p| p as u64),
            );
        }
        self.scan_targets(&targets)
    }

    fn scan_targets(&self, targets: &HashSet<u64>) -> Vec<*const u8> {
        let mut hits = Vec::new();
        if targets.is_empty() {
            return hits;
        }
        for range in &self.code {
            hits.extend(self.scan_code(range.start, (range.end - range.start) as usize, targets));
        }
        hits.sort_unstable_by_key(|p| *p as usize);
        hits.dedup();
        hits
    }

    fn scan_code(&self, base: u64, size: usize, targets: &HashSet<u64>) -> Vec<*const u8> {
        let mut hits = Vec::new();
        let bitness = match self.architecture {
            TargetArchitecture::X86 => 32,
            TargetArchitecture::X64 => 64,
        };
        // The longest x86 instruction is 15 bytes. Look ahead so a chunk
        // boundary never splits an instruction; resume at the decoded boundary.
        let mut buffer = vec![0; size.min(CHUNK + 14)];
        let mut offset = 0;
        while offset < size {
            let requested = buffer.len().min(size - offset);
            let mut got = 0;
            while got < requested {
                let read = self.memory.read_bytes_into(
                    base + offset as u64 + got as u64,
                    &mut buffer[got..requested],
                );
                if read == 0 {
                    break;
                }
                got += read;
            }
            let mut decoder = Decoder::with_ip(
                bitness,
                &buffer[..got],
                base + offset as u64,
                DecoderOptions::NONE,
            );
            while decoder.can_decode() && decoder.position() < CHUNK {
                let start = decoder.position();
                let instruction = decoder.decode();
                if decoder.last_error() == DecoderError::NoMoreBytes {
                    break;
                }
                if instruction.is_invalid() {
                    decoder.set_position(start + 1).unwrap();
                    decoder.set_ip(base + offset as u64 + start as u64 + 1);
                    continue;
                }
                if references_any(&instruction, targets) {
                    hits.push((base as usize + offset + start) as *const u8);
                }
            }
            let consumed = decoder.position();
            if consumed == 0 {
                break;
            }
            offset += consumed;
            if got < requested && consumed >= got {
                break;
            }
        }
        hits
    }
}

impl<'a, M: MemoryView> From<&'a PE32Runtime<M>> for XrefScanner<'a, M> {
    fn from(runtime: &'a PE32Runtime<M>) -> Self {
        Self::from_image(
            &runtime.memory,
            runtime.module_base as u64,
            runtime.image_size,
            runtime.sections(),
            TargetArchitecture::X86,
        )
    }
}

impl<'a, M: MemoryView> From<&'a PE64Runtime<M>> for XrefScanner<'a, M> {
    fn from(runtime: &'a PE64Runtime<M>) -> Self {
        Self::from_image(
            &runtime.memory,
            runtime.module_base,
            runtime.image_size,
            runtime.sections(),
            TargetArchitecture::X64,
        )
    }
}

impl<'a, M: MemoryView> From<&'a NativePeRuntime<M>> for XrefScanner<'a, M> {
    fn from(runtime: &'a NativePeRuntime<M>) -> Self {
        match runtime {
            NativePeRuntime::Pe32(runtime) => runtime.into(),
            NativePeRuntime::Pe64(runtime) => runtime.into(),
        }
    }
}

fn references_any(instruction: &Instruction, targets: &HashSet<u64>) -> bool {
    (0..instruction.op_count()).any(|operand| {
        let address = match instruction.op_kind(operand) {
            OpKind::Memory => {
                if instruction.mnemonic() != Mnemonic::Lea
                    && matches!(instruction.memory_segment(), Register::FS | Register::GS)
                {
                    return false;
                }
                if instruction.is_ip_rel_memory_operand() {
                    instruction.ip_rel_memory_address()
                } else if instruction.memory_base() == Register::None
                    && instruction.memory_index() == Register::None
                {
                    instruction.memory_displacement64()
                } else {
                    return false;
                }
            }
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => instruction.immediate(operand),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                instruction.near_branch_target()
            }
            _ => return false,
        };
        targets.contains(&address)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExpError;
    use crate::winapi::HANDLE;

    // A virtual address space exercises remote-style addresses without ever
    // dereferencing them, and can force partial reads at instruction boundaries.
    struct Memory {
        base: u64,
        bytes: Vec<u8>,
        max_read: usize,
    }

    fn section(rva: usize, size: usize, characteristics: u32) -> ImageSectionHeader {
        ImageSectionHeader {
            name: [0; 8],
            virtual_size: size as u32,
            virtual_address: rva as u32,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics,
        }
    }

    impl Memory {
        fn new(size: usize) -> Self {
            Self {
                base: 0x1000_0000,
                bytes: vec![0x90; size],
                max_read: usize::MAX,
            }
        }

        fn ptr(&self, offset: usize) -> *const u8 { (self.base + offset as u64) as *const u8 }

        fn scanner(&self, size: usize, architecture: TargetArchitecture) -> XrefScanner<'_, Self> {
            XrefScanner::from_image(
                self,
                self.base,
                self.bytes.len().max(size) as u32,
                &[
                    section(0, size, MEM_READ | MEM_EXECUTE),
                    section(size, self.bytes.len().saturating_sub(size), MEM_READ),
                ],
                architecture,
            )
        }

        fn into_pe32(self, code_size: usize) -> PE32Runtime<Self> {
            PE32Runtime {
                module_base: self.base as u32,
                image_size: self.bytes.len() as u32,
                section_headers: vec![
                    section(0, code_size, MEM_READ | MEM_EXECUTE),
                    section(code_size, self.bytes.len() - code_size, MEM_READ),
                ],
                memory: self,
                dos_header: std::ptr::null(),
                nt_headers: std::ptr::null(),
                export_dir: std::ptr::null(),
                section_count: 2,
            }
        }

        fn into_pe64(self, code_size: usize) -> PE64Runtime<Self> {
            PE64Runtime {
                module_base: self.base,
                image_size: self.bytes.len() as u32,
                section_headers: vec![
                    section(0, code_size, MEM_READ | MEM_EXECUTE),
                    section(code_size, self.bytes.len() - code_size, MEM_READ),
                ],
                memory: self,
                dos_header: std::ptr::null(),
                nt_headers: std::ptr::null(),
                export_dir: std::ptr::null(),
                section_count: 2,
                teb: std::ptr::null_mut(),
                header_erased: false,
            }
        }

        fn lea(&mut self, offset: usize, target: usize) {
            self.bytes[offset..offset + 3].copy_from_slice(&[0x48, 0x8d, 0x0d]);
            let displacement = (target as i64 - (offset + 7) as i64) as i32;
            self.bytes[offset + 3..offset + 7].copy_from_slice(&displacement.to_le_bytes());
        }
    }

    impl MemoryView for Memory {
        fn read<T: Copy>(&self, _: u64) -> Result<T, ExpError> { unreachable!() }
        fn write<T: Copy>(&self, _: u64, _: T) -> Result<(), ExpError> { unreachable!() }
        fn get_handle(&self) -> Option<HANDLE> { None }
        fn read_bytes_into(&self, address: u64, buffer: &mut [u8]) -> usize {
            let Some(offset) = address.checked_sub(self.base).map(|n| n as usize) else {
                return 0;
            };
            let Some(bytes) = self.bytes.get(offset..) else {
                return 0;
            };
            let n = buffer.len().min(bytes.len()).min(self.max_read);
            buffer[..n].copy_from_slice(&bytes[..n]);
            n
        }
    }

    #[test]
    fn x64_string_references_and_nearest_signature() {
        let mut memory = Memory::new(256);
        memory.bytes[128..134].copy_from_slice(b"hello\0");
        memory.bytes[160..166].copy_from_slice(b"hello\0");
        memory.lea(16, 128);
        memory.lea(64, 160);
        memory.bytes[0..5].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        memory.bytes[72..77].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        memory.lea(180, 128); // Instruction-like bytes in data are not xrefs.
        let runtime = memory.into_pe64(96);
        let memory = &runtime.memory;
        let scanner = XrefScanner::new(&runtime);
        let xrefs = scanner.scan_string("hello\0");
        assert_eq!(xrefs, vec![memory.ptr(16), memory.ptr(64)]);
        assert_eq!(scanner.scan(memory.ptr(128)), vec![memory.ptr(16)]);
        let pattern = Pattern::builder()
            .pattern("E8 ?? ?? ?? ??")
            .unwrap()
            .scan_number(1)
            .build();
        assert_eq!(scanner.scan_closest(&pattern, &xrefs), Some(memory.ptr(72)));
        assert!(scanner.scan_string("absent").is_empty());
        assert!(scanner.scan_string("").is_empty());
        assert_eq!(scanner.scan_closest(&pattern, &[]), None);
    }

    #[test]
    fn x86_push_mov_and_absolute_lea() {
        let mut memory = Memory::new(128);
        let target = memory.ptr(96) as u32;
        let address = target.to_le_bytes();
        memory.bytes[0] = 0x68; // push imm32
        memory.bytes[1..5].copy_from_slice(&address);
        memory.bytes[5] = 0xb9; // mov ecx, imm32
        memory.bytes[6..10].copy_from_slice(&address);
        memory.bytes[10..12].copy_from_slice(&[0x8d, 0x15]); // lea edx, [disp32]
        memory.bytes[12..16].copy_from_slice(&address);
        memory.bytes[16..18].copy_from_slice(&[0x8b, 0x83]); // mov eax, [ebx+disp32]: not a fixed address
        memory.bytes[18..22].copy_from_slice(&address);
        memory.bytes[22..28]
            .copy_from_slice(&[0x64, 0xa1, address[0], address[1], address[2], address[3]]);
        let runtime = memory.into_pe32(28);
        let memory = &runtime.memory;
        assert_eq!(
            XrefScanner::new(&runtime).scan(memory.ptr(96)),
            vec![memory.ptr(0), memory.ptr(5), memory.ptr(10)]
        );
    }

    #[test]
    fn native_runtime_selects_the_decoder_from_its_pe_variant() {
        fn memory() -> Memory {
            let mut memory = Memory::new(128);
            // 0x40 is INC EAX in x86, but part of MOV's REX prefix in x64.
            memory.bytes[0..2].copy_from_slice(&[0x40, 0xb8]);
            let target = memory.ptr(64) as u32;
            memory.bytes[2..6].copy_from_slice(&target.to_le_bytes());
            memory.bytes[64..70].copy_from_slice(b"hello\0");
            memory
        }
        let pe32 = NativePeRuntime::Pe32(memory().into_pe32(6));
        let pe64 = NativePeRuntime::Pe64(memory().into_pe64(6));
        assert_eq!(
            XrefScanner::new(&pe32).scan_string("hello\0"),
            vec![0x1000_0001 as *const u8]
        );
        assert_eq!(
            XrefScanner::new(&pe64).scan_string("hello\0"),
            vec![0x1000_0000 as *const u8]
        );
    }

    #[test]
    fn module_search_uses_section_permissions_and_image_bounds() {
        let mut memory = Memory::new(256);
        memory.lea(16, 64);
        memory.lea(24, 40);
        memory.lea(128, 64);
        memory.lea(192, 64); // Outside SizeOfImage.
        memory.bytes[64..70].copy_from_slice(b"hello\0");
        memory.bytes[40..47].copy_from_slice(b"hidden\0");
        for offset in [0, 120, 152] {
            memory.bytes[offset..offset + 5].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        }
        let mut runtime = memory.into_pe64(32);
        runtime.image_size = 160;
        // Unsorted and duplicate sections must still return sorted unique xrefs.
        runtime.section_headers = vec![
            section(128, 128, MEM_READ | MEM_EXECUTE), // Clipped at image end.
            section(64, 64, MEM_READ),
            section(0, 32, MEM_READ | MEM_EXECUTE),
            section(0, 32, MEM_READ | MEM_EXECUTE),
            section(32, 32, MEM_READ | MEM_DISCARDABLE),
            section(32, 32, MEM_EXECUTE), // Not marked readable.
            section(192, 64, MEM_READ | MEM_EXECUTE),
        ];
        let scanner = XrefScanner::new(&runtime);
        let xrefs = scanner.scan_string("hello\0");
        assert_eq!(xrefs, vec![runtime.memory.ptr(16), runtime.memory.ptr(128)]);
        assert!(scanner.scan_string("hidden\0").is_empty());
        let pattern = Pattern::builder()
            .pattern("E8 ?? ?? ?? ??")
            .unwrap()
            .build();
        // Data at +120 is closer, but only executable sections count.
        assert_eq!(
            scanner.scan_closest(&pattern, &xrefs),
            Some(runtime.memory.ptr(0))
        );
        let absent = Pattern::builder().bytes(&[0xcc, 0xcc]).build();
        assert_eq!(scanner.scan_closest(&absent, &xrefs), None);
    }

    #[test]
    fn x64_immediates_signed_push_and_direct_call() {
        let mut memory = Memory::new(64);
        let target = 0xffff_ffff_8123_4567u64;
        memory.bytes[0..2].copy_from_slice(&[0x48, 0xb8]); // mov rax, imm64
        memory.bytes[2..10].copy_from_slice(&target.to_le_bytes());
        memory.bytes[10] = 0x68; // push sign-extended imm32
        memory.bytes[11..15].copy_from_slice(&(target as u32).to_le_bytes());
        memory.bytes[15..18].copy_from_slice(&[0x48, 0xc7, 0xc0]); // mov rax, sign-extended imm32
        memory.bytes[18..22].copy_from_slice(&(target as u32).to_le_bytes());
        memory.bytes[22..27].copy_from_slice(&[0xe8, 5, 0, 0, 0]);
        let scanner = memory.scanner(27, TargetArchitecture::X64);
        assert_eq!(
            scanner.scan(target as *const u8),
            vec![memory.ptr(0), memory.ptr(10), memory.ptr(15)]
        );
        assert_eq!(scanner.scan(memory.ptr(32)), vec![memory.ptr(22)]);
    }

    #[test]
    fn utf16_surrogate_pairs_and_backward_rip_reference() {
        let mut memory = Memory::new(128);
        let text = "hi🌍\0";
        let bytes: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        memory.bytes[..bytes.len()].copy_from_slice(&bytes);
        memory.lea(64, 0);
        let mut runtime = memory.into_pe64(96);
        runtime.section_headers = vec![
            section(0, 32, MEM_READ),
            section(64, 32, MEM_READ | MEM_EXECUTE),
        ];
        let memory = &runtime.memory;
        let scanner = XrefScanner::new(&runtime);
        assert_eq!(scanner.scan_utf16(text), vec![memory.ptr(64)]);
        assert!(scanner.scan_utf16("").is_empty());
    }

    #[test]
    fn chunk_boundary_partial_reads_and_truncated_tail() {
        let mut memory = Memory::new(CHUNK + 64);
        memory.max_read = 3;
        memory.lea(CHUNK - 3, CHUNK + 32);
        memory.lea(CHUNK + 4, CHUNK + 32);
        // A mov immediate containing bytes that resemble a reference must not
        // be scanned as overlapping instructions.
        memory.bytes[0..10].copy_from_slice(&[0x48, 0xb8, 0x68, 0, 0, 0, 0x10, 0x90, 0x90, 0x90]);
        memory.bytes[CHUNK + 11..CHUNK + 14].copy_from_slice(&[0x48, 0x8d, 0x0d]);
        let scanner = memory.scanner(CHUNK + 14, TargetArchitecture::X64);
        assert_eq!(
            scanner.scan(memory.ptr(CHUNK + 32)),
            vec![memory.ptr(CHUNK - 3), memory.ptr(CHUNK + 4)]
        );
        assert!(scanner.scan(memory.ptr(0)).is_empty());
        // A declared range extending beyond readable memory terminates safely.
        assert_eq!(
            memory
                .scanner(CHUNK + 128, TargetArchitecture::X64)
                .scan(memory.ptr(CHUNK + 32)),
            vec![memory.ptr(CHUNK - 3), memory.ptr(CHUNK + 4)]
        );
    }
}
