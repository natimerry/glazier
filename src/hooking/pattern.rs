use crate::ExpError;
use crate::TH32CS_SNAPMODULE;
use crate::TH32CS_SNAPMODULE32;
use crate::hooking::trace_instructions::DisasmLayout;
use crate::hooking::trace_instructions::pattern_traces::log_pattern;
use crate::runtime::memory::MemoryView;
use crate::runtime::memory::RemoteMemory;
use crate::winapi::CreateToolhelp32Snapshot;
use crate::winapi::HANDLE;
use crate::winapi::MODULEENTRY32W;
use crate::winapi::Module32NextW;
use crate::winapi::raw::Module32FirstW;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Instruction;
use log::Level;
use log::debug;
use log::trace;

/// A compiled byte pattern supporting wildcards, used for scanning memory
/// regions.
///
/// Construct via [`Pattern::builder`] or [`PatternBuilder`]. Internally
/// pre-computes [`ConcreteRun`]s (contiguous non-wildcard spans ≥ 6 bytes) for
/// accelerated scanning via `memchr`.
pub struct Pattern {
    bytes: Vec<Option<u8>>,
    concrete_runs: Vec<ConcreteRun>,
    return_num: Option<usize>,
}

/// Controls whether scan results point to the start or end of each match.
#[derive(Clone, Copy)]
pub enum PatternScanOption {
    Begin,
    End,
}

pub struct PatternBuilder {
    bytes: Vec<Option<u8>>,
    return_num: Option<usize>,
}

impl PatternBuilder {
    // Creates a new empty builder
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            return_num: None,
        }
    }

    /// Appends a single concrete byte.
    pub fn byte(mut self, b: u8) -> Self {
        self.bytes.push(Some(b));
        self
    }

    /// Appends a single wildcard byte (`?`).
    pub fn wildcard(mut self) -> Self {
        self.bytes.push(None);
        self
    }

    /// Appends a slice of concrete bytes.
    pub fn bytes(mut self, bytes: &[u8]) -> Self {
        for b in bytes {
            self.bytes.push(Some(*b));
        }
        self
    }

    /// Appends the UTF-8 bytes of `s` as concrete bytes.
    pub fn str(mut self, s: &str) -> Self {
        for b in s.as_bytes() {
            self.bytes.push(Some(*b));
        }
        self
    }

    /// Appends `s` as little-endian UTF-16 concrete bytes.
    pub fn utf16(mut self, s: &str) -> Self {
        for c in s.encode_utf16() {
            let bytes = c.to_le_bytes();
            self.bytes.push(Some(bytes[0]));
            self.bytes.push(Some(bytes[1]));
        }
        self
    }
    /// Appends `n` wildcard bytes.
    pub fn wildcard_bytes(mut self, n: usize) -> Self {
        for _ in 0..n {
            self.bytes.push(None);
        }
        self
    }

    /// Parses an IDA-style hex pattern string (e.g. `"48 8B ? 05 ?? 00"`).
    ///
    /// `?` and `??` are treated as wildcards; all other tokens must be valid
    /// two-digit hex bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ExpError::InvalidPatternError`] if any token is not a valid
    /// hex byte.
    pub fn pattern(mut self, pattern: &str) -> Result<Self, ExpError> {
        for part in pattern.split_whitespace() {
            if part == "?" || part == "??" {
                self.bytes.push(None);
            } else {
                let b = u8::from_str_radix(part, 16).map_err(|_| ExpError::InvalidPatternError)?;
                self.bytes.push(Some(b));
            }
        }

        Ok(self)
    }

    /// Stops scanning after `n` matches have been found.
    pub fn scan_number(mut self, n: usize) -> Self {
        self.return_num = Some(n);
        self
    }

    /// Compiles the pattern, pre-computing concrete runs for accelerated
    /// scanning.
    pub fn build(self) -> Pattern {
        let concrete_runs = ConcreteRun::build(&self.bytes).unwrap_or_default();

        Pattern {
            bytes: self.bytes,
            concrete_runs,
            return_num: self.return_num,
        }
    }

    pub fn generate_wildcards(mut self) -> PatternBuilder {
        let bytes = self
            .bytes
            .iter()
            .map(|x| x.expect("Tried to build pattern on instructions with existing wildcards"))
            .collect::<Vec<u8>>();

        let mut pattern = Vec::<Option<u8>>::with_capacity(bytes.len());

        let mut decoder = Decoder::new(64, &bytes, DecoderOptions::NONE);
        let mut instr = Instruction::default();

        while decoder.can_decode() {
            let instruction_start = decoder.position();

            decoder.decode_out(&mut instr);

            let instruction_end = decoder.position();

            if instr.is_invalid() || instruction_end <= instruction_start {
                debug!("invalid instruction at byte offset +{instruction_start:#X}; stopping");
                break;
            }

            let pattern_start = pattern.len();

            pattern.extend(
                bytes[instruction_start..instruction_end]
                    .iter()
                    .copied()
                    .map(Some),
            );

            let offsets = decoder.get_constant_offsets(&instr);

            // op [rcx+50h]
            if offsets.has_displacement() {
                let start = pattern_start + offsets.displacement_offset();
                let end = start + offsets.displacement_size();

                // we need to None out this shit
                pattern[start..end].fill(None);
            }

            if offsets.has_immediate() {
                let start = pattern_start + offsets.immediate_offset();
                let end = start + offsets.immediate_size();

                pattern[start..end].fill(None);
            }

            // is this even possible?
            if offsets.has_immediate2() {
                let start = pattern_start + offsets.immediate_offset2();
                let end = start + offsets.immediate_size2();

                pattern[start..end].fill(None);
            }
        }
        log_pattern(
            "New pattern generated is",
            &pattern,
            64,
            0,
            DisasmLayout::MultiLine,
            Level::Info,
        );

        self.bytes = pattern;

        self
    }
}

impl Pattern {
    /// Returns a new [`PatternBuilder`].
    pub fn builder() -> PatternBuilder { PatternBuilder::new() }

    /// Scans a memory region for all matches of this pattern.
    ///
    /// Reads in 4 MiB chunks with overlap to handle matches spanning chunk
    /// boundaries.
    ///
    /// Returns `None` if the region is smaller than the pattern or no matches
    /// are found. Respects [`PatternBuilder::scan_number`] if set.
    pub fn scan<M: MemoryView>(
        &mut self,
        memory_reader: &M,
        base: *const u8,
        size: usize,
        opt: PatternScanOption,
    ) -> Option<Vec<*const u8>> {
        log_pattern(
            "Searching For:",
            &self.bytes,
            64,
            base as u64,
            DisasmLayout::MultiLine,
            Level::Debug,
        );

        let n = self.bytes.len();
        if size < n {
            return None;
        }

        const CHUNK: usize = 4 * 1024 * 1024;
        let overlap = n - 1;

        let mut buf = vec![0u8; (CHUNK + overlap).min(size)];
        let mut matches = Vec::new();
        let mut off = 0usize;

        let no_wildcards = self.bytes.iter().all(|b| b.is_some());
        let first_byte = self.bytes.iter().find_map(|b| *b);
        // if we can split this crap up
        if !self.concrete_runs.is_empty() {
            let anchor = &self.concrete_runs[0];
            let anchor_offset = anchor.offset;
            let anchor_bytes = &anchor.bytes;
            let anchor_first = anchor_bytes[0];

            let mut matches = Vec::new();
            let mut off = 0usize;

            'chunks: while off + n <= size {
                if self.return_num.is_some_and(|cap| matches.len() >= cap) {
                    break;
                }
                let to_read = (CHUNK + overlap).min(size - off);
                let got =
                    memory_reader.read_bytes_into(base as u64 + off as u64, &mut buf[..to_read]);
                if got < n {
                    break;
                }
                let data = &buf[..got];

                for pos in memchr::memchr_iter(anchor_first, data) {
                    // pos is where anchor_bytes[0] was found; pat_base is where pattern[0] sits
                    let Some(pat_base) = pos.checked_sub(anchor_offset) else {
                        continue;
                    };
                    if pat_base + n > got {
                        break;
                    }

                    let matched = self.concrete_runs.iter().all(|run| {
                        let s = pat_base + run.offset;
                        let e = s + run.bytes.len();
                        e <= got && data[s..e] == run.bytes[..]
                    });

                    if matched {
                        unsafe {
                            let addr = match opt {
                                PatternScanOption::Begin => base.add(off + pat_base),
                                PatternScanOption::End => base.add(off + pat_base + n),
                            };
                            matches.push(addr);
                        }
                        if self.return_num.is_some_and(|cap| matches.len() >= cap) {
                            break 'chunks;
                        }
                    }
                }
                off += got.saturating_sub(overlap);
            }

            return if matches.is_empty() {
                None
            } else {
                Some(matches)
            };
        }

        'chunks: while off + n <= size {
            if self.return_num.is_some_and(|cap| matches.len() >= cap) {
                break;
            }

            let to_read = (CHUNK + overlap).min(size - off);
            let got = memory_reader.read_bytes_into(base as u64 + off as u64, &mut buf[..to_read]);
            if got < n {
                break;
            }

            let data = &buf[..got];

            if let Some(b) = first_byte {
                for i in memchr::memchr_iter(b, data) {
                    if i + n > got {
                        break;
                    }

                    let matched = if no_wildcards {
                        data[i..i + n]
                            == self.bytes.iter().filter_map(|x| *x).collect::<Vec<_>>()[..]
                    } else {
                        self.bytes
                            .iter()
                            .enumerate()
                            .all(|(j, p)| p.map_or(true, |byte| data[i + j] == byte))
                    };

                    if matched {
                        unsafe {
                            let addr = match opt {
                                PatternScanOption::Begin => base.add(off + i),
                                PatternScanOption::End => base.add(off + i + n),
                            };
                            matches.push(addr);
                        }

                        if self.return_num.is_some_and(|cap| matches.len() >= cap) {
                            break 'chunks;
                        }
                    }
                }
            } else {
                // pattern is entirely wildcards
                for i in 0..=got - n {
                    unsafe {
                        let addr = match opt {
                            PatternScanOption::Begin => base.add(off + i),
                            PatternScanOption::End => base.add(off + i + n),
                        };
                        matches.push(addr);
                    }
                    if self.return_num.is_some_and(|cap| matches.len() >= cap) {
                        break 'chunks;
                    }
                }
            }

            off += got.saturating_sub(overlap);
        }

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }

    /// Scans all modules loaded in a remote process, returning each match
    /// paired with its module name.
    ///
    /// Enumerates modules via `CreateToolhelp32Snapshot` / `Module32FirstW` /
    /// `Module32NextW` and delegates to [`Pattern::scan`] per module.
    ///
    /// Returns `None` if the snapshot handle is invalid.
    ///
    /// # Safety
    ///
    /// `handle` must be a valid process handle with `PROCESS_VM_READ` access.
    /// `pid` must correspond to the process identified by `handle`.
    pub unsafe fn scan_all_loaded_modules(
        &mut self,
        handle: HANDLE,
        pid: u32,
        opt: PatternScanOption,
    ) -> Option<Vec<(*const u8, String)>> {
        let mut matches: Vec<(*const u8, String)> = vec![];
        let scanner = RemoteMemory::from_handle(handle);

        let pid = pid;
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap as i64 == -1 {
            return None;
        }

        let mut me = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..unsafe { std::mem::zeroed() }
        };
        if Module32FirstW(snap, &mut me) > 0 {
            loop {
                let szmodule = me.szModule;
                let len = szmodule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(szmodule.len());
                let mod_name = String::from_utf16_lossy(&szmodule[..len]);
                trace!("Scanning: {}", &mod_name);
                let scan_res = self
                    .scan(
                        &scanner,
                        me.modBaseAddr as *const u8,
                        me.modBaseSize as usize,
                        opt,
                    )
                    .unwrap_or_default();
                let final_vec = scan_res
                    .iter()
                    .map(|x| (*x, mod_name.clone()))
                    .collect::<Vec<_>>();
                matches.extend(final_vec);

                if Module32NextW(snap, &mut me) == 0 {
                    break;
                }
            }
        }
        Some(matches)
    }
}

struct ConcreteRun {
    offset: usize,
    bytes: Vec<u8>,
}

const MIN_RUN: usize = 6;

impl ConcreteRun {
    /// Build concrete runs from a pattern. Only keeps runs >= MIN_RUN.
    /// Returns None if no sufficiently large runs exist.
    pub fn build(bytes: &[Option<u8>]) -> Option<Vec<ConcreteRun>> {
        let mut runs = Vec::new();
        let mut i = 0;

        while i < bytes.len() {
            // Skip wildcards
            while i < bytes.len() && bytes[i].is_none() {
                i += 1;
            }

            if i >= bytes.len() {
                break;
            }

            let start = i;

            // find end of concrete segment
            while i < bytes.len() && bytes[i].is_some() {
                i += 1;
            }

            let len = i - start;

            if len >= MIN_RUN {
                let mut run_bytes = Vec::with_capacity(len);
                for b in &bytes[start..i] {
                    if let Some(byte) = b {
                        run_bytes.push(*byte);
                    }
                }

                runs.push(ConcreteRun {
                    offset: start,
                    bytes: run_bytes,
                });
            }
        }

        if runs.is_empty() { None } else { Some(runs) }
    }
}
