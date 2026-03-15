use crate::ExpError;
use crate::runtime::memory::MemoryView;
use crate::runtime::memory::RemoteMemory;
use crate::winapi::CreateToolhelp32Snapshot;
use crate::winapi::HANDLE;
use crate::winapi::MODULEENTRY32W;
use crate::winapi::Module32NextW;
use crate::winapi::raw::Module32FirstW;
use log::trace;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE32;

pub struct Pattern {
    bytes: Vec<Option<u8>>,
    concrete_runs: Vec<ConcreteRun>,
    return_num: Option<usize>,
}

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
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            return_num: None,
        }
    }

    pub fn byte(mut self, b: u8) -> Self {
        self.bytes.push(Some(b));
        self
    }

    pub fn wildcard(mut self) -> Self {
        self.bytes.push(None);
        self
    }

    pub fn bytes(mut self, bytes: &[u8]) -> Self {
        for b in bytes {
            self.bytes.push(Some(*b));
        }
        self
    }

    pub fn str(mut self, s: &str) -> Self {
        for b in s.as_bytes() {
            self.bytes.push(Some(*b));
        }
        self
    }

    pub fn utf16(mut self, s: &str) -> Self {
        for c in s.encode_utf16() {
            let bytes = c.to_le_bytes();
            self.bytes.push(Some(bytes[0]));
            self.bytes.push(Some(bytes[1]));
        }
        self
    }

    pub fn wildcard_bytes(mut self, n: usize) -> Self {
        for _ in 0..n {
            self.bytes.push(None);
        }
        self
    }

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
    pub fn scan_number(mut self, n: usize) -> Self {
        self.return_num = Some(n);
        self
    }

    pub fn build(self) -> Pattern {
        let concrete_runs = ConcreteRun::build(&self.bytes).unwrap_or_default();

        Pattern {
            bytes: self.bytes,
            concrete_runs,
            return_num: self.return_num,
        }
    }
}

impl Pattern {
    pub fn builder() -> PatternBuilder { PatternBuilder::new() }

    pub fn scan<M: MemoryView>(
        &mut self,
        memory_reader: &M,
        base: *const u8,
        size: usize,
        opt: PatternScanOption,
    ) -> Option<Vec<*const u8>> {
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
                            == self.bytes.iter().map(|x| x.unwrap()).collect::<Vec<_>>()[..]
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
    /// returns an optional vector of matches and the module it was found in
    /// a remote process
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
                    run_bytes.push(b.unwrap());
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
