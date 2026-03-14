use crate::ExpError;
use crate::runtime::memory::MemoryView;
use crate::runtime::process::Process;
use crate::winapi::CreateToolhelp32Snapshot;
use crate::winapi::MODULEENTRY32W;
use crate::winapi::Module32NextW;
use crate::winapi::raw::Module32FirstW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE32;
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;

pub struct Pattern {
    bytes: Vec<u8>,
    mask: Vec<bool>,
}

#[derive(Clone, Copy)]
pub enum PatternScanOption {
    Begin,
    End,
}

impl Pattern {
    pub fn from(pattern: impl ToString) -> Result<Self, ExpError> {
        let pattern = pattern.to_string();

        let parts = pattern.split_whitespace().collect::<Vec<&str>>();

        let mut bytes = vec![];
        let mut mask = vec![];

        for part in parts {
            if part == "?" || part == "??" || part == "*" {
                bytes.push(0);
                mask.push(false);
            } else {
                bytes
                    .push(u8::from_str_radix(part, 16).map_err(|_| ExpError::InvalidPatternError)?);
                mask.push(true);
            }
        }

        Ok(Pattern { bytes, mask })
    }

    pub fn scan<M: MemoryView>(
        &mut self,
        memory_reader: &M,
        base: *const u8,
        size: usize,
        opt: PatternScanOption,
    ) -> Option<Vec<*const u8>> {
        let mut matches = vec![];

        let data = memory_reader
            .read_bytes(base as u64, size)
            .expect("Unrecoverable error trying to scan pattern");

        let n = self.bytes.len();
        if size < n {
            return None;
        }
        for i in 0..=(size - n) {
            let mut found = true;

            for j in 0..n {
                if self.mask[j] && data[i + j] != self.bytes[j] {
                    found = false;
                    break;
                }
            }

            if found {
                unsafe {
                    match opt {
                        PatternScanOption::Begin => matches.push(base.add(i)),
                        PatternScanOption::End => matches.push(base.add(i + n)),
                    }
                }
            }
        }

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }

    /// returns an optional vector of matches and the module it was found in
    /// a remote process
    pub unsafe fn scan_all_loaded_modules<M: MemoryView>(
        &mut self,
        memory_reader: &M,
        process_name: impl ToString,
        opt: PatternScanOption,
    ) -> Option<Vec<(*const u8, String)>> {
        let procs = Process::get_from_name(process_name, PROCESS_ALL_ACCESS).unwrap();

        let mut matches: Vec<(*const u8, String)> = vec![];
        for proc in procs {
            let pid = proc.pid;
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
                    let scan_res = self
                        .scan(
                            memory_reader,
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
        }

        todo!()
    }
}
