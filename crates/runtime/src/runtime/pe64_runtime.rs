use crate::ExpError;
use crate::containing_record;
use crate::memory::LocalMemory;
use crate::memory::MemoryView;
use crate::memory::RemoteMemory;
use crate::pe::export_address_table::ImageExportDirectory;
use crate::pe::image_dos_header::ImageDosHeader;
use crate::pe::image_nt_header::IMAGE_DIRECTORY_ENTRY_EXPORT;
use crate::pe::image_nt_header::ImageNtHeaders64;
use crate::pe::image_section_header::ImageSectionHeader;
use crate::utils::get_peb;
use crate::utils::get_teb;
use libwinexploit_bindings::HANDLE;
use libwinexploit_bindings::LDR_DATA_TABLE_ENTRY;
use libwinexploit_bindings::LIST_ENTRY;
use libwinexploit_bindings::NtQueryInformationProcess;
use libwinexploit_bindings::PEB;
use libwinexploit_bindings::PROCESS_BASIC_INFORMATION;
use libwinexploit_bindings::TEB;
use std::mem::offset_of;

// Use manual PEB_LDR_DATA definition because bindgen generates incomplete
// structs when running on non-Windows hosts (Linux/macOS), even when
// cross-compiling to Windows
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[allow(nonstandard_style)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: *mut std::ffi::c_void,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: *mut std::ffi::c_void,
    pub ShutdownInProgress: u8,
    pub ShutdownThreadId: *mut std::ffi::c_void,
}

pub struct PE64Runtime<M: MemoryView> {
    pub memory: M,
    pub teb: *mut TEB,

    /// Base address of the loaded module
    pub module_base: u64,

    /// Pointer to IMAGE_DOS_HEADER
    pub dos_header: *const ImageDosHeader,

    /// Pointer to IMAGE_NT_HEADERS64
    pub nt_headers: *const ImageNtHeaders64,

    /// Pointer to the section headers array
    pub section_headers: Vec<ImageSectionHeader>,

    /// Number of sections
    pub section_count: u16,

    /// Pointer to export directory (if present)
    pub export_dir: *const ImageExportDirectory,

    /// Image size
    pub image_size: u32,

    /// Whether we have erased the PE header (for heuristic evasion)
    pub header_erased: bool,
}

impl PE64Runtime<RemoteMemory> {
    /// Returns the export directory of a remote process's main module (first
    /// entry in the PEB `InMemoryOrderModuleList`).
    ///
    /// Queries the remote [`PEB`] via `NtQueryInformationProcess`, reads
    /// [`PEB_LDR_DATA`], and takes the first [`LDR_DATA_TABLE_ENTRY`]
    /// without walking the full list. Delegates to
    /// [`Self::from_base_address_remote`] for PE parsing.
    ///
    /// # Errors
    ///
    /// - [`ExpError::RuntimeError`] — `NtQueryInformationProcess` failed.
    /// - Any [`ExpError`] from [`RemoteMemory::read`] on cross-process read
    ///   failure.
    ///
    /// Requires `handle` to have `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`
    /// access.
    pub fn from_handle(handle: HANDLE) -> Result<Self, ExpError> {
        let memory = RemoteMemory { handle };

        // Get basic process info to find PEB base
        let mut process_info: PROCESS_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        let _status = unsafe {
            NtQueryInformationProcess(
                handle,
                0,
                &mut process_info as *mut _ as *mut _,
                core::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                core::ptr::null_mut(),
            )
        };

        let peb_base = process_info.PebBaseAddress as u64;

        // Read PEB from remote process
        let peb = memory.read::<PEB>(peb_base)?;
        let ldr_ptr = peb.Ldr as u64;
        let ldr = memory.read::<PEB_LDR_DATA>(ldr_ptr)?;

        // Walk InMemoryOrderModuleList to get first entry (the main module)
        let first_flink = ldr.InMemoryOrderModuleList.Flink as u64;

        let entry_addr = first_flink - offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) as u64;
        let entry = memory.read::<LDR_DATA_TABLE_ENTRY>(entry_addr)?;
        let module_base = entry.DllBase as u64;

        Self::from_base_address_remote(memory, module_base)
    }

    /// Locates a module in a remote process by walking the PEB module list and
    /// returns its parsed export directory.
    ///
    /// Queries the remote [`PEB`] via `NtQueryInformationProcess`, walks
    /// `InMemoryOrderModuleList`, and matches each entry's full DLL path
    /// against `dll_name` (case-insensitive substring). On match, delegates
    /// to [`Self::from_base_address_remote`].
    ///
    /// # Arguments
    ///
    /// * `handle` - Target process handle; requires `PROCESS_QUERY_INFORMATION
    ///   | PROCESS_VM_READ`.
    /// * `dll_name` - Case-insensitive substring matched against each module's
    ///   full path (e.g. `"ntdll"` matches `C:\Windows\System32\ntdll.dll`).
    ///
    /// # Errors
    ///
    /// - [`ExpError::RuntimeError`] — `NtQueryInformationProcess` failed.
    /// - [`ExpError::ExportError`] — no loaded module matched `dll_name`.
    /// - Any [`ExpError`] from [`RemoteMemory::read`] on cross-process read
    ///   failure.
    pub fn from_module_remote(handle: HANDLE, dll_name: impl ToString) -> Result<Self, ExpError> {
        let memory = RemoteMemory { handle };
        let target_name = dll_name.to_string().to_lowercase();

        let mut process_info: PROCESS_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                0,
                &mut process_info as *mut _ as *mut _,
                core::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                core::ptr::null_mut(),
            )
        };

        if status == -1 {
            return Err(ExpError::RuntimeError(
                "Failed to NtQueryInformationProcess".to_string(),
            ));
        }

        let peb_base = process_info.PebBaseAddress as u64;
        let peb = memory.read::<PEB>(peb_base)?;
        let ldr_ptr = peb.Ldr as u64;
        let ldr = memory.read::<PEB_LDR_DATA>(ldr_ptr)?;

        let head_addr = ldr_ptr + offset_of!(PEB_LDR_DATA, InMemoryOrderModuleList) as u64;
        let mut curr_flink = ldr.InMemoryOrderModuleList.Flink as u64;

        loop {
            if curr_flink == head_addr {
                break;
            }

            let entry_addr =
                curr_flink - offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) as u64;
            let entry = memory.read::<LDR_DATA_TABLE_ENTRY>(entry_addr)?;

            let buf_ptr = entry.FullDllName.Buffer as u64;
            let buf_len = (entry.FullDllName.Length / 2) as usize;

            if buf_ptr != 0 && buf_len > 0 {
                let mut wide_buf = vec![0u16; buf_len];
                for i in 0..buf_len {
                    wide_buf[i] =
                        memory.read::<u16>(buf_ptr + i as u64 * size_of::<u16>() as u64)?;
                }
                let name = String::from_utf16_lossy(&wide_buf).to_lowercase();
                if name.contains(&target_name) {
                    let module_base = entry.DllBase as u64;
                    return Self::from_base_address_remote(memory, module_base);
                }
            }

            let next_entry = memory.read::<LIST_ENTRY>(curr_flink)?;
            curr_flink = next_entry.Flink as u64;
        }

        Err(ExpError::ExportError(format!(
            "Module not found: {}",
            target_name
        )))
    }

    fn from_base_address_remote(memory: RemoteMemory, module_base: u64) -> Result<Self, ExpError> {
        let dos_header = memory.read::<ImageDosHeader>(module_base)?;
        let nt_headers_addr = module_base + dos_header.nt_headers_offset() as u64;
        let nt_headers = memory.read::<ImageNtHeaders64>(nt_headers_addr)?;

        let section_count = nt_headers.file_header.number_of_sections;
        let section_headers_addr =
            nt_headers_addr + core::mem::size_of::<ImageNtHeaders64>() as u64;
        let mut section_headers = Vec::with_capacity(section_count as usize);

        for index in 0..section_count {
            section_headers.push(memory.read::<ImageSectionHeader>(
                section_headers_addr
                    + index as u64 * core::mem::size_of::<ImageSectionHeader>() as u64,
            )?);
        }

        let export_rva =
            nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;

        let export_dir_addr = if export_rva != 0 {
            module_base + export_rva as u64
        } else {
            0
        };

        let image_size = nt_headers.optional_header.size_of_image;

        // HACK: We leak memory header but eh
        let dos_header = Box::into_raw(Box::new(dos_header)) as *const ImageDosHeader;
        let nt_headers = Box::into_raw(Box::new(nt_headers)) as *const ImageNtHeaders64;
        let export_dir = export_dir_addr as *const ImageExportDirectory;

        Ok(Self {
            memory,
            teb: core::ptr::null_mut(),
            module_base,
            dos_header,
            nt_headers,
            section_headers,
            section_count,
            export_dir,
            image_size,
            header_erased: false,
        })
    }

    pub fn patch_memory(&self, address: u64, bytes: &[u8]) -> Result<(), ExpError> {
        self.memory.write_bytes(address, bytes)
    }
}
impl PE64Runtime<LocalMemory> {
    /// Returns the export directory of the current process's main module via
    /// the in-process PEB.
    ///
    /// Reads the TEB directly, walks to `PEB.Ldr.InMemoryOrderModuleList`, and
    /// takes the first [`LDR_DATA_TABLE_ENTRY`] without cross-process
    /// reads. Delegates to [`Self::from_base_address`] for PE parsing.
    ///
    /// # Errors
    ///
    /// - [`ExpError::ExportError`] — TEB or PEB pointer is null.
    /// - Any [`ExpError`] from [`Self::from_base_address`].
    pub fn from_current_module() -> Result<Self, ExpError> {
        unsafe {
            let teb = get_teb();
            if teb.is_null() {
                return Err(ExpError::ExportError("TEB is null".to_string()));
            }

            let peb = get_peb();
            if peb.is_null() {
                return Err(ExpError::ExportError("PEB is null".to_string()));
            }

            let ldr = (*peb).Ldr;
            let head = &mut *ldr.cast::<u8>().add(0x20).cast::<LIST_ENTRY>();
            let first = head.Flink;

            let entry = containing_record!(first, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            let module_base = (*entry).DllBase as u64;

            Self::from_base_address(teb, module_base)
        }
    }

    pub fn override_size_of_image(&mut self, new_size: u32) -> Result<(), ExpError> {
        if self.header_erased {
            return Err(ExpError::ExportError(
                "Cannot override size of image after header is erased".to_string(),
            ));
        }

        unsafe {
            let mut old_protect = 0;
            if self.memory.virtual_protect(
                self.nt_headers as *mut u8,
                core::mem::size_of::<ImageNtHeaders64>(),
                crate::PAGE_READWRITE,
                &mut old_protect,
            ) == 0
            {
                return Err(ExpError::RuntimeError(
                    "Failed to make NT headers writable".to_string(),
                ));
            }

            let nt_headers_mut = self.nt_headers as *mut ImageNtHeaders64;
            (*nt_headers_mut).optional_header.size_of_image = new_size;

            let mut restore_protect = 0;
            self.memory.virtual_protect(
                self.nt_headers as *mut u8,
                core::mem::size_of::<ImageNtHeaders64>(),
                old_protect,
                &mut restore_protect,
            );

            let teb = get_teb();
            if teb.is_null() {
                return Err(ExpError::ExportError("TEB is null".to_string()));
            }

            let peb = get_peb();
            if peb.is_null() {
                return Err(ExpError::ExportError("PEB is null".to_string()));
            }

            let ldr = (*peb).Ldr;
            let head = &mut *ldr.cast::<u8>().add(0x20).cast::<LIST_ENTRY>();
            let first = head.Flink;

            let entry = containing_record!(first, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            (*entry).SizeOfImage = new_size;
        }
        self.image_size = new_size;
        Ok(())
    }

    /// Locates a module in the current process by walking the PEB module list
    /// and returns its parsed export directory.
    ///
    /// Reads the TEB directly, walks `InMemoryOrderModuleList`, and matches
    /// each entry's full DLL path against `dll_name` (case-insensitive
    /// substring). Delegates to [`Self::from_base_address`] on match.
    ///
    /// # Errors
    ///
    /// - [`ExpError::ExportError`] — TEB or PEB is null, or no loaded module
    ///   matched `dll_name`.
    /// - Any [`ExpError`] from [`Self::from_base_address`].
    pub fn from_module(dll_name: impl ToString) -> Result<Self, ExpError> {
        unsafe {
            let teb = get_teb();

            if teb.is_null() {
                return Err(ExpError::ExportError("TEB is null".to_string()));
            }

            let peb = get_peb();
            if peb.is_null() {
                return Err(ExpError::ExportError("PEB is null".to_string()));
            }

            let ldr = (*peb).Ldr;
            let head = &mut *ldr.cast::<u8>().add(0x20).cast::<LIST_ENTRY>();
            let mut curr = head.Flink;

            let target_name = dll_name.to_string().to_lowercase();

            loop {
                let dll_entry = containing_record!(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                let unicode = &(*dll_entry).FullDllName;

                if !unicode.Buffer.is_null() && unicode.Length > 0 {
                    let slice =
                        core::slice::from_raw_parts(unicode.Buffer, (unicode.Length / 2) as usize);
                    let name = String::from_utf16_lossy(slice).to_lowercase();

                    if name.contains(&target_name) {
                        let module_base = (*dll_entry).DllBase as u64;
                        return Self::from_base_address(teb, module_base);
                    }
                }

                curr = (*curr).Flink;
                if curr == head {
                    break;
                }
            }

            Err(ExpError::ExportError(format!(
                "Module not found: {}",
                target_name
            )))
        }
    }

    fn from_base_address(teb: *mut TEB, module_base: u64) -> Result<Self, ExpError> {
        unsafe {
            let dos_header = module_base as *const ImageDosHeader;
            let nt_headers =
                (module_base + (*dos_header).nt_headers_offset() as u64) as *const ImageNtHeaders64;

            let section_count = (*nt_headers).file_header.number_of_sections;
            // section headers should come after the NT headers
            let section_headers_ptr = (nt_headers as usize
                + core::mem::size_of::<ImageNtHeaders64>())
                as *const ImageSectionHeader;
            let section_headers =
                core::slice::from_raw_parts(section_headers_ptr, section_count as usize).to_vec();

            let export_rva = (*nt_headers).optional_header.data_directory
                [IMAGE_DIRECTORY_ENTRY_EXPORT]
                .virtual_address;

            let export_dir = if export_rva != 0 {
                (module_base + export_rva as u64) as *const ImageExportDirectory
            } else {
                core::ptr::null()
            };

            let image_size = (*nt_headers).optional_header.size_of_image;

            Ok(Self {
                memory: LocalMemory {},
                teb,
                module_base,
                dos_header,
                nt_headers,
                section_headers,
                section_count,
                export_dir,
                image_size,
                header_erased: false,
            })
        }
    }
}

impl<M: MemoryView> PE64Runtime<M> {
    /// Returns all section headers parsed from the PE header.
    pub fn sections(&self) -> &[ImageSectionHeader] { &self.section_headers }

    /// Finds a section by its null-padded 8-byte name (e.g. `".text"`,
    /// `".rdata"`).
    pub fn find_section(&self, name: &str) -> Option<&ImageSectionHeader> {
        self.sections().iter().find(|section| {
            let section_name = unsafe {
                core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                    section.name.as_ptr(),
                    section.name.len(),
                ))
            };
            section_name == name
        })
    }
    /// Returns the section whose virtual address range contains `rva`, if any.
    pub fn section_containing_rva(&self, rva: u32) -> Option<&ImageSectionHeader> {
        self.sections()
            .iter()
            .find(|s| rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
    }

    /// Converts a relative virtual address to an absolute virtual address.
    #[inline]
    pub fn rva_to_va(&self, rva: u32) -> u64 { self.module_base + rva as u64 }

    /// Converts an absolute virtual address to an RVA, or `None` if `va`
    /// precedes the module base.
    #[inline]
    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        if va >= self.module_base {
            Some((va - self.module_base) as u32)
        } else {
            None
        }
    }

    /// Returns `true` if the PE has a non-null export directory.
    #[inline]
    pub fn has_exports(&self) -> bool { !self.export_dir.is_null() }

    /// Removes the PE header from memory
    pub fn erase_header(&mut self) -> Result<(), ExpError> {
        if self.header_erased {
            return Err(ExpError::ExportError(
                "Header is already erased".to_string(),
            ));
        }

        let mut old_protect = 0;
        self.memory.virtual_protect(
            self.module_base as *mut u8,
            4096,
            crate::PAGE_READWRITE,
            &mut old_protect,
        );
        self.memory.write_bytes(self.module_base, &[0u8; 4096])?;
        self.header_erased = true;

        Ok(())
    }
}
