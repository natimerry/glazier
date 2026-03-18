use crate::ExpError;
use crate::containing_record;
use crate::pe::export_address_table::ImageExportDirectory;
use crate::pe::image_dos_header::ImageDosHeader;
use crate::pe::image_nt_header::IMAGE_DIRECTORY_ENTRY_EXPORT;
use crate::pe::image_nt_header::ImageNtHeaders64;
use crate::pe::image_section_header::ImageSectionHeader;
use crate::runtime::memory::LocalMemory;
use crate::runtime::memory::MemoryView;
use crate::runtime::memory::RemoteMemory;
use crate::utils::get_teb;
use crate::winapi::HANDLE;
use crate::winapi::LIST_ENTRY;
use crate::winapi::NtQueryInformationProcess;
use crate::winapi::PEB;
use crate::winapi::PEB_LDR_DATA;
use crate::winapi::PROCESS_BASIC_INFORMATION;
use std::mem::offset_of;
use windows_sys::Win32::System::Threading::TEB;
use windows_sys::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;

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
    pub section_headers: *const ImageSectionHeader,

    /// Number of sections
    pub section_count: u16,

    /// Pointer to export directory (if present)
    pub export_dir: *const ImageExportDirectory,

    /// Image size
    pub image_size: u32,
}

impl PE64Runtime<RemoteMemory> {
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
        let section_headers = section_headers_addr as *const ImageSectionHeader;
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
        })
    }

    pub fn patch_memory(&self, address: u64, bytes: &[u8]) -> Result<(), ExpError> {
        self.memory.write_bytes(address, bytes)
    }
}
impl PE64Runtime<LocalMemory> {
    pub fn from_current_module() -> Result<Self, ExpError> {
        unsafe {
            let teb = get_teb();
            if teb.is_null() {
                return Err(ExpError::ExportError("TEB is null".to_string()));
            }

            let peb = (*teb).ProcessEnvironmentBlock;
            if peb.is_null() {
                return Err(ExpError::ExportError("PEB is null".to_string()));
            }

            let ldr = (*peb).Ldr;
            let head = &mut (*ldr).InMemoryOrderModuleList;
            let first = head.Flink;

            let entry = containing_record!(first, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            let module_base = (*entry).DllBase as u64;

            Self::from_base_address(teb, module_base)
        }
    }

    pub fn from_module(dll_name: impl ToString) -> Result<Self, ExpError> {
        unsafe {
            let teb = get_teb();

            if teb.is_null() {
                return Err(ExpError::ExportError("TEB is null".to_string()));
            }

            let peb = (*teb).ProcessEnvironmentBlock;
            if peb.is_null() {
                return Err(ExpError::ExportError("PEB is null".to_string()));
            }

            let ldr = (*peb).Ldr;
            let head = &mut (*ldr).InMemoryOrderModuleList;
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
            let section_headers = (nt_headers as usize + core::mem::size_of::<ImageNtHeaders64>())
                as *const ImageSectionHeader;

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
            })
        }
    }
}

impl<M: MemoryView> PE64Runtime<M> {
    pub fn sections(&self) -> &[ImageSectionHeader] {
        unsafe { core::slice::from_raw_parts(self.section_headers, self.section_count as usize) }
    }

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

    pub fn section_containing_rva(&self, rva: u32) -> Option<&ImageSectionHeader> {
        self.sections()
            .iter()
            .find(|s| rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
    }

    #[inline]
    pub fn rva_to_va(&self, rva: u32) -> u64 { self.module_base + rva as u64 }

    #[inline]
    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        if va >= self.module_base {
            Some((va - self.module_base) as u32)
        } else {
            None
        }
    }

    #[inline]
    pub fn has_exports(&self) -> bool { !self.export_dir.is_null() }
}
