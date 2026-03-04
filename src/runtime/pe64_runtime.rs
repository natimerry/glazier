use crate::ExpError;
use crate::containing_record;
use crate::pe::export_address_table::ImageExportDirectory;
use crate::pe::image_dos_header::ImageDosHeader;
use crate::pe::image_nt_header::IMAGE_DIRECTORY_ENTRY_EXPORT;
use crate::pe::image_nt_header::ImageNtHeaders64;
use crate::pe::image_section_header::ImageSectionHeader;
use crate::runtime::memory::LocalMemory;
use crate::runtime::memory::MemoryView;
use crate::utils::get_teb;
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
    pub fn from_remote_handle(memory: impl MemoryView) -> Result<Self, ExpError> { todo!() }

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
