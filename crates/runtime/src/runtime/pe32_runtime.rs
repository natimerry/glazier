use crate::ExpError;
use crate::memory::MemoryView;
use crate::memory::RemoteMemory;
use crate::pe::export_address_table::ImageExportDirectory;
use crate::pe::image_dos_header::ImageDosHeader;
use crate::pe::image_nt_header::IMAGE_DIRECTORY_ENTRY_EXPORT;
use crate::pe::image_nt_header::ImageNtHeaders32;
use crate::pe::image_section_header::ImageSectionHeader;
use glazier_bindings::HANDLE;
use glazier_bindings::LDR_DATA_TABLE_ENTRY32;
use glazier_bindings::NtQueryInformationProcess;
use glazier_bindings::PEB_LDR_DATA32;
use glazier_bindings::PEB32;
use std::mem::offset_of;

const PROCESS_WOW64_INFORMATION: u32 = 26;

pub struct PE32Runtime<M: MemoryView> {
    pub memory: M,
    pub module_base: u32,
    pub dos_header: *const ImageDosHeader,
    pub nt_headers: *const ImageNtHeaders32,
    pub section_headers: Vec<ImageSectionHeader>,
    pub section_count: u16,
    pub export_dir: *const ImageExportDirectory,
    pub image_size: u32,
}

impl PE32Runtime<RemoteMemory> {
    pub fn from_handle(handle: HANDLE) -> Result<Self, ExpError> {
        let memory = RemoteMemory { handle };
        let peb_base = wow64_peb_address(handle)?;
        let peb = memory.read::<PEB32>(peb_base as u64)?;
        let ldr_ptr = peb.Ldr;
        let ldr = memory.read::<PEB_LDR_DATA32>(ldr_ptr as u64)?;

        let first_flink = ldr.InMemoryOrderModuleList.Flink;
        let entry_addr =
            first_flink - offset_of!(LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks) as u32;
        let entry = memory.read::<LDR_DATA_TABLE_ENTRY32>(entry_addr as u64)?;
        let module_base = entry.DllBase;

        Self::from_base_address_remote(memory, module_base)
    }

    pub fn from_module_remote(handle: HANDLE, dll_name: impl ToString) -> Result<Self, ExpError> {
        let memory = RemoteMemory { handle };
        let target_name = dll_name.to_string().to_lowercase();
        let peb_base = wow64_peb_address(handle)?;
        let peb = memory.read::<PEB32>(peb_base as u64)?;
        let ldr_ptr = peb.Ldr;
        let ldr = memory.read::<PEB_LDR_DATA32>(ldr_ptr as u64)?;

        let head_addr = ldr_ptr + offset_of!(PEB_LDR_DATA32, InMemoryOrderModuleList) as u32;
        let mut curr_flink = ldr.InMemoryOrderModuleList.Flink;

        while curr_flink != head_addr {
            let entry_addr =
                curr_flink - offset_of!(LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks) as u32;
            let entry = memory.read::<LDR_DATA_TABLE_ENTRY32>(entry_addr as u64)?;

            let buf_ptr = entry.FullDllName.Buffer;
            let buf_len = (entry.FullDllName.Length / 2) as usize;

            if buf_ptr != 0 && buf_len > 0 {
                let mut wide_buf = vec![0u16; buf_len];
                for (i, slot) in wide_buf.iter_mut().enumerate() {
                    *slot = memory.read::<u16>(buf_ptr as u64 + i as u64 * 2)?;
                }
                let name = String::from_utf16_lossy(&wide_buf).to_lowercase();
                if name.contains(&target_name) {
                    return Self::from_base_address_remote(memory, entry.DllBase);
                }
            }

            curr_flink = entry.InMemoryOrderLinks.Flink;
        }

        Err(ExpError::ExportError(format!(
            "Module not found: {}",
            target_name
        )))
    }

    fn from_base_address_remote(memory: RemoteMemory, module_base: u32) -> Result<Self, ExpError> {
        let dos_header = memory.read::<ImageDosHeader>(module_base as u64)?;
        let nt_headers_addr = module_base + dos_header.nt_headers_offset();
        let nt_headers = memory.read::<ImageNtHeaders32>(nt_headers_addr as u64)?;

        let section_count = nt_headers.file_header.number_of_sections;
        let section_headers_addr =
            nt_headers_addr + core::mem::size_of::<ImageNtHeaders32>() as u32;
        let mut section_headers = Vec::with_capacity(section_count as usize);
        for index in 0..section_count {
            section_headers.push(memory.read::<ImageSectionHeader>(
                section_headers_addr as u64
                    + index as u64 * core::mem::size_of::<ImageSectionHeader>() as u64,
            )?);
        }

        let export_rva =
            nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;

        let export_dir_addr = if export_rva != 0 {
            module_base + export_rva
        } else {
            0
        };

        let image_size = nt_headers.optional_header.size_of_image;

        let dos_header = Box::into_raw(Box::new(dos_header)) as *const ImageDosHeader;
        let nt_headers = Box::into_raw(Box::new(nt_headers)) as *const ImageNtHeaders32;
        let export_dir = export_dir_addr as usize as *const ImageExportDirectory;

        Ok(Self {
            memory,
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

fn wow64_peb_address(handle: HANDLE) -> Result<u32, ExpError> {
    let mut peb_address = 0usize;
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_WOW64_INFORMATION as _,
            &mut peb_address as *mut _ as *mut _,
            core::mem::size_of::<usize>() as u32,
            core::ptr::null_mut(),
        )
    };

    if status < 0 || peb_address == 0 || peb_address > u32::MAX as usize {
        return Err(ExpError::RuntimeError(
            "Process does not expose a WOW64 PEB".to_string(),
        ));
    }

    Ok(peb_address as u32)
}

impl<M: MemoryView> PE32Runtime<M> {
    pub fn patch_memory(&self, address: u32, bytes: &[u8]) -> Result<(), ExpError> {
        self.memory.write_bytes(address as u64, bytes)
    }

    pub fn sections(&self) -> &[ImageSectionHeader] { &self.section_headers }

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
    pub fn rva_to_va(&self, rva: u32) -> u32 { self.module_base + rva }

    #[inline]
    pub fn va_to_rva(&self, va: u32) -> Option<u32> {
        if va >= self.module_base {
            Some(va - self.module_base)
        } else {
            None
        }
    }

    #[inline]
    pub fn has_exports(&self) -> bool { !self.export_dir.is_null() }
}
