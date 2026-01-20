use std::ffi::c_char;
use std::ops::Add;
use crate::ExpError;
use crate::pe::image_dos_header::ImageDosHeader;
use crate::pe::image_nt_header::ImageNtHeaders64;
use crate::runtime::pe64_runtime::PE64Runtime;
use windows_sys::Win32::System::Threading::TEB;
use windows_sys::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;
use crate::pe::export_address_table::ImageExportDirectory;

#[macro_export]
macro_rules! containing_record {
    ($ptr:expr, $container:ty, $field:ident) => {{
        let offset = core::mem::offset_of!($container, $field);
        ($ptr as *const u8).wrapping_sub(offset) as *mut $container
    }};
}

///NOTE: this library doesnt aim to be compatible with aarch64, this is put if for one very specific usecase
/// and may be removed in future builds
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    core::arch::asm!(
    "mrs {0}, tpidr_el0",
    out(reg) teb,
    options(nostack, preserves_flags)
    );
    teb
}


#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn get_teb() -> *mut TEB {
    unsafe {
        let teb: *mut TEB;
        core::arch::asm!(
        "mov {}, gs:[0x30]",
        out(reg) teb,
        options(nostack, preserves_flags)
        );
        teb
    }
}

impl PE64Runtime{
    pub fn exports(&self) -> ExportIterator {
        ExportIterator::new(self)
    }
    
    pub fn find_export(&self,export_name: impl ToString) -> Result<u64,ExpError>
    {
        unsafe {
            if !self.has_exports()
            {
                return Err(ExpError::ExportError(
                    "PE64Runtime has no exports".to_string(),
                ));
            }
            
            let name_table = (self.module_base + (*self.export_dir).address_of_names as u64) as *const u32;
            
    
            let ordinal_table = (self.module_base + (*self.export_dir).address_of_name_ordinals as u64) as *const u16;
            let func_table = (self.module_base + (*self.export_dir).address_of_functions as u64) as *const u32;
            
            
            let target_name = export_name.to_string();
            
            
            for i in 0..(*self.export_dir).number_of_names
            {
                let name_rva = *name_table.add(i as usize);  
                let func_name_ptr = (self.module_base + name_rva as u64) as *const c_char;

    
                // strcmpi equivalent
                let func_name = {
                    let mut len = 0;
                    while *func_name_ptr.add(len) != 0 {
                        len += 1;
                    }
                    let slice = core::slice::from_raw_parts(
                        func_name_ptr as *const u8,
                        len,
                    );
                    core::str::from_utf8_unchecked(slice)
                };
    
                if func_name.eq_ignore_ascii_case(&export_name.to_string()) {
                    let ordinal = *ordinal_table.add(i as usize) as usize;
    
                    let func_rva = *func_table.add(ordinal) as usize;
                    return Ok(self.module_base + func_rva as u64);
                }
            }
            Err(ExpError::ExportError(format!(
                "Export not found: {}",
                target_name
            )))
        }
    }
}
pub fn find_dll_base(dll_name: impl ToString) -> Result<u64, ExpError> {
    unsafe {
        let teb = get_teb();

        if teb.is_null() {
            return Err(ExpError::ExportError(
                "Failed to retrieve the TEB".to_string(),
            ));
        }

        let peb = (*teb).ProcessEnvironmentBlock;
        if peb.is_null() {
            return Err(ExpError::ExportError(
                "Failed to retrieve the TEB".to_string(),
            ));
        }

        let ldr = (*peb).Ldr;
        let head = &mut (*ldr).InMemoryOrderModuleList;
        let mut curr = head.Flink;

        loop {
            let dll_entry = containing_record!(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            let unicode = &(*dll_entry).FullDllName;

            if !unicode.Buffer.is_null() && unicode.Length > 0 {
                let slice =
                    core::slice::from_raw_parts(unicode.Buffer, (unicode.Length / 2) as usize);

                let name = String::from_utf16_lossy(slice);

                let name = name.to_lowercase();

                if name.contains(&dll_name.to_string().to_lowercase()) {
                    return Ok((*dll_entry).DllBase as u64);
                }
            }
            curr = (*curr).Flink;

            if curr == head {
                break;
            }
        }
    }

    Err(ExpError::ExportError(format!(
        "Did not find module: {}",
        dll_name.to_string()
    )))
}

