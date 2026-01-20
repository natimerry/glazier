use crate::ExpError;
use crate::pe::export_address_table::{ImageExportDirectory, ParsedExportFunction};
use crate::pe::image_dos_header::ImageDosHeader;
use crate::pe::image_nt_header::ImageNtHeaders64;
use crate::runtime::pe64_runtime::PE64Runtime;
use std::ffi::c_char;
use std::ops::Add;
use windows_sys::Win32::System::Threading::TEB;
use windows_sys::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;

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
impl PE64Runtime {
    pub fn exports(&self) -> RuntimeParsedExportIterator<'_> {
        RuntimeParsedExportIterator::new(self)
    }

    pub fn find_export(
        &self,
        export_name: impl ToString,
    ) -> Result<ParsedExportFunction, ExpError> {
        unsafe {
            if !self.has_exports() {
                return Err(ExpError::ExportError(
                    "PE64Runtime has no exports".to_string(),
                ));
            }

            let name_table =
                (self.module_base + (*self.export_dir).address_of_names as u64) as *const u32;

            let ordinal_table = (self.module_base
                + (*self.export_dir).address_of_name_ordinals as u64)
                as *const u16;
            let func_table =
                (self.module_base + (*self.export_dir).address_of_functions as u64) as *const u32;

            let target_name = export_name.to_string();

            for i in 0..(*self.export_dir).number_of_names {
                let name_rva = *name_table.add(i as usize);
                let func_name_ptr = (self.module_base + name_rva as u64) as *const c_char;

                // strcmpi equivalent
                let func_name = {
                    let mut len = 0;
                    while *func_name_ptr.add(len) != 0 {
                        len += 1;
                    }
                    let slice = core::slice::from_raw_parts(func_name_ptr as *const u8, len);
                    core::str::from_utf8_unchecked(slice)
                };

                if func_name.eq_ignore_ascii_case(&export_name.to_string()) {
                    let ordinal = *ordinal_table.add(i as usize) as usize;

                    let func_rva = *func_table.add(ordinal) as usize;
                    return Ok(ParsedExportFunction {
                        name: Some(export_name.to_string()),
                        ordinal: ordinal as u32,
                        func_addr: self.module_base as usize + func_rva,
                        func_rva: func_rva as u32,
                        forwarder: None,
                    });
                }
            }
            Err(ExpError::ExportError(format!(
                "Export not found: {}",
                target_name
            )))
        }
    }
}

pub struct RuntimeParsedExportIterator<'a> {
    runtime: &'a PE64Runtime,
    index: usize,
}

impl<'a> RuntimeParsedExportIterator<'a> {
    pub fn new(runtime: &'a PE64Runtime) -> Self {
        Self { runtime, index: 0 }
    }
}

impl<'a> Iterator for RuntimeParsedExportIterator<'a> {
    type Item = ExportedFunction;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if self.runtime.has_exports() == false {
                return None;
            }

            let export_dir = &*self.runtime.export_dir;

            if self.index >= export_dir.number_of_names as usize {
                return None;
            }

            let name_table =
                (self.runtime.module_base + export_dir.address_of_names as u64) as *const u32;
            let ordinal_table = (self.runtime.module_base
                + export_dir.address_of_name_ordinals as u64)
                as *const u16;
            let func_table =
                (self.runtime.module_base + export_dir.address_of_functions as u64) as *const u32;

            let name_rva = *name_table.add(self.index as usize);
            let func_name_ptr = (self.runtime.module_base + name_rva as u64) as *const c_char;

            let name = {
                let mut len = 0;
                while *func_name_ptr.add(len) != 0 {
                    len += 1;
                }
                let slice = core::slice::from_raw_parts(func_name_ptr as *const u8, len);
                String::from_utf8_lossy(slice).to_string()
            };

            let ordinal = *ordinal_table.add(self.index as usize) as usize;
            let func_rva = *func_table.add(ordinal);
            let address = self.runtime.module_base + func_rva as u64;

            self.index += 1;

            Some(ExportedFunction {
                name,
                address,
                ordinal: ordinal as u16,
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExportedFunction {
    pub name: String,
    pub address: u64,
    pub ordinal: u16,
}
