use crate::ByteReader;
use crate::ExpError;
use crate::PE64Static;
use crate::pe::export_address_table::ImageExportDirectory;
use crate::pe::export_address_table::ParsedExportFunction;
use crate::pe::export_address_table::ParsedExportModule;
use crate::runtime::pe64_runtime::PE64Runtime;
use crate::utils::cast_from_mem;
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use std::ffi::c_char;

impl PE64Runtime {
    pub fn exports(&self) -> RuntimeParsedExportIterator<'_> {
        RuntimeParsedExportIterator::new(self)
    }

    pub fn get_syscall_num(&self, exported_func: ParsedExportFunction) -> Result<u16, ExpError> {
        let func_addr = exported_func.func_addr as *const u8;

        if let Some(func_name) = &exported_func.name {
            if !(func_name.starts_with("Nt") || func_name.starts_with("Zw")) {
                println!("Function is not a syscall, are you sure you know what you are doing?");
            }
        }

        // TODO: Implement syscall extraction for hooked function with a loop (and maybe implement max tries to avoid segfaults)
        unsafe {
            // mov r10, rcx
            if *func_addr == 0x4C
                && *func_addr.add(1) == 0x8B
                && *func_addr.add(2) == 0xD1
                && *func_addr.add(3) == 0xB8
            {
                let ssn_low = *func_addr.add(4);
                let ssn_high = *func_addr.add(5);

                let ssn = ((ssn_high as u16) << 8) | (ssn_low as u16);
                return Ok(ssn);
            }

            if *func_addr == 0xE9 {
                return Err(ExpError::ExportError(format!(
                    "Function {} is hooked (starts with JMP). Hell's Gate extraction failed.",
                    exported_func.name.unwrap().to_string()
                )));
            }

            Err(ExpError::ExportError(format!(
                "Pattern mismatch for {}. Could not identify syscall stub.",
                exported_func.name.unwrap().to_string()
            )))
        }
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
    pub fn new(runtime: &'a PE64Runtime) -> Self { Self { runtime, index: 0 } }
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

impl PE64Static {
    pub fn get_exports<R: ByteReader + std::io::Read>(
        &self,
        reader: &mut R,
    ) -> Result<Option<ImageExportDirectory>, ExpError> {
        let export_dir = self.image_nt_headers64.optional_header.data_directory[0];

        if export_dir.virtual_address == 0 {
            return Ok(None);
        }

        let offset = self
            .rva_to_offset(export_dir.virtual_address)
            .ok_or_else(|| ExpError::ParseError("Invalid Export Directory RVA".into()))?;

        reader.seek(offset as usize)?;

        let desc: ImageExportDirectory = cast_from_mem(reader)?;

        Ok(Some(desc))
    }

    pub fn get_parsed_exports<R: ByteReader + std::io::Read>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<ParsedExportModule>, ExpError> {
        let descriptor = match self.get_exports(reader)? {
            Some(d) => d,
            None => return Ok(Vec::new()), // No exports
        };

        let dll_name = self.read_string_at_rva(reader, descriptor.name)?;

        let func_table_offset =
            self.rva_to_offset(descriptor.address_of_functions)
                .ok_or(ExpError::ParseError(
                    "Invalid Export Address Table RVA".into(),
                ))?;

        let name_table_offset = self
            .rva_to_offset(descriptor.address_of_names)
            .ok_or(ExpError::ParseError("Invalid Export Name Table RVA".into()))?;

        let ordinal_table_offset = self
            .rva_to_offset(descriptor.address_of_name_ordinals)
            .ok_or(ExpError::ParseError(
                "Invalid Export Ordinal Table RVA".into(),
            ))?;

        let mut functions = Vec::with_capacity(descriptor.number_of_functions as usize);

        reader.seek(func_table_offset as u64 as usize)?;

        let mut func_rvas = Vec::with_capacity(descriptor.number_of_functions as usize);
        for _ in 0..descriptor.number_of_functions {
            func_rvas.push(reader.read_u32()?);
        }

        // Initialize Parsed Functions
        for (i, &rva) in func_rvas.iter().enumerate() {
            functions.push(ParsedExportFunction {
                name: None,
                ordinal: descriptor.base + (i as u32), // Base + Index
                func_rva: rva,
                func_addr: self.rva_to_offset(rva).unwrap() as usize,
                forwarder: None,
            });
        }

        // We loop over the NAME table, which points to strings and gives us an index
        // into the func table.
        for i in 0..descriptor.number_of_names {
            let name_ptr_offset = name_table_offset as u64 + (i as u64 * 4);
            reader.seek(name_ptr_offset as usize)?;
            let name_rva = reader.read_u32()?;

            let ord_ptr_offset = ordinal_table_offset as u64 + (i as u64 * 2);
            reader.seek(ord_ptr_offset as usize)?;
            let func_idx = reader.read_u16::<LittleEndian>()? as usize;

            if func_idx < functions.len() {
                let restore_pos = reader.current_offset()?;

                if let Some(offset) = self.rva_to_offset(name_rva) {
                    reader.seek(offset as u64 as usize)?;
                    let name = reader.read_c_string()?;
                    functions[func_idx].name = Some(name);
                }

                reader.seek(restore_pos)?;
            }
        }

        let dir_rva = self.image_nt_headers64.optional_header.data_directory[0].virtual_address;
        let dir_size = self.image_nt_headers64.optional_header.data_directory[0].size;
        let export_range = dir_rva..(dir_rva + dir_size);

        let final_functions = functions
            .into_iter()
            .filter(|f| f.func_rva != 0) // Filter out non-existent functions (gaps)
            .map(|mut f| {
                if export_range.contains(&(f.func_rva)) {
                    let restore_pos = reader.current_offset().unwrap_or(0);

                    // The RVA points to a string inside the export section
                    if let Ok(fwd_name) = self.read_string_at_rva(reader, f.func_rva as u32) {
                        f.forwarder = Some(fwd_name);
                    }

                    reader.seek(restore_pos).ok();
                }
                f
            })
            .collect();

        Ok(vec![ParsedExportModule {
            name: dll_name,
            descriptor,
            functions: final_functions,
        }])
    }
}
#[derive(Debug, Clone)]
pub struct ExportedFunction {
    pub name: String,
    pub address: u64,
    pub ordinal: u16,
}
