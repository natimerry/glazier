use crate::ByteReader;
use crate::ExpError;
use crate::PE64Static;
use crate::pe::export_address_table::ImageExportDirectory;
use crate::pe::export_address_table::ParsedExportFunction;
use crate::pe::export_address_table::ParsedExportModule;
use crate::runtime::memory::LocalMemory;
use crate::runtime::memory::MemoryView;
use crate::runtime::pe64_runtime::PE64Runtime;
use crate::utils::cast_from_mem;
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use log::debug;
use log::warn;

impl PE64Runtime<LocalMemory> {
    pub fn get_syscall_num(&self, exported_func: ParsedExportFunction) -> Result<u16, ExpError> {
        let func_addr = exported_func.func_addr as *const u8;

        if let Some(func_name) = &exported_func.name {
            if !(func_name.starts_with("Nt") || func_name.starts_with("Zw")) {
                warn!("Function is not a syscall, are you sure you know what you are doing?");
            }
        }

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
            let func_name = exported_func.name.clone().unwrap();
            if *func_addr == 0xE9 {
                warn!(
                    "Function {} is hooked (JMP detected). Scanning forward...",
                    func_name.clone().to_string()
                );
                return self.halos_gate(&func_name);
            }

            Err(ExpError::ExportError(format!(
                "Pattern mismatch for {}. Could not identify syscall stub.",
                exported_func.name.unwrap().to_string()
            )))
        }
    }

    fn halos_gate(&self, target_func: &str) -> Result<u16, ExpError> {
        let mut syscall_funcs: Vec<(String, usize)> = Vec::new();
        let iterator = RuntimeParsedExportIterator::new(&self);

        for export in iterator {
            let name_str = export.name.clone();
            if name_str.starts_with("Nt") || name_str.starts_with("Zw") {
                syscall_funcs.push((name_str, export.address as usize));
            }
        }

        syscall_funcs.sort_by_key(|(_, addr)| *addr);

        let target_idx = syscall_funcs
            .iter()
            .position(|(name, _)| name == target_func)
            .ok_or_else(|| ExpError::ExportError(format!("Function {} not found", target_func)))?;

        debug!("Target {} at index {}", target_func, target_idx);

        for offset in 1..=20 {
            if let Some((neighbor_name, neighbor_addr)) = syscall_funcs.get(target_idx + offset) {
                if let Ok(neighbor_ssn) = self.try_extract_ssn(*neighbor_addr) {
                    let calculated_ssn = neighbor_ssn - offset as u16;
                    debug!(
                        "Found unhooked neighbor {} (+{}) with SSN 0x{:X}",
                        neighbor_name, offset, neighbor_ssn
                    );
                    debug!("Calculated {} SSN: 0x{:X}", target_func, calculated_ssn);
                    return Ok(calculated_ssn);
                }
            }

            // Try function before target
            if target_idx >= offset {
                if let Some((neighbor_name, neighbor_addr)) = syscall_funcs.get(target_idx - offset)
                {
                    if let Ok(neighbor_ssn) = self.try_extract_ssn(*neighbor_addr) {
                        let calculated_ssn = neighbor_ssn + offset as u16;
                        debug!(
                            "Found unhooked neighbor {} (-{}) with SSN 0x{:X}",
                            neighbor_name, offset, neighbor_ssn
                        );
                        debug!("Calculated {} SSN: 0x{:X}", target_func, calculated_ssn);
                        return Ok(calculated_ssn);
                    }
                }
            }
        }

        Err(ExpError::ExportError(format!(
            "Halo's Gate failed: no unhooked neighbors found for {}",
            target_func
        )))
    }
    fn try_extract_ssn(&self, func_addr: usize) -> Result<u16, ()> {
        unsafe {
            let addr = func_addr as *const u8;

            // Check for syscall stub pattern
            if *addr == 0x4C && *addr.add(1) == 0x8B && *addr.add(2) == 0xD1 && *addr.add(3) == 0xB8
            {
                let ssn_low = *addr.add(4);
                let ssn_high = *addr.add(5);
                Ok(((ssn_high as u16) << 8) | (ssn_low as u16))
            } else {
                Err(())
            }
        }
    }
}

impl<M: MemoryView> PE64Runtime<M> {
    pub fn exports(&self) -> RuntimeParsedExportIterator<'_, M> {
        RuntimeParsedExportIterator::new(self)
    }

    pub fn find_export(
        &self,
        export_name: impl ToString,
    ) -> Result<ParsedExportFunction, ExpError> {
        if !self.has_exports() {
            return Err(ExpError::ExportError(
                "PE64Runtime has no exports".to_string(),
            ));
        }

        let export_dir = self
            .memory
            .read::<ImageExportDirectory>(self.export_dir as u64)?;

        let name_table_base = self.module_base + export_dir.address_of_names as u64;
        let ordinal_table_base = self.module_base + export_dir.address_of_name_ordinals as u64;
        let func_table_base = self.module_base + export_dir.address_of_functions as u64;

        let target_name = export_name.to_string();

        for i in 0..export_dir.number_of_names {
            let name_rva = self
                .memory
                .read::<u32>(name_table_base + i as u64 * size_of::<u32>() as u64)?;
            let func_name_ptr = self.module_base + name_rva as u64;

            // Read the export name as a null-terminated string
            let func_name = {
                let mut bytes = Vec::new();
                let mut offset = 0u64;
                loop {
                    let byte = self.memory.read::<u8>(func_name_ptr + offset)?;
                    if byte == 0 {
                        break;
                    }
                    bytes.push(byte);
                    offset += 1;
                }
                String::from_utf8_lossy(&bytes).into_owned()
            };

            if func_name.eq_ignore_ascii_case(&target_name) {
                let ordinal = self
                    .memory
                    .read::<u16>(ordinal_table_base + i as u64 * size_of::<u16>() as u64)?
                    as usize;

                let func_rva = self
                    .memory
                    .read::<u32>(func_table_base + ordinal as u64 * size_of::<u32>() as u64)?
                    as usize;

                return Ok(ParsedExportFunction {
                    name: Some(target_name),
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

pub struct RuntimeParsedExportIterator<'a, M: MemoryView> {
    runtime: &'a PE64Runtime<M>,
    index: usize,
}

impl<'a, M: MemoryView> RuntimeParsedExportIterator<'a, M> {
    pub fn new(runtime: &'a PE64Runtime<M>) -> Self { Self { runtime, index: 0 } }
}

impl<'a, M: MemoryView> Iterator for RuntimeParsedExportIterator<'a, M> {
    type Item = ExportedFunction;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.runtime.has_exports() {
            return None;
        }

        let export_dir = self
            .runtime
            .memory
            .read::<ImageExportDirectory>(self.runtime.export_dir as u64)
            .ok()?;

        if self.index >= export_dir.number_of_names as usize {
            return None;
        }

        let name_table_base = self.runtime.module_base + export_dir.address_of_names as u64;
        let ordinal_table_base =
            self.runtime.module_base + export_dir.address_of_name_ordinals as u64;
        let func_table_base = self.runtime.module_base + export_dir.address_of_functions as u64;

        let name_rva = self
            .runtime
            .memory
            .read::<u32>(name_table_base + self.index as u64 * size_of::<u32>() as u64)
            .ok()?;

        let func_name_ptr = self.runtime.module_base + name_rva as u64;
        let name = {
            let mut bytes = Vec::new();
            let mut offset = 0u64;
            loop {
                let byte = self
                    .runtime
                    .memory
                    .read::<u8>(func_name_ptr + offset)
                    .ok()?;
                if byte == 0 {
                    break;
                }
                bytes.push(byte);
                offset += 1;
            }
            String::from_utf8_lossy(&bytes).to_string()
        };

        let ordinal = self
            .runtime
            .memory
            .read::<u16>(ordinal_table_base + self.index as u64 * size_of::<u16>() as u64)
            .ok()? as usize;

        let func_rva = self
            .runtime
            .memory
            .read::<u32>(func_table_base + ordinal as u64 * size_of::<u32>() as u64)
            .ok()?;

        let address = self.runtime.module_base + func_rva as u64;

        self.index += 1;

        Some(ExportedFunction {
            name,
            address,
            ordinal: ordinal as u16,
        })
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
