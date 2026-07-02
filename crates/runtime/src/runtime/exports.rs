use crate::ExpError;
use crate::memory::LocalMemory;
use crate::memory::MemoryView;
use crate::pe::export_address_table::ImageExportDirectory;
use crate::pe::export_address_table::ParsedExportFunction;
use crate::pe32_runtime::PE32Runtime;
use crate::pe64_runtime::PE64Runtime;
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
            let func_name = exported_func.name.clone().ok_or_else(|| {
                ExpError::ExportError("Unnamed export has no syscall name".into())
            })?;

            let control_flow_ops = [
                0xE8, // call rel32
                0xE9, // jmp rel32
                0xEB, // jmp rel8
                0x70, // jcc short
                0x0F, // jcc near
                0xFF, // call/jmp r/m
                0xC3, // ret
                0xC2, // ret imm16
                0xE3, // jcxz
            ];
            let op = *func_addr;
            if control_flow_ops.contains(&(op as i32)) {
                warn!(
                    "Function {} is hooked (JMP detected). Scanning forward...",
                    func_name.clone().to_string()
                );
                return self.halos_gate(&func_name);
            }

            Err(ExpError::ExportError(format!(
                "Pattern mismatch for {}. Could not identify syscall stub.",
                func_name
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

impl<M: MemoryView> PE32Runtime<M> {
    pub fn exports(&self) -> RuntimeParsedExportIterator32<'_, M> {
        RuntimeParsedExportIterator32::new(self)
    }

    pub fn find_export(
        &self,
        export_name: impl ToString,
    ) -> Result<ParsedExportFunction, ExpError> {
        if !self.has_exports() {
            return Err(ExpError::ExportError(
                "PE32Runtime has no exports".to_string(),
            ));
        }

        let export_dir = self
            .memory
            .read::<ImageExportDirectory>(self.export_dir as u64)?;

        let name_table_base = self.module_base + export_dir.address_of_names;
        let ordinal_table_base = self.module_base + export_dir.address_of_name_ordinals;
        let func_table_base = self.module_base + export_dir.address_of_functions;

        let target_name = export_name.to_string();

        for i in 0..export_dir.number_of_names {
            let name_rva = self
                .memory
                .read::<u32>(name_table_base as u64 + i as u64 * size_of::<u32>() as u64)?;
            let func_name_ptr = self.module_base + name_rva;

            let func_name = {
                let mut bytes = Vec::new();
                let mut offset = 0u64;
                loop {
                    let byte = self.memory.read::<u8>(func_name_ptr as u64 + offset)?;
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
                    .read::<u16>(ordinal_table_base as u64 + i as u64 * size_of::<u16>() as u64)?
                    as usize;

                let func_rva = self.memory.read::<u32>(
                    func_table_base as u64 + ordinal as u64 * size_of::<u32>() as u64,
                )? as usize;

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

pub struct RuntimeParsedExportIterator32<'a, M: MemoryView> {
    runtime: &'a PE32Runtime<M>,
    index: usize,
}

impl<'a, M: MemoryView> RuntimeParsedExportIterator32<'a, M> {
    pub fn new(runtime: &'a PE32Runtime<M>) -> Self { Self { runtime, index: 0 } }
}

impl<'a, M: MemoryView> Iterator for RuntimeParsedExportIterator32<'a, M> {
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

        let name_table_base = self.runtime.module_base + export_dir.address_of_names;
        let ordinal_table_base = self.runtime.module_base + export_dir.address_of_name_ordinals;
        let func_table_base = self.runtime.module_base + export_dir.address_of_functions;

        let name_rva = self
            .runtime
            .memory
            .read::<u32>(name_table_base as u64 + self.index as u64 * size_of::<u32>() as u64)
            .ok()?;

        let func_name_ptr = self.runtime.module_base + name_rva;
        let name = {
            let mut bytes = Vec::new();
            let mut offset = 0u64;
            loop {
                let byte = self
                    .runtime
                    .memory
                    .read::<u8>(func_name_ptr as u64 + offset)
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
            .read::<u16>(ordinal_table_base as u64 + self.index as u64 * size_of::<u16>() as u64)
            .ok()? as usize;

        let func_rva = self
            .runtime
            .memory
            .read::<u32>(func_table_base as u64 + ordinal as u64 * size_of::<u32>() as u64)
            .ok()?;

        let address = self.runtime.module_base as u64 + func_rva as u64;

        self.index += 1;

        Some(ExportedFunction {
            name,
            address,
            ordinal: ordinal as u16,
        })
    }
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

#[derive(Debug, Clone)]
pub struct ExportedFunction {
    pub name: String,
    pub address: u64,
    pub ordinal: u16,
}
