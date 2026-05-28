use crate::ByteReader;
use crate::ExpError;
use crate::pe::export_address_table::ImageExportDirectory;
use crate::pe::export_address_table::ParsedExportFunction;
use crate::pe::export_address_table::ParsedExportModule;
use crate::pe::image_dos_header::ImageDosHeader;
use crate::pe::image_nt_header::ImageNtHeaders32;
use crate::pe::image_section_header::ImageSectionHeader;
use crate::pe::import_address_table::ImageImportDescriptor;
use crate::pe::import_address_table::ParsedImportFunction;
use crate::pe::import_address_table::ParsedImportModule;
use crate::utils::cast_from_mem;
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use std::fs::File;
use std::io;

pub struct PE32Static {
    pub image_dos_header: ImageDosHeader,
    pub image_nt_headers32: ImageNtHeaders32,
    pub sections: Vec<ImageSectionHeader>,
}

impl PE32Static {
    pub fn from_reader<R>(mut reader: R) -> Result<Self, ExpError>
    where
        R: ByteReader + std::io::Read,
    {
        reader.seek(0)?;

        let image_dos_header: ImageDosHeader = cast_from_mem(&mut reader)?;
        reader.seek(image_dos_header.nt_headers_offset() as usize)?;

        let image_nt_headers32: ImageNtHeaders32 = cast_from_mem(&mut reader)?;
        let num_sections = image_nt_headers32.file_header.number_of_sections;

        let mut sections = Vec::with_capacity(num_sections as usize);
        for _ in 0..num_sections {
            sections.push(cast_from_mem(&mut reader)?);
        }

        Ok(Self {
            image_dos_header,
            image_nt_headers32,
            sections,
        })
    }

    pub fn from_pe_file(filename: &str) -> Result<Self, ExpError> {
        let file = File::open(filename)?;
        let cursor = io::BufReader::new(file);

        Self::from_reader(cursor)
    }

    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        if rva < self.image_nt_headers32.optional_header.size_of_headers {
            return Some(rva);
        }

        for section in &self.sections {
            let v_start = section.virtual_address;
            let v_size = section.virtual_size.max(section.size_of_raw_data);
            let v_end = v_start.checked_add(v_size)?;

            if rva >= v_start && rva < v_end {
                let delta = rva - v_start;

                if delta < section.size_of_raw_data {
                    return Some(section.pointer_to_raw_data + delta);
                }
                return None;
            }
        }

        None
    }

    pub fn read_string_at_rva<P: ByteReader>(
        &self,
        reader: &mut P,
        rva: u32,
    ) -> Result<String, ExpError> {
        let offset = self
            .rva_to_offset(rva)
            .ok_or_else(|| ExpError::ParseError("Invalid RVA".into()))?;

        reader.read_string_at_offset(offset as usize)
    }

    pub fn get_imports<R: ByteReader + std::io::Read>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<ImageImportDescriptor>, ExpError> {
        let import_dir = self.image_nt_headers32.optional_header.data_directory[1];

        if import_dir.virtual_address == 0 {
            return Ok(Vec::new());
        }

        let offset = self
            .rva_to_offset(import_dir.virtual_address)
            .ok_or_else(|| ExpError::ParseError("Invalid Import Directory RVA".into()))?;

        reader.seek(offset as usize)?;

        let mut descriptors = Vec::new();

        loop {
            let desc: ImageImportDescriptor = cast_from_mem(reader)?;

            if desc.original_first_thunk == 0 && desc.name == 0 {
                break;
            }
            descriptors.push(desc);
        }

        Ok(descriptors)
    }

    pub fn get_parsed_imports<R: ByteReader + std::io::Read>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<ParsedImportModule>, ExpError> {
        let mut modules = Vec::new();
        let raw_descriptors = self.get_imports(reader)?;

        for desc in raw_descriptors {
            let dll_name = self.read_string_at_rva(reader, desc.name)?;

            let lookup_rva = if desc.original_first_thunk != 0 {
                desc.original_first_thunk
            } else {
                desc.first_thunk
            };

            let lookup_offset = self
                .rva_to_offset(lookup_rva)
                .ok_or_else(|| ExpError::ParseError("Invalid import lookup RVA".into()))?;

            let mut functions = Vec::new();
            let mut current_iat_rva = desc.first_thunk;

            reader.seek(lookup_offset as usize)?;

            loop {
                let thunk_data = reader.read_u32()?;

                if thunk_data == 0 {
                    break;
                }

                let is_ordinal = (thunk_data & 0x8000_0000) != 0;
                let mut func_name = None;
                let mut ordinal = 0;

                if is_ordinal {
                    ordinal = (thunk_data & 0xFFFF) as u16;
                } else {
                    let name_rva = thunk_data & 0x7FFF_FFFF;
                    let restore_pos = reader.current_offset()?;

                    if let Some(offset) = self.rva_to_offset(name_rva) {
                        reader.seek((offset + 2) as usize)?;
                        func_name = Some(reader.read_c_string()?);
                    }

                    reader.seek(restore_pos)?;
                }

                functions.push(ParsedImportFunction {
                    name: func_name,
                    ordinal,
                    iat_rva: current_iat_rva,
                });

                current_iat_rva += 4;
            }

            modules.push(ParsedImportModule {
                name: dll_name,
                descriptor: desc,
                functions,
            });
        }

        Ok(modules)
    }

    pub fn get_exports<R: ByteReader + std::io::Read>(
        &self,
        reader: &mut R,
    ) -> Result<Option<ImageExportDirectory>, ExpError> {
        let export_dir = self.image_nt_headers32.optional_header.data_directory[0];

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
            None => return Ok(Vec::new()),
        };

        let dll_name = self.read_string_at_rva(reader, descriptor.name)?;

        let func_table_offset = self
            .rva_to_offset(descriptor.address_of_functions)
            .ok_or_else(|| ExpError::ParseError("Invalid Export Address Table RVA".into()))?;

        let name_table_offset = self
            .rva_to_offset(descriptor.address_of_names)
            .ok_or_else(|| ExpError::ParseError("Invalid Export Name Table RVA".into()))?;

        let ordinal_table_offset = self
            .rva_to_offset(descriptor.address_of_name_ordinals)
            .ok_or_else(|| ExpError::ParseError("Invalid Export Ordinal Table RVA".into()))?;

        let mut functions = Vec::with_capacity(descriptor.number_of_functions as usize);

        reader.seek(func_table_offset as usize)?;

        let mut func_rvas = Vec::with_capacity(descriptor.number_of_functions as usize);
        for _ in 0..descriptor.number_of_functions {
            func_rvas.push(reader.read_u32()?);
        }

        for (i, &rva) in func_rvas.iter().enumerate() {
            let func_addr = self.rva_to_offset(rva).unwrap_or(0) as usize;
            functions.push(ParsedExportFunction {
                name: None,
                ordinal: descriptor.base + (i as u32),
                func_rva: rva,
                func_addr,
                forwarder: None,
            });
        }

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
                    reader.seek(offset as usize)?;
                    functions[func_idx].name = Some(reader.read_c_string()?);
                }

                reader.seek(restore_pos)?;
            }
        }

        let dir_rva = self.image_nt_headers32.optional_header.data_directory[0].virtual_address;
        let dir_size = self.image_nt_headers32.optional_header.data_directory[0].size;
        let export_range = dir_rva..(dir_rva + dir_size);

        let final_functions = functions
            .into_iter()
            .filter(|f| f.func_rva != 0)
            .map(|mut f| {
                if export_range.contains(&f.func_rva) {
                    if let Ok(restore_pos) = reader.current_offset() {
                        if let Ok(fwd_name) = self.read_string_at_rva(reader, f.func_rva) {
                            f.forwarder = Some(fwd_name);
                        }
                        let _ = reader.seek(restore_pos);
                    }
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
