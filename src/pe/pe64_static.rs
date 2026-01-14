use crate::pe::cast_from_mem;
use std::fs::File;
use std::io;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use crate::{ByteReader, ExpError};
use crate::pe::export_address_table::{ImageExportDirectory, ParsedExportFunction, ParsedExportModule};
use crate::pe::image_dos_header::ImageDosHeader;
use crate::pe::image_nt_header::ImageNtHeaders64;
use crate::pe::image_section_header::ImageSectionHeader;
use crate::pe::import_address_table::{ImageImportDescriptor, ParsedImportFunction, ParsedImportModule};

pub struct PE64Static {
    pub image_dos_header: ImageDosHeader,
    pub image_nt_headers64: ImageNtHeaders64,
    pub sections: Vec<ImageSectionHeader>,
}

impl ByteReader for BufReader<File>{
    fn read_u8(&mut self) -> Result<u8, ExpError> {
        Ok(byteorder::ReadBytesExt::read_u8(self)?)
    }

    fn read_u32(&mut self) -> Result<u32, ExpError> {
        Ok(byteorder::ReadBytesExt::read_u32::<LittleEndian>(self)?)
    }

    fn read_u64(&mut self) -> Result<u64, ExpError> {
        Ok(byteorder::ReadBytesExt::read_u64::<LittleEndian>(self)?)
    }

    fn read_i8(&mut self) -> Result<i8, ExpError> {
        Ok(byteorder::ReadBytesExt::read_i8(self)?)
    }

    fn read_i16(&mut self) -> Result<i16, ExpError> {
        Ok(byteorder::ReadBytesExt::read_i16::<LittleEndian>(self)?)
    }

    fn read_i32(&mut self) -> Result<i32, ExpError> {
        Ok(byteorder::ReadBytesExt::read_i32::<LittleEndian>(self)?)
    }

    fn read_i64(&mut self) -> Result<i64, ExpError> {
        Ok(byteorder::ReadBytesExt::read_i64::<LittleEndian>(self)?)
    }

    fn read_f32(&mut self) -> Result<f32, ExpError> {
        Ok(byteorder::ReadBytesExt::read_f32::<LittleEndian>(self)?)
    }

    fn read_f64(&mut self) -> Result<f64, ExpError> {
        Ok(byteorder::ReadBytesExt::read_f64::<LittleEndian>(self)?)
    }

    fn read_c_string(&mut self) -> Result<String, ExpError> {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 1];

        loop {
            let n = self.read(&mut buf)?;
            if n == 0 {
                return Err(ExpError::ParseError(String::from("EOF")));
            }

            if buf[0] == 0 {
                break;
            }

            bytes.push(buf[0]);
        }

        String::from_utf8(bytes).map_err(|x| ExpError::ParseError(x.to_string()))
    }


    fn read_string_at_offset(&mut self, offset: usize) -> Result<String, ExpError> {
        Seek::seek(self, SeekFrom::Start(offset as u64))?;

        return self.read_c_string();
    }

    fn seek(&mut self, offset: usize) -> Result<u64, ExpError> {
        let x = Seek::seek(self, SeekFrom::Start(offset as u64))?;
        Ok(x)
    }

    fn current_offset(&mut self) -> Result<usize, ExpError> {
        let x= self.stream_position()?;
        Ok(x as usize)
    }
}


impl PE64Static {
    pub fn get_imports<R: ByteReader + std::io::Read>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<ImageImportDescriptor>, ExpError> {
        let import_dir = self.image_nt_headers64.optional_header.data_directory[1];

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

            // Check for Null Terminator (empty struct)
            if desc.original_first_thunk == 0 && desc.name == 0 {
                break;
            }
            descriptors.push(desc);
        }

        Ok(descriptors)
    }

    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        if rva < self.image_nt_headers64.optional_header.size_of_headers {
            return Some(rva);
        }

        for section in &self.sections {
            let v_start = section.virtual_address;
            let v_end = v_start + section.virtual_size;

            if rva >= v_start && rva < v_end {
                let delta = rva - v_start;

                if delta < section.size_of_raw_data {
                    return Some(section.pointer_to_raw_data + delta);
                } else {
                    return None;
                }
            }
        }

        None
    }

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
        reader: &mut R
    ) -> Result<Vec<ParsedExportModule>, ExpError> {
        let descriptor = match self.get_exports(reader)? {
            Some(d) => d,
            None => return Ok(Vec::new()), // No exports
        };

        let dll_name = self.read_string_at_rva(reader, descriptor.name)?;

        let func_table_offset = self.rva_to_offset(descriptor.address_of_functions)
            .ok_or(ExpError::ParseError("Invalid Export Address Table RVA".into()))?;

        let name_table_offset = self.rva_to_offset(descriptor.address_of_names)
            .ok_or(ExpError::ParseError("Invalid Export Name Table RVA".into()))?;

        let ordinal_table_offset = self.rva_to_offset(descriptor.address_of_name_ordinals)
            .ok_or(ExpError::ParseError("Invalid Export Ordinal Table RVA".into()))?;

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
                forwarder: None,
            });
        }

        // We loop over the NAME table, which points to strings and gives us an index into the func table.
        for i in 0..descriptor.number_of_names {
            let name_ptr_offset = name_table_offset as u64 + (i as u64 * 4);
            reader.seek(name_ptr_offset as usize)?;
            let name_rva = reader.read_u32()?;

            let ord_ptr_offset = ordinal_table_offset as u64 + (i as u64 * 2) ;
            reader.seek(ord_ptr_offset as u64 as usize)?;
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

        let final_functions = functions.into_iter()
            .filter(|f| f.func_rva != 0) // Filter out non-existent functions (gaps)
            .map(|mut f| {
                if export_range.contains(&f.func_rva) {
                    let restore_pos = reader.current_offset().unwrap_or(0);

                    // The RVA points to a string inside the export section
                    if let Ok(fwd_name) = self.read_string_at_rva(reader, f.func_rva) {
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


    pub fn get_parsed_imports<R: ByteReader + std::io::Read>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<ParsedImportModule>, ExpError> {
        let mut modules = Vec::new();

        // Use your existing method to get raw descriptors
        let raw_descriptors = self.get_imports(reader)?;

        for desc in raw_descriptors {
            let dll_name = self.read_string_at_rva(reader, desc.name)?;

            let lookup_rva = if desc.original_first_thunk != 0 {
                desc.original_first_thunk
            } else {
                desc.first_thunk
            };

            let lookup_offset = self.rva_to_offset(lookup_rva).unwrap();

            let mut functions = Vec::new();

            // We need to track the parallel IAT (FirstThunk) RVA for patching later
            let mut current_iat_rva = desc.first_thunk;

            reader.seek(lookup_offset as u64 as usize)?;

            // loop to read 64-bit thunks until null terminator
            loop {
                let thunk_data = reader.read_u64()?;

                if thunk_data == 0 {
                    break;
                } // End of list

                let is_ordinal = (thunk_data & 0x8000_0000_0000_0000) != 0;
                let mut func_name = None;
                let mut ordinal = 0;

                if is_ordinal {
                    ordinal = (thunk_data & 0xFFFF) as u16;
                } else {
                    // It's an RVA to IMAGE_IMPORT_BY_NAME
                    let name_rva = (thunk_data & 0x7FFFFFFF) as u32;

                    // Save cursor, jump to name, restore cursor
                    let restore_pos = reader.current_offset()?;

                    // +2 skips the "Hint" field to get straight to the ASCII string
                    if let Some(offset) = self.rva_to_offset(name_rva) {
                        reader.seek((offset + 2) as usize)?;
                        func_name = Some(reader.read_c_string()?);
                    }

                    reader.seek(restore_pos as usize)?;
                }

                functions.push(ParsedImportFunction {
                    name: func_name,
                    ordinal,
                    iat_rva: current_iat_rva, // Critical for patching!
                });

                // Move to next slot in the IAT array (8 bytes for 64-bit)
                current_iat_rva += 8;
            }

            modules.push(ParsedImportModule {
                name: dll_name,
                descriptor: desc,
                functions,
            });
        }

        Ok(modules)
    }

    pub fn from_reader<R>(mut reader: R) -> Result<PE64Static, ExpError>
    where
        R: ByteReader + std::io::Read,
    {
        // Always start from 0
        reader.seek(0)?;

        let image_dos_header: ImageDosHeader = cast_from_mem(&mut reader)?;

        reader.seek(
            image_dos_header.nt_headers_offset() as usize,
        )?;

        let image_nt_headers64: ImageNtHeaders64 = cast_from_mem(&mut reader)?;

        let num_sections =
            image_nt_headers64.file_header.number_of_sections;

        let mut sections = Vec::with_capacity(num_sections as usize);
        for _ in 0..num_sections {
            let section: ImageSectionHeader = cast_from_mem(&mut reader)?;
            sections.push(section);
        }

        Ok(PE64Static {
            image_dos_header,
            image_nt_headers64,
            sections,
        })
    }
    pub fn from_pe_file(filename: &str) -> Result<PE64Static, ExpError> {
        let file = File::open(filename)?;
        let cursor = io::BufReader::new(file);

        Self::from_reader(cursor)
    }

    pub fn read_string_at_rva<P: ByteReader>(
        &self,
        reader: &mut P,
        rva: u32,
    ) -> Result<String, ExpError> {
        let offset = self
            .rva_to_offset(rva)
            .ok_or(ExpError::ParseError("Invalid RVA".into()))?;

        reader.read_string_at_offset(offset as usize)
    }

    pub fn read_string_at_current_pos<P: ByteReader>(
        source: &mut P,
        pos: &mut u64,
    ) -> Result<String, ExpError> {
        let s = source.read_string_at_offset(*pos as usize)?;

        *pos += s.len() as u64 + 1;
        Ok(s)
    }
}

