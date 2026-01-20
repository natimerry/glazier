use crate::ByteReader;
use crate::ExpError;
use crate::pe::image_dos_header::ImageDosHeader;
use crate::pe::image_nt_header::ImageNtHeaders64;
use crate::pe::image_section_header::ImageSectionHeader;
use crate::pe::import_address_table::ImageImportDescriptor;
use crate::pe::import_address_table::ParsedImportFunction;
use crate::pe::import_address_table::ParsedImportModule;
use crate::utils::cast_from_mem;
use byteorder::LittleEndian;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

pub struct PE64Static {
    pub image_dos_header: ImageDosHeader,
    pub image_nt_headers64: ImageNtHeaders64,
    pub sections: Vec<ImageSectionHeader>,
}

impl ByteReader for BufReader<File> {
    fn read_u8(&mut self) -> Result<u8, ExpError> { Ok(byteorder::ReadBytesExt::read_u8(self)?) }

    fn read_u32(&mut self) -> Result<u32, ExpError> {
        Ok(byteorder::ReadBytesExt::read_u32::<LittleEndian>(self)?)
    }

    fn read_u64(&mut self) -> Result<u64, ExpError> {
        Ok(byteorder::ReadBytesExt::read_u64::<LittleEndian>(self)?)
    }

    fn read_i8(&mut self) -> Result<i8, ExpError> { Ok(byteorder::ReadBytesExt::read_i8(self)?) }

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

        self.read_c_string()
    }

    fn seek(&mut self, offset: usize) -> Result<u64, ExpError> {
        let x = Seek::seek(self, SeekFrom::Start(offset as u64))?;
        Ok(x)
    }

    fn current_offset(&mut self) -> Result<usize, ExpError> {
        let x = self.stream_position()?;
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

                    reader.seek(restore_pos)?;
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

        reader.seek(image_dos_header.nt_headers_offset() as usize)?;

        let image_nt_headers64: ImageNtHeaders64 = cast_from_mem(&mut reader)?;

        let num_sections = image_nt_headers64.file_header.number_of_sections;

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
