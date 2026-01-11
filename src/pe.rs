use crate::ExpError;
use crate::ExpError::ParseError;
use crate::pe::image_dos_header::ImageDosHeader;
use crate::pe::image_nt_header::ImageNtHeaders64;
use crate::pe::image_section_header::ImageSectionHeader;
use crate::pe::import_address_table::{ImageImportDescriptor, ParsedImportFunction, ParsedImportModule};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::{io, mem};
use byteorder::{LittleEndian, ReadBytesExt};

pub mod image_dos_header;
pub mod image_nt_header;
pub mod image_section_header;
mod import_address_table;

pub struct PE64 {
    pub image_dos_header: ImageDosHeader,
    pub image_nt_headers64: ImageNtHeaders64,
    pub sections: Vec<ImageSectionHeader>,
}

impl PE64 {
    pub fn get_imports<R: io::Read + io::Seek>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<ImageImportDescriptor>, ExpError> {
        let import_dir = self.image_nt_headers64.optional_header.data_directory[1];

        if import_dir.virtual_address == 0 {
            return Ok(Vec::new());
        }

        let offset = self.rva_to_offset(import_dir.virtual_address)
            .ok_or_else(|| ExpError::ParseError("Invalid Import Directory RVA".into()))?;

        reader.seek(io::SeekFrom::Start(offset as u64))?;

        let mut descriptors = Vec::new();

        loop {
            let desc: ImageImportDescriptor = cast_from_mem(reader)?;

            // Check for Null Terminator (empty struct)
            // SAFETY: should be 0 since the vector is 0 initialized
            if desc.original_first_thunk == 0 && desc.name == 0 {
                break;
            }
            descriptors.push(desc);
        }

        Ok(descriptors)
    }
    fn read_string_current_pos<R: io::Read>(
        &self,
        reader: &mut R
    ) -> Result<String, ExpError> {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 1];

        loop {
            // Read 1 byte
            reader.read_exact(&mut buf)?;

            // Stop at null terminator
            if buf[0] == 0 {
                break;
            }
            bytes.push(buf[0]);
        }

        // Convert bytes to String (lossy handles invalid UTF-8 gracefully)
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    pub fn get_parsed_imports<R: io::Read + io::Seek>(&self, reader: &mut R) -> Result<Vec<ParsedImportModule>, ExpError> {
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

            reader.seek(SeekFrom::Start(lookup_offset as u64))?;

            // loop to read 64-bit thunks until null terminator
            loop {
                let thunk_data = reader.read_u64::<LittleEndian>()?;

                if thunk_data == 0 { break; } // End of list

                let is_ordinal = (thunk_data & 0x8000_0000_0000_0000) != 0;
                let mut func_name = None;
                let mut ordinal = 0;

                if is_ordinal {
                    ordinal = (thunk_data & 0xFFFF) as u16;
                } else {
                    // It's an RVA to IMAGE_IMPORT_BY_NAME
                    let name_rva = (thunk_data & 0x7FFFFFFF) as u32;

                    // Save cursor, jump to name, restore cursor
                    let restore_pos = reader.stream_position()?;

                    // +2 skips the "Hint" field to get straight to the ASCII string
                    if let Some(offset) = self.rva_to_offset(name_rva) {
                        reader.seek(SeekFrom::Start((offset + 2) as u64))?;
                        func_name = Some(self.read_string_current_pos(reader)?);
                    }

                    reader.seek(SeekFrom::Start(restore_pos))?;
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

    pub fn from_pe_file(filename: &str) -> Result<PE64, ExpError> {
        let file = File::open(filename)?;
        let mut cursor = io::BufReader::new(file);

        let image_dos_header: ImageDosHeader = cast_from_mem(&mut cursor)?;
        cursor.seek(io::SeekFrom::Start(
            image_dos_header.nt_headers_offset() as u64
        ))?;

        let image_nt_headers64: ImageNtHeaders64 = cast_from_mem(&mut cursor)?;

        let num_sections = image_nt_headers64.file_header.number_of_sections;
        let mut sections = Vec::with_capacity(num_sections as usize);
        for _ in 0..num_sections {
            let section: ImageSectionHeader = cast_from_mem(&mut cursor)?;
            sections.push(section);
        }

        Ok(PE64 {
            image_dos_header,
            image_nt_headers64,
            sections,
        })
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
    pub fn read_string_at_rva<R: io::Seek + io::Read>(&self, reader:&mut R, rva: u32) -> Result<String, ExpError> {
        let offset = self.rva_to_offset(rva).unwrap();
        reader.seek(SeekFrom::Start(offset as u64))?;

        let mut bytes = Vec::new();
        let mut buf = [0u8; 1];

        // Read until null terminator
        loop {
            reader.read_exact(&mut buf)?;
            if buf[0] == 0 { break; }
            bytes.push(buf[0]);
        }

        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

}

pub trait PESection {
    fn is_valid(&self) -> bool;
}

pub fn cast_from_mem<R: io::Read, T: Sized + PESection + Clone>(
    reader: &mut R,
) -> Result<T, ExpError> {
    unsafe {
        let mut buffer = vec![0u8; mem::size_of::<T>()];
        reader.read_exact(&mut buffer.as_mut_slice())?;

        let header = &*(buffer.as_ptr() as *const T);

        if !header.is_valid() {
            return Err(ParseError(String::from("Invalid section parsed.")));
        }

        Ok(header.clone())
    }
}


