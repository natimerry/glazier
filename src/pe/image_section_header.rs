use crate::ByteReader;
use crate::ExpError;
use crate::pe::PESection;
use crate::pe::pe64_static::PE64Static;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],            // UTF-8/ASCII name (e.g., ".text")
    pub virtual_size: u32,        // Size in memory (Misc.VirtualSize)
    pub virtual_address: u32,     // RVA start in memory
    pub size_of_raw_data: u32,    // Size on disk
    pub pointer_to_raw_data: u32, // File offset to raw data
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32, // R/W/X permissions
}

impl ImageSectionHeader {
    pub fn resolve_section_name<R: ByteReader>(&self, pe: &PE64Static, reader: &mut R) -> String {
        let name_str = String::from_utf8_lossy(&self.name)
            .trim_matches('\0')
            .to_string();

        if let Some(name_str) = name_str.strip_prefix('/')
            && let Ok(offset) = name_str.parse::<u32>()
        {
            return read_coff_string(pe, offset, reader).unwrap_or(name_str.to_string());
        }
        name_str
    }
}

fn read_coff_string<R: ByteReader>(
    pe: &PE64Static,
    string_table_offset: u32,
    reader: &mut R,
) -> Result<String, ExpError> {
    let file_header = &pe.image_nt_headers64.file_header;

    if file_header.pointer_to_symbol_table == 0 {
        return Ok(format!("/{}", string_table_offset)); // Fallback if stripped
    }

    let symbol_table_size = file_header.number_of_symbols * 18;
    let string_table_base = file_header.pointer_to_symbol_table + symbol_table_size;

    let target_offset = string_table_base + string_table_offset;

    reader.seek(target_offset as usize)?;

    reader.read_c_string()
}

impl PESection for ImageSectionHeader {
    fn is_valid(&self) -> bool { true }
}
