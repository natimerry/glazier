use crate::pe::PESection;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageNtHeaders64 {
    pub signature: u32,                        // "PE\0\0" (0x00004550)
    pub file_header: ImageFileHeader,          // Standard COFF Header
    pub optional_header: ImageOptionalHeader64, // PE64 Specific Header
}

impl PESection for ImageNtHeaders64 {
    fn is_valid(&self) -> bool {
        self.signature == 0x00004550
    }
}


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,              // 0x8664 for AMD64
    pub number_of_sections: u16,   // Number of sections to parse later
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16, // Size of the struct below
    pub characteristics: u16,      // Flags
}

impl PESection for ImageFileHeader {
    fn is_valid(&self) -> bool {
        true // i got no way to figure this out yet
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,                 // 0x20B for PE32+ (64-bit)
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32, // RVA to execution start
    pub base_of_code: u32,           // RVA to code section

    pub image_base: u64,             // Preferred load address (64-bit)
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,    // Reserved, must be 0
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,              // GUI (2) vs CUI (3)
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,  // 64-bit
    pub size_of_stack_commit: u64,   // 64-bit
    pub size_of_heap_reserve: u64,   // 64-bit
    pub size_of_heap_commit: u64,    // 64-bit
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32, // Usually 16
    pub data_directory: [ImageDataDirectory; 16], // Import/Export tables
}

impl PESection for ImageOptionalHeader64 {
    fn is_valid(&self) -> bool {
        self.magic == 0x20B
    }
}


#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32, // RVA of the table (e.g., Import Table)
    pub size: u32,            // Size of the table in bytes
}

impl PESection for ImageDataDirectory {
    fn is_valid(&self) -> bool {
        true
    }
}

