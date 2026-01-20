use crate::pe::PESection;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageNtHeaders64 {
    pub signature: u32,                         // "PE\0\0" (0x00004550)
    pub file_header: ImageFileHeader,           // Standard COFF Header
    pub optional_header: ImageOptionalHeader64, // PE64 Specific Header
}

impl PESection for ImageNtHeaders64 {
    fn is_valid(&self) -> bool { self.signature == 0x00004550 }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,            // 0x8664 for AMD64
    pub number_of_sections: u16, // Number of sections to parse later
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16, // Size of the struct below
    pub characteristics: u16,         // Flags
}

impl PESection for ImageFileHeader {
    fn is_valid(&self) -> bool {
        true // i got no way to figure this out yet
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOptionalHeader64 {
    pub magic: u16, // 0x20B for PE32+ (64-bit)
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32, // RVA to execution start
    pub base_of_code: u32,           // RVA to code section

    pub image_base: u64, // Preferred load address (64-bit)
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32, // Reserved, must be 0
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16, // GUI (2) vs CUI (3)
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64, // 64-bit
    pub size_of_stack_commit: u64,  // 64-bit
    pub size_of_heap_reserve: u64,  // 64-bit
    pub size_of_heap_commit: u64,   // 64-bit
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,             // Usually 16
    pub data_directory: [ImageDataDirectory; 16], // Import/Export tables
}

impl PESection for ImageOptionalHeader64 {
    fn is_valid(&self) -> bool { self.magic == 0x20B }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32, // RVA of the table (e.g., Import Table)
    pub size: u32,            // Size of the table in bytes
}

impl PESection for ImageDataDirectory {
    fn is_valid(&self) -> bool { true }
}

/// Index for the Export Directory in the PE DataDirectory array.
///
/// Points to the IMAGE_EXPORT_DIRECTORY structure containing information about
/// functions and data exported by this module.
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

/// Index for the Import Directory in the PE DataDirectory array.
///
/// Points to the IMAGE_IMPORT_DESCRIPTOR array containing information about
/// DLLs and functions imported by this module.
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

/// Index for the Resource Directory in the PE DataDirectory array.
///
/// Points to the IMAGE_RESOURCE_DIRECTORY structure containing resources like
/// icons, dialogs, version information, and other embedded data.
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;

/// Index for the Exception Directory in the PE DataDirectory array.
///
/// Points to the exception handling information (primarily used on x64 for
/// structured exception handling and stack unwinding).
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;

/// Index for the Security Directory in the PE DataDirectory array.
///
/// Points to the Authenticode digital signature used for code signing.
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

/// Index for the Base Relocation Table in the PE DataDirectory array.
///
/// Points to the IMAGE_BASE_RELOCATION structure used for address relocation
/// when the module cannot load at its preferred base address.
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

/// Index for the Debug Directory in the PE DataDirectory array.
///
/// Points to the IMAGE_DEBUG_DIRECTORY array containing debug information
/// like PDB paths and CodeView data.
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;

/// Index for Architecture Specific Data in the PE DataDirectory array.
///
/// Reserved for architecture-specific data. Must be zero.
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;

/// Index for the Global Pointer Register RVA in the PE DataDirectory array.
///
/// RVA of the value to be stored in the global pointer register.
/// Size must be zero.
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;

/// Index for the TLS Directory in the PE DataDirectory array.
///
/// Points to the IMAGE_TLS_DIRECTORY structure containing Thread Local Storage
/// initialization and callback information.
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

/// Index for the Load Configuration Directory in the PE DataDirectory array.
///
/// Points to the IMAGE_LOAD_CONFIG_DIRECTORY structure containing advanced
/// loader settings like SEH, CFG, and other security features.
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;

/// Index for the Bound Import Directory in the PE DataDirectory array.
///
/// Points to the IMAGE_BOUND_IMPORT_DESCRIPTOR array containing bound import
/// information for optimization (largely deprecated).
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;

/// Index for the Import Address Table in the PE DataDirectory array.
///
/// Points to the IAT (Import Address Table) containing addresses of imported
/// functions after they've been resolved by the loader.
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

/// Index for the Delay Import Directory in the PE DataDirectory array.
///
/// Points to the delay-load import descriptors for DLLs that are loaded
/// on-demand rather than at process startup.
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;

/// Index for the COM Runtime Descriptor in the PE DataDirectory array.
///
/// Points to the CLR runtime header for .NET assemblies.
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

/// Maximum number of directory entries in the PE DataDirectory array.
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;
