use crate::pe::PESection;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,                   // RVA to the DLL internal name string
    pub base: u32,                   // The starting ordinal number
    pub number_of_functions: u32,    // Count of entries in AddressOfFunctions
    pub number_of_names: u32,        // Count of entries in AddressOfNames
    pub address_of_functions: u32,   // RVA to Export Address Table (EAT)
    pub address_of_names: u32,       // RVA to Export Name Pointer Table
    pub address_of_name_ordinals: u32, // RVA to Export Ordinal Table
}

impl PESection for ImageExportDirectory {
    fn is_valid(&self) -> bool {
        // A valid export directory usually exports at least one thing
        self.number_of_functions > 0
    }
}

#[derive(Debug, Clone)]
pub struct ParsedExportModule {
    pub name: String, // The DLL name defined inside the export dir
    pub descriptor: ImageExportDirectory,
    pub functions: Vec<ParsedExportFunction>,
}

#[derive(Debug, Clone)]
pub struct ParsedExportFunction {
    pub name: Option<String>,      // Function name (None if exported by ordinal only)
    pub ordinal: u32,              // The final ordinal (Base + Index)
    pub func_rva: u32,             // The RVA pointing to the code (or forwarder string)
    pub forwarder: Option<String>, // If set, 'rva' points to this string (e.g. "NTDLL.SomeFunc")
}