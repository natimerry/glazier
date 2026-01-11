use crate::pe::PESection;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32, // RVA to Import Lookup Table (ILT)
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,                 // RVA to DLL Name string
    pub first_thunk: u32,          // RVA to Import Address Table (IAT)
}

impl PESection for ImageImportDescriptor {
    fn is_valid(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct ParsedImportModule {
    pub name: String,
    pub descriptor: ImageImportDescriptor, // Keep the raw descriptor if you need it later
    pub functions: Vec<ParsedImportFunction>,
}

#[derive(Debug, Clone)]
pub struct ParsedImportFunction {
    pub name: Option<String>, // Function name (e.g. "WriteFile")
    pub ordinal: u16,         // Ordinal if imported by ordinal
    pub iat_rva: u32,         // The RVA in the IAT where the address is stored (FirstThunk + offset)
}