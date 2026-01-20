use crate::pe::PESection;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: u32,
}

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // 'MZ'

impl PESection for ImageDosHeader {
    fn is_valid(&self) -> bool {
        self.e_magic == IMAGE_DOS_SIGNATURE
    }
}
impl ImageDosHeader {
    pub fn nt_headers_offset(&self) -> u32 {
        self.e_lfanew
    }
}
