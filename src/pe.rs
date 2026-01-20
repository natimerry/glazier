pub mod export_address_table;
pub mod image_dos_header;
pub mod image_nt_header;
pub mod image_section_header;
pub mod import_address_table;
pub mod pe64_static;

pub trait PESection {
    fn is_valid(&self) -> bool;
}
