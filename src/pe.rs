use crate::ExpError;
use crate::ExpError::ParseError;
use std::{io, mem};

pub mod export_address_table;
pub mod image_dos_header;
pub mod image_nt_header;
pub mod image_section_header;
pub mod import_address_table;
pub mod pe64_static;

pub trait PESection {
    fn is_valid(&self) -> bool;
}

pub fn cast_from_mem<R: io::Read, T: Sized + PESection + Clone>(
    reader: &mut R,
) -> Result<T, ExpError> {
    unsafe {
        let mut buffer = vec![0u8; mem::size_of::<T>()];
        reader.read_exact(buffer.as_mut_slice())?;

        let header = &*(buffer.as_ptr() as *const T);

        if !header.is_valid() {
            return Err(ParseError(String::from("Invalid section parsed.")));
        }

        Ok(header.clone())
    }
}
