use crate::ExpError;
use crate::ExpError::ParseError;
use crate::pe::PESection;
use std::mem;

pub fn cast_from_mem<R: std::io::Read, T: Sized + PESection + Clone>(
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
