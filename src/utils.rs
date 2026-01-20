use crate::ExpError;
use crate::ExpError::ParseError;
use crate::pe::PESection;
use std::mem;
use windows_sys::Win32::System::Threading::TEB;

#[macro_export]
macro_rules! containing_record {
    ($ptr:expr, $container:ty, $field:ident) => {{
        let offset = core::mem::offset_of!($container, $field);
        ($ptr as *const u8).wrapping_sub(offset) as *mut $container
    }};
}

/// NOTE: this library doesnt aim to be compatible with aarch64, this is put if
/// for one very specific usecase and may be removed in future builds
#[cfg(target_arch = "aarch64")]
#[cfg(feature = "runtime")]
#[inline(always)]
unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    core::arch::asm!(
    "mrs {0}, tpidr_el0",
    out(reg) teb,
    options(nostack, preserves_flags)
    );
    teb
}

include!(concat!(env!("OUT_DIR"), "/teb_asm.rs"));

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
