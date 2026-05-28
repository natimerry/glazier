use crate::ExpError;
use crate::ExpError::ParseError;
use crate::pe::PESection;
use std::arch::global_asm;
use std::mem;
#[cfg(feature = "runtime")]
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

#[cfg(target_arch = "x86_64")]
#[cfg(feature = "runtime")]
#[inline(always)]
unsafe fn readqgsword(offset: usize) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[{}]",
            out(reg) result,
            in(reg) offset
        );
    }
    result
}
#[cfg(feature = "runtime")]
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
global_asm!(
    r#"
    .section .text
    .global do_syscall
    .def do_syscall
        .scl 2
        .type 32
    .endef

do_syscall:
    # Save shadow space (Windows x64 ABI)
    mov [rsp + 8], rcx
    mov [rsp + 16], rdx
    mov [rsp + 24], r8
    mov [rsp + 32], r9

    # Map arguments for syscall
    mov eax, ecx        # SSN -> EAX
    mov r10, rdx        # Arg1 -> R10
    mov rdx, r8         # Arg2
    mov r8,  r9         # Arg3
    mov r9,  [rsp + 40] # Arg4

    # Shift stack args (SSN added as arg0)
    mov rcx, [rsp + 48]
    mov [rsp + 40], rcx

    mov rcx, [rsp + 56]
    mov [rsp + 48], rcx

    syscall
    ret
    "#
);

unsafe extern "C" {
    // We shift arguments by 1 because SSN is the first arg
    pub fn do_syscall(ssn: u16, ...) -> i32;

}
pub fn to_wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }
