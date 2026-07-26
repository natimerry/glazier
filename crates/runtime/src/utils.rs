#[cfg(target_arch = "x86_64")]
use glazier_bindings::PEB;
use glazier_bindings::TEB;

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
#[inline(always)]
pub unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    core::arch::asm!(
    "mrs {0}, tpidr_el0",
    out(reg) teb,
    options(nostack, preserves_flags)
    );
    teb
}

#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86")]
#[inline(always)]
pub unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    unsafe {
        core::arch::asm!(
            "mov {}, fs:[0x18]",
            out(reg) teb,
            options(nostack, preserves_flags)
        );
    }
    teb
}
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn get_teb() -> *mut TEB { unsafe { readqgsword(0x30) as *mut TEB } }

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn get_peb() -> *mut PEB { unsafe { readqgsword(0x60) as *mut PEB } }

pub fn to_wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }
