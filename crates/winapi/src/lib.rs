#![allow(
    warnings,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unsafe_op_in_unsafe_fn
)]

#[cfg(feature = "obfuscation")]
mod resolver;

include!(concat!(env!("OUT_DIR"), "/winapi_bindings.rs"));

#[inline(always)]
pub unsafe fn to_syscall_arg<T>(val: T) -> usize {
    match std::mem::size_of::<T>() {
        8 => unsafe { std::mem::transmute_copy(&val) },
        4 => unsafe { std::mem::transmute_copy::<T, u32>(&val) as usize },
        2 => unsafe { std::mem::transmute_copy::<T, u16>(&val) as usize },
        1 => unsafe { std::mem::transmute_copy::<T, u8>(&val) as usize },
        _ => unsafe { std::mem::transmute_copy(&val) },
    }
}

#[macro_export]
macro_rules! syscall {
    ($ssn:expr) => {{
        let status: i32;
        unsafe { core::arch::asm!("syscall", in("eax") ($ssn) as u32, lateout("eax") status, out("rcx") _, out("r11") _, options(nostack, preserves_flags)); }
        status
    }};
    ($ssn:expr, $a1:expr) => {{
        let status: i32;
        unsafe { core::arch::asm!("syscall", in("eax") ($ssn) as u32, in("r10") $crate::to_syscall_arg($a1), lateout("eax") status, out("rcx") _, out("r11") _, options(nostack, preserves_flags)); }
        status
    }};
    ($ssn:expr, $a1:expr, $a2:expr) => {{
        let status: i32;
        unsafe { core::arch::asm!("syscall", in("eax") ($ssn) as u32, in("r10") $crate::to_syscall_arg($a1), in("rdx") $crate::to_syscall_arg($a2), lateout("eax") status, out("rcx") _, out("r11") _, options(nostack, preserves_flags)); }
        status
    }};
    ($ssn:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let status: i32;
        unsafe { core::arch::asm!("syscall", in("eax") ($ssn) as u32, in("r10") $crate::to_syscall_arg($a1), in("rdx") $crate::to_syscall_arg($a2), in("r8") $crate::to_syscall_arg($a3), lateout("eax") status, out("rcx") _, out("r11") _, options(nostack, preserves_flags)); }
        status
    }};
    ($ssn:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {{
        let status: i32;
        unsafe { core::arch::asm!("syscall", in("eax") ($ssn) as u32, in("r10") $crate::to_syscall_arg($a1), in("rdx") $crate::to_syscall_arg($a2), in("r8") $crate::to_syscall_arg($a3), in("r9") $crate::to_syscall_arg($a4), lateout("eax") status, out("rcx") _, out("r11") _, options(nostack, preserves_flags)); }
        status
    }};
    ($ssn:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $($rest:expr),+) => {{
        unsafe {
            $crate::do_syscall(
                ($ssn),
                $crate::to_syscall_arg($a1),
                $crate::to_syscall_arg($a2),
                $crate::to_syscall_arg($a3),
                $crate::to_syscall_arg($a4),
                $($crate::to_syscall_arg($rest)),*
            )
        }
    }};
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
    .section .text
    .global do_syscall
    .def do_syscall
        .scl 2
        .type 32
    .endef
do_syscall:
    mov [rsp + 8], rcx
    mov [rsp + 16], rdx
    mov [rsp + 24], r8
    mov [rsp + 32], r9
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp + 40]
    mov rcx, [rsp + 48]
    mov [rsp + 40], rcx
    mov rcx, [rsp + 56]
    mov [rsp + 48], rcx
    syscall
    ret
"#
);

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    pub fn do_syscall(ssn: u16, ...) -> i32;
}
