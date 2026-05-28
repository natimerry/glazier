#![allow(unsafe_op_in_unsafe_fn)]

use thiserror::Error;

pub mod consts;
#[cfg(feature = "runtime")]
pub mod hde;
pub mod pe;
#[cfg(feature = "runtime")]
pub mod runtime;
pub mod utils;

// reexport
pub use consts::*;
pub use pe::pe64_static::*;
#[cfg(feature = "runtime")]
pub use runtime::*;

#[cfg(feature = "runtime")]
pub mod hooking;
#[cfg(not(target_arch = "x86_64"))]
compile_error!("This crate only supports x86_64");

#[derive(Error, Debug)]
pub enum ExpError {
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Export Error: {0}")]
    ExportError(String),

    #[cfg(feature = "runtime")]
    #[error("Failed to open process: {0}")]
    OpenProcessError(u32),

    #[cfg(feature = "runtime")]
    #[error("Runtime error: {0}")]
    RuntimeError(String),

    #[cfg(feature = "runtime")]
    #[error("CreateToolhelp32Snapshot error")]
    CreateToolhelp32SnapshotError(),

    #[cfg(feature = "runtime")]
    #[error("Process not found error")]
    ProcessNotFoundError(String),

    #[cfg(feature = "runtime")]
    #[error("Process32Next error")]
    Process32NextError(),

    #[error("Invalid pattern error. Use IDA style patterns")]
    InvalidPatternError,
}

pub trait ByteReader {
    fn read_u8(&mut self) -> Result<u8, ExpError>;
    fn read_u32(&mut self) -> Result<u32, ExpError>;
    fn read_u64(&mut self) -> Result<u64, ExpError>;
    fn read_i8(&mut self) -> Result<i8, ExpError>;
    fn read_i16(&mut self) -> Result<i16, ExpError>;
    fn read_i32(&mut self) -> Result<i32, ExpError>;
    fn read_i64(&mut self) -> Result<i64, ExpError>;
    fn read_f32(&mut self) -> Result<f32, ExpError>;
    fn read_f64(&mut self) -> Result<f64, ExpError>;

    fn read_c_string(&mut self) -> Result<String, ExpError>;

    fn read_string_at_offset(&mut self, offset: usize) -> Result<String, ExpError>;

    fn seek(&mut self, offset: usize) -> Result<u64, ExpError>;

    fn current_offset(&mut self) -> Result<usize, ExpError>;
}

// Wrapped bindings (works for both modes)
#[allow(
    non_snake_case,
    non_camel_case_types,
    dead_code,
    non_upper_case_globals,
    warnings
)]
pub mod winapi {
    include!(concat!(env!("OUT_DIR"), "/winapi_bindings.rs"));
}

#[inline(always)]
pub unsafe fn to_syscall_arg<T>(val: T) -> usize {
    let size = std::mem::size_of::<T>();
    if size == 8 {
        unsafe { std::mem::transmute_copy(&val) }
    } else if size == 4 {
        let val_u32: u32 = unsafe { std::mem::transmute_copy(&val) };
        val_u32 as usize
    } else if size == 2 {
        let val_u16: u16 = unsafe { std::mem::transmute_copy(&val) };
        val_u16 as usize
    } else if size == 1 {
        let val_u8: u8 = unsafe { std::mem::transmute_copy(&val) };
        val_u8 as usize
    } else {
        unsafe { std::mem::transmute_copy(&val) }
    }
}

#[macro_export]
macro_rules! syscall {
    // 0 Arguments
    ($ssn:expr) => {{
        let status: i32;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("eax") ($ssn) as u32,
                lateout("eax") status,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags)
            );
        }
        status
    }};

    // 1 Argument
    ($ssn:expr, $a1:expr) => {{
        let status: i32;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("eax") ($ssn) as u32,
                in("r10") $crate::to_syscall_arg($a1),
                lateout("eax") status,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags)
            );
        }
        status
    }};

    // 2 Arguments
    ($ssn:expr, $a1:expr, $a2:expr) => {{
        let status: i32;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("eax") ($ssn) as u32,
                in("r10") $crate::to_syscall_arg($a1),
                in("rdx") $crate::to_syscall_arg($a2),
                lateout("eax") status,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags)
            );
        }
        status
    }};

    // 3 Arguments
    ($ssn:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let status: i32;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("eax") ($ssn) as u32,
                in("r10") $crate::to_syscall_arg($a1),
                in("rdx") $crate::to_syscall_arg($a2),
                in("r8")  $crate::to_syscall_arg($a3),
                lateout("eax") status,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags)
            );
        }
        status
    }};

    // 4 Arguments
    ($ssn:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {{
        let status: i32;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("eax") ($ssn) as u32,
                in("r10") $crate::to_syscall_arg($a1),
                in("rdx") $crate::to_syscall_arg($a2),
                in("r8")  $crate::to_syscall_arg($a3),
                in("r9")  $crate::to_syscall_arg($a4),
                lateout("eax") status,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags)
            );
        }
        status
    }};

    // 5+ Arguments (Uses Assembly Thunk)
    ($ssn:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $($rest:expr),+) => {{
        unsafe {
            $crate::utils::do_syscall(
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
