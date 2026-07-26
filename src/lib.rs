#![allow(unsafe_op_in_unsafe_fn)]

pub use glazier_pe::ByteReader;
pub use glazier_pe::ExpError;
pub use glazier_pe::pe;
pub use glazier_pe::pe::pe32_static::*;
pub use glazier_pe::pe::pe64_static::*;
pub use glazier_runtime as runtime;
pub use glazier_runtime::consts;
pub use glazier_runtime::consts::*;
pub use glazier_runtime::containing_record;
pub use glazier_winapi as winapi;
pub use glazier_winapi::syscall;
pub use glazier_winapi::to_syscall_arg;

pub mod utils {
    pub use glazier_pe::utils::*;
    pub use glazier_runtime::utils::*;
}

#[cfg(feature = "hardware_breakpoint")]
pub mod hardware_breakpoint;
#[cfg(feature = "runtime")]
pub mod hooking;

#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "This crate must be compiled for x86_64; PE32/WOW64 targets are supported at runtime"
);
