#![allow(unsafe_op_in_unsafe_fn)]

pub use libwinexploit_pe::ByteReader;
pub use libwinexploit_pe::ExpError;
pub use libwinexploit_pe::pe;
pub use libwinexploit_pe::pe::pe32_static::*;
pub use libwinexploit_pe::pe::pe64_static::*;
pub use libwinexploit_runtime as runtime;
pub use libwinexploit_runtime::consts;
pub use libwinexploit_runtime::consts::*;
pub use libwinexploit_runtime::containing_record;
pub use libwinexploit_winapi as winapi;
pub use libwinexploit_winapi::syscall;
pub use libwinexploit_winapi::to_syscall_arg;

pub mod utils {
    pub use libwinexploit_pe::utils::*;
    pub use libwinexploit_runtime::utils::*;
}

#[cfg(feature = "hardware_breakpoint")]
pub mod hardware_breakpoint;
#[cfg(feature = "runtime")]
pub mod hooking;

#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "This crate must be compiled for x86_64; PE32/WOW64 targets are supported at runtime"
);
