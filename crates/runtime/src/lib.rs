#![allow(unsafe_op_in_unsafe_fn)]

pub mod consts;
pub mod utils;
pub use glazier_pe::ByteReader;
pub use glazier_pe::ExpError;
pub use glazier_pe::pe;
pub use glazier_pe::pe::pe32_static::*;
pub use glazier_pe::pe::pe64_static::*;

#[path = "runtime/architecture.rs"]
pub mod architecture;
#[path = "runtime/exports.rs"]
pub mod exports;
#[path = "runtime/memory.rs"]
pub mod memory;
#[path = "runtime/native_pe_runtime.rs"]
pub mod native_pe_runtime;
#[path = "runtime/pe32_runtime.rs"]
pub mod pe32_runtime;
#[path = "runtime/pe64_runtime.rs"]
pub mod pe64_runtime;
#[path = "runtime/process.rs"]
pub mod process;

pub use architecture::ArchitectureError;
pub use architecture::TargetArchitecture;
pub use architecture::process_architecture;
pub use architecture::thread_architecture;
pub use consts::*;
pub use native_pe_runtime::NativePERuntime;
pub use native_pe_runtime::NativePeRuntime;
