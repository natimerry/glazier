pub mod pattern;

use crate::winapi::LPVOID;
use crate::winapi::MEMORY_BASIC_INFORMATION;
use crate::winapi::VirtualQuery;
use thiserror::Error;

pub static mut GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub struct HookEntry {
    target: *mut u8,
    /// Target of the hook
    detour: *mut u8,
    /// Address of function to jmp to
    trampoline: *mut u8,
    /// Address of trampoline
    hot_patch: bool,
    enabled: bool,
    n_ip: u8, // Instruction boundary count
    old_ips: Vec<u8>,
    new_ips: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum HookError {
    #[error("Invalid pointer")]
    InvalidPointer,
    #[error("Invalid instruction")]
    InvalidInstruction,
    #[error("Insufficient size")]
    InsufficientSize,

    #[error("Allocation failed")]
    AllocationFailed,

    #[error("Target or detour address is not executable")]
    NonExecutableAddress,
}

impl HookEntry {
    unsafe fn check_address_executable(address: *mut u8) -> bool {
        let mut mi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        VirtualQuery(
            address as LPVOID,
            &mut mi as *mut _,
            size_of::<MEMORY_BASIC_INFORMATION>() as u64,
        );

        return (mi.State == 0x00001000 && (mi.Protect & (0x10 | 0x20 | 0x40 | 0x80)) != 0);
    }
    pub fn new(target: *mut u8, detour: *mut u8) -> Result<Self, HookError> {
        if target.is_null() || detour.is_null() {
            return Err(HookError::InvalidPointer);
        }

        unsafe {
            if !Self::check_address_executable(target) || !Self::check_address_executable(detour) {
                return Err(HookError::InvalidPointer);
            }
        }

        todo!()
    }
}
