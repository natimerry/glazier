pub mod pattern;

use crate::ExpError;

struct HookEntry {
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
