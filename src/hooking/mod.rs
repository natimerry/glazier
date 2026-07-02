mod callback;
mod iced_relocator;
pub mod pattern;
pub mod trace_instructions;

#[allow(non_snake_case, non_camel_case_types, dead_code)]
pub mod winapi {
    include!(concat!(env!("OUT_DIR"), "/winapi_hook_bindings.rs"));
}

use crate::ExpError;
use crate::runtime::NativePeRuntime as NativePERuntime;
use crate::runtime::memory::MemoryView;
use crate::winapi::FlushInstructionCache;
use crate::winapi::GetCurrentProcess;
use crate::winapi::GetSystemInfo;
use crate::winapi::HANDLE;
use crate::winapi::LPVOID;
use crate::winapi::MEMORY_BASIC_INFORMATION;
use crate::winapi::SIZE_T;
use crate::winapi::SYSTEM_INFO;
use crate::winapi::VirtualAlloc;
use crate::winapi::VirtualAllocEx;
use crate::winapi::VirtualQuery;
use crate::winapi::VirtualQueryEx;
use std::ptr::null_mut;
use std::u8;
use thiserror::Error;

pub static GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[allow(unused)]
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
    backup: Vec<u8>,
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

    #[error("Disassembly error")]
    DisassemblyError,

    #[error("Trampoline Error")]
    TrampolineError,

    #[error("Runtime error: {0}")]
    RuntimeError(#[from] ExpError),

    #[error("Tried to hook an external process!")]
    ExternalHook,

    #[error("A callback hook is already installed for this WinAPI function")]
    CallbackAlreadyInstalled,
}

/// Owns a generated WinAPI callback hook.
///
/// Generated callback state is immutable and retained for the process lifetime
/// so the detour hot path needs no lock or reference-count operation.
pub struct CallbackHook {
    entry: HookEntry,
}

impl CallbackHook {
    #[doc(hidden)]
    pub fn __new(entry: HookEntry) -> Self { Self { entry } }

    pub fn enable(&mut self) -> Result<(), HookError> {
        unsafe { self.entry.enable(&crate::runtime::memory::LocalMemory) }
    }

    pub fn disable(&mut self) -> Result<(), HookError> {
        unsafe { self.entry.disable(&crate::runtime::memory::LocalMemory) }
    }

    pub fn is_enabled(&self) -> bool { self.entry.is_enabled() }
}

impl std::ops::Deref for CallbackHook {
    type Target = HookEntry;

    fn deref(&self) -> &Self::Target { &self.entry }
}

impl std::ops::DerefMut for CallbackHook {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.entry }
}

impl Drop for CallbackHook {
    fn drop(&mut self) {
        if self.entry.is_enabled() {
            let _ = unsafe { self.entry.disable(&crate::runtime::memory::LocalMemory) };
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]

struct MemorySlot {
    next: *mut MemorySlot,
    // trampoline bytes follow
}

#[repr(C)]
#[derive(Copy, Clone)]
struct MemoryBlock {
    next: *mut MemoryBlock,
    free: *mut MemorySlot,
    used_count: u32,
}

const MEMORY_BLOCK_SIZE: usize = 0x10000; // 64KB
const MEMORY_SLOT_SIZE: usize = 64; // enough for trampoline
const MAX_MEMORY_RANGE: usize = 0x2000_0000; // 512MB

static mut MEMORY_BLOCKS: *mut MemoryBlock = null_mut();

unsafe fn check_address_executable(address: *mut u8, handle: Option<HANDLE>) -> bool {
    let mut mi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    if let Some(handle) = handle {
        VirtualQueryEx(
            handle,
            address as LPVOID,
            &mut mi as *mut _,
            size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T,
        );
    } else {
        VirtualQuery(
            address as LPVOID,
            &mut mi as *mut _,
            size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T,
        );
    }

    return mi.State == 0x00001000 && (mi.Protect & (0x10 | 0x20 | 0x40 | 0x80)) != 0;
}

unsafe fn get_memory_block<M: MemoryView>(
    origin: *mut u8,
    m: &M,
) -> Result<*mut MemoryBlock, ExpError> {
    let mut si: SYSTEM_INFO = std::mem::zeroed();
    GetSystemInfo(&mut si);

    let mut min_addr = si.lpMinimumApplicationAddress as usize;
    let mut max_addr = si.lpMaximumApplicationAddress as usize;

    let origin = origin as usize;

    if origin > MAX_MEMORY_RANGE && min_addr < origin - MAX_MEMORY_RANGE {
        min_addr = origin - MAX_MEMORY_RANGE;
    }

    if max_addr > origin + MAX_MEMORY_RANGE {
        max_addr = origin + MAX_MEMORY_RANGE;
    }

    max_addr -= MEMORY_BLOCK_SIZE - 1;

    // Try existing blocks first
    let mut block = MEMORY_BLOCKS;
    while !block.is_null() {
        let addr = block as usize;
        let current_block = m.read::<MemoryBlock>(block as u64)?;
        if addr >= min_addr && addr < max_addr {
            if !current_block.free.is_null() {
                return Ok(block);
            }
        }
        block = current_block.next;
    }

    // Try allocate new block below origin
    let mut alloc_addr = origin;

    while alloc_addr >= min_addr {
        alloc_addr =
            find_prev_free_region(alloc_addr, min_addr, si.dwAllocationGranularity as usize, m);

        if alloc_addr == 0 {
            break;
        }

        let new_block = if let Some(handle) = m.get_handle() {
            VirtualAllocEx(
                handle,
                alloc_addr as LPVOID,
                MEMORY_BLOCK_SIZE as SIZE_T,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x40,   // PAGE_EXECUTE_READWRITE
            )
        } else {
            VirtualAlloc(
                alloc_addr as LPVOID,
                MEMORY_BLOCK_SIZE as SIZE_T,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x40,   // PAGE_EXECUTE_READWRITE
            )
        } as *mut MemoryBlock;

        if !new_block.is_null() {
            initialize_block(m, new_block)?;
            return Ok(new_block);
        }
    }

    // Try allocate above
    alloc_addr = origin;

    while alloc_addr <= max_addr {
        alloc_addr =
            find_next_free_region(alloc_addr, max_addr, si.dwAllocationGranularity as usize, m);

        if alloc_addr == 0 {
            break;
        }

        let new_block = VirtualAlloc(
            alloc_addr as LPVOID,
            MEMORY_BLOCK_SIZE as SIZE_T,
            0x3000,
            0x40,
        ) as *mut MemoryBlock;

        if !new_block.is_null() {
            initialize_block(m, new_block)?;
            return Ok(new_block);
        }
    }

    Ok(null_mut())
}

unsafe fn initialize_block<M: MemoryView>(m: &M, block: *mut MemoryBlock) -> Result<(), ExpError> {
    let mut b = m.read::<MemoryBlock>(block as u64)?;
    b.used_count = 0;
    b.free = null_mut();

    let mut slot = (block as *mut u8).add(size_of::<MemoryBlock>()) as *mut MemorySlot;
    let end = (block as usize) + MEMORY_BLOCK_SIZE;

    while (slot as usize) + MEMORY_SLOT_SIZE <= end {
        let mut s = m.read::<MemorySlot>(slot as u64)?;
        s.next = b.free;
        m.write::<MemorySlot>(slot as u64, s)?;

        b.free = slot;
        slot = (slot as *mut u8).add(MEMORY_SLOT_SIZE) as *mut MemorySlot;
    }

    b.next = m.read::<*mut MemoryBlock>(std::ptr::addr_of!(MEMORY_BLOCKS) as u64)?;
    MEMORY_BLOCKS = block;

    m.write::<MemoryBlock>(block as u64, b)?;
    Ok(())
}

unsafe fn find_prev_free_region<M: MemoryView>(
    mut addr: usize,
    min: usize,
    granularity: usize,
    m: &M,
) -> usize {
    while addr > min {
        addr = addr.saturating_sub(granularity); // always step back

        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        if m.virtual_query(addr as LPVOID, &mut mbi) == 0 {
            break;
        }

        if mbi.State == 0x10000 {
            let aligned = (mbi.BaseAddress as usize + granularity - 1) & !(granularity - 1);
            if aligned + MEMORY_BLOCK_SIZE <= mbi.BaseAddress as usize + mbi.RegionSize as usize {
                return aligned;
            }
        }

        // Step back by the region size to avoid re-querying the same region
        if mbi.RegionSize as usize > granularity {
            addr = addr.saturating_sub(mbi.RegionSize as usize - granularity);
        }
    }
    0
}

unsafe fn find_next_free_region<M: MemoryView>(
    mut addr: usize,
    max: usize,
    granularity: usize,
    m: &M,
) -> usize {
    while addr < max {
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        if m.virtual_query(addr as LPVOID, &mut mbi) == 0 {
            break;
        }

        let region_size = mbi.RegionSize as usize;
        if region_size == 0 {
            break; // guard against zero-size regions looping forever
        }

        if mbi.State == 0x10000 {
            let aligned = (mbi.BaseAddress as usize + granularity - 1) & !(granularity - 1);
            if aligned + MEMORY_BLOCK_SIZE <= mbi.BaseAddress as usize + region_size {
                return aligned;
            }
        }

        // Always advance past this region.
        addr = mbi.BaseAddress as usize + region_size;
    }
    0
}

pub unsafe fn allocate_buffer<M: MemoryView>(origin: *mut u8, m: &M) -> Result<*mut u8, ExpError> {
    let block = get_memory_block(origin, m)?;
    if block.is_null() {
        return Ok(null_mut());
    }

    let slot = (*block).free;
    if slot.is_null() {
        return Ok(null_mut());
    }

    let mut b = m.read::<MemoryBlock>(block as u64)?;
    let s = m.read::<MemorySlot>(b.free as u64)?;

    b.free = s.next;
    b.used_count += 1;

    m.write::<MemoryBlock>(block as u64, b)?;

    // Debug fill
    m.write_bytes(slot as u64, &[0xCC; MEMORY_SLOT_SIZE])?;

    Ok(slot as *mut u8)
}

impl HookEntry {
    /// hook a loaded winapi function
    /// this only works for currently loaded modulse
    pub fn from_winapi_function(
        func_name: impl ToString,
        module_name: Option<impl ToString>,
        detour: *mut u8,
    ) -> Result<Self, HookError> {
        let runtime = match module_name {
            Some(module) => NativePERuntime::from_module(module)?,
            None => NativePERuntime::from_current_module()?,
        };

        let runtime_addr = runtime.find_export(func_name.to_string())?;

        Self::new(
            runtime_addr.func_addr as *mut u8,
            detour,
            runtime.into_memory(),
        )
    }

    pub fn new(target: *mut u8, detour: *mut u8, m: impl MemoryView) -> Result<Self, HookError> {
        if target.is_null() || detour.is_null() {
            return Err(HookError::InvalidPointer);
        }

        let handle = m.get_handle();
        // problem for future me

        if let Some(_) = handle {
            return Err(HookError::ExternalHook);
        }

        unsafe {
            if !check_address_executable(target, handle)
                || !check_address_executable(detour, handle)
            {
                return Err(HookError::InvalidPointer);
            }

            let buffer_addr = allocate_buffer(target, &m)?;
            if buffer_addr.is_null() {
                return Err(HookError::AllocationFailed);
            }

            let ct = Trampoline::new(target, detour, buffer_addr, &m)?;
            let mut hook = HookEntry {
                target,
                detour: ct.relay,
                trampoline: ct.trampoline,
                hot_patch: ct.patch_above,
                enabled: false,
                n_ip: ct.num_ips,
                old_ips: ct.old_ips.into(),
                new_ips: ct.new_ips.into(),
                backup: vec![],
            };
            let size_rel = size_of::<JmpRel>();
            let size_short = size_of::<JmpRelShort>();

            let (src, size) = if ct.patch_above {
                (target.sub(size_rel), size_rel + size_short)
            } else {
                (target, size_rel)
            };

            hook.backup.resize(size, 0);

            hook.backup = m.read_bytes(src as u64, size)?;

            return Ok(hook);
        }
    }

    pub unsafe fn toggle<M: MemoryView>(&mut self, m: &M) -> Result<(), HookError> {
        let mut old_protect = 0;
        let size_rel = size_of::<JmpRel>();
        let size_short = size_of::<JmpRelShort>();
        let mut patch_size = size_rel;
        let mut patch_target = self.target;
        if self.hot_patch {
            patch_target = patch_target.sub(size_rel);
            patch_size += size_short;
        }
        if m.virtual_protect(patch_target, patch_size, 0x40, &mut old_protect) == 0 {
            return Err(HookError::NonExecutableAddress);
        }

        if !self.enabled {
            // Enable: write JMP_REL at patch_target pointing to detour
            let mut jmp = m.read::<JmpRel>(patch_target as u64)?;
            jmp.opcode = 0xE9;

            let displacement = (self.detour as isize) - (patch_target as isize + size_rel as isize);
            if displacement < i32::MIN as isize || displacement > i32::MAX as isize {
                // This hook is too far away for a 0xE9 jump!
                return Err(HookError::TrampolineError);
            }
            jmp.operand = displacement as i32;

            m.write::<JmpRel>(patch_target as u64, jmp)?;

            if self.hot_patch {
                // Write short jump at target pointing back to patch_target (the JMP_REL)
                let mut short_jmp = m.read::<JmpRelShort>(self.target as u64)?;
                short_jmp.opcode = 0xEB;
                short_jmp.operand = (0i32 - (size_short + size_rel) as i32) as i8;
                m.write::<JmpRelShort>(self.target as u64, short_jmp)?;
            }
        } else {
            // Disable: restore original bytes from backup
            m.copy_non_overlapping(self.backup.as_ptr() as u64, patch_target as u64, patch_size)?;
        }

        m.virtual_protect(patch_target, patch_size, old_protect, &mut old_protect);

        FlushInstructionCache(
            m.get_handle().unwrap_or(GetCurrentProcess()),
            patch_target as LPVOID,
            patch_size as SIZE_T,
        );

        self.enabled = !self.enabled;

        Ok(())
    }

    pub unsafe fn enable<M: MemoryView>(&mut self, m: &M) -> Result<(), HookError> {
        if !self.enabled {
            self.toggle(m)?;
        }
        Ok(())
    }

    pub unsafe fn disable<M: MemoryView>(&mut self, m: &M) -> Result<(), HookError> {
        if self.enabled {
            self.toggle(m)?;
        }
        Ok(())
    }

    pub fn is_enabled(&self) -> bool { self.enabled }

    pub fn original(&self) -> *mut u8 { self.trampoline }
}
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct JmpAbs {
    opcode0: u8, // FF25 00000000: JMP [+6]
    opcode1: u8,
    dummy: u32,
    address: u64,
}
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Trampoline {
    target: *mut u8,
    detour: *mut u8,
    trampoline: *mut u8,
    relay: *mut u8,
    patch_above: bool,
    num_ips: u8,
    old_ips: [u8; 8],
    new_ips: [u8; 8],
}
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct JmpRel {
    opcode: u8,   // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
    operand: i32, // Relative destination address
}
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct JmpRelShort {
    opcode: u8,  // EB xx: JMP +2+xx
    operand: i8, // Relative destination address
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::memory::LocalMemory;
    use crate::winapi::raw::VirtualAlloc;
    use crate::winapi::raw::VirtualFree;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RELEASE: u32 = 0x8000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    unsafe extern "C" fn detour() -> u32 { 42 }

    #[test]
    fn hook_and_trampoline_execute_on_native_architecture() {
        let _guard = GLOBAL_LOCK.lock().unwrap();
        unsafe {
            let target = VirtualAlloc(
                null_mut(),
                0x1000 as SIZE_T,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8;
            assert!(!target.is_null());

            let target_code = [0xb8, 7, 0, 0, 0, 0xc3];
            core::ptr::copy_nonoverlapping(target_code.as_ptr(), target, target_code.len());

            let target_fn: unsafe extern "C" fn() -> u32 = core::mem::transmute(target);
            assert_eq!(target_fn(), 7);

            let mut hook = HookEntry::new(target, detour as *mut u8, LocalMemory).unwrap();
            let original: unsafe extern "C" fn() -> u32 = core::mem::transmute(hook.original());

            hook.toggle(&LocalMemory).unwrap();
            assert_eq!(target_fn(), 42);
            assert_eq!(original(), 7);

            hook.toggle(&LocalMemory).unwrap();
            assert_eq!(target_fn(), 7);

            assert_ne!(VirtualFree(target as *mut _, 0, MEM_RELEASE), 0);
        }
    }

    #[test]
    fn trampoline_relocates_rip_relative_memory_operand() {
        let _guard = GLOBAL_LOCK.lock().unwrap();
        unsafe {
            let target = VirtualAlloc(
                null_mut(),
                0x1000 as SIZE_T,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8;
            assert!(!target.is_null());

            let target_code = [
                0x8B, 0x05, 0x06, 0x00, 0x00, 0x00, // mov eax,[rip+6]
                0xC3, // ret
                0x90, 0x90, 0x90, 0x90, 0x90, 0x78, 0x56, 0x34, 0x12,
            ];
            core::ptr::copy_nonoverlapping(target_code.as_ptr(), target, target_code.len());

            let target_fn: unsafe extern "C" fn() -> u32 = core::mem::transmute(target);
            assert_eq!(target_fn(), 0x1234_5678);

            let mut hook = HookEntry::new(target, detour as *mut u8, LocalMemory).unwrap();
            let original: unsafe extern "C" fn() -> u32 = core::mem::transmute(hook.original());

            hook.toggle(&LocalMemory).unwrap();
            assert_eq!(target_fn(), 42);
            assert_eq!(original(), 0x1234_5678);

            hook.toggle(&LocalMemory).unwrap();
            assert_eq!(target_fn(), 0x1234_5678);

            assert_ne!(VirtualFree(target as *mut _, 0, MEM_RELEASE), 0);
        }
    }

    #[test]
    fn generated_winapi_hook_invokes_typed_callback() {
        let _guard = GLOBAL_LOCK.lock().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let callback_hits = Arc::clone(&hits);
        let expected = unsafe { crate::winapi::raw::GetCurrentProcessId() };

        let mut hook = winapi::GetCurrentProcessId(move |original| {
            callback_hits.fetch_add(1, Ordering::SeqCst);
            unsafe { original() }
        })
        .unwrap();

        hook.enable().unwrap();
        assert_eq!(
            unsafe { crate::winapi::raw::GetCurrentProcessId() },
            expected
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        hook.disable().unwrap();
    }
}
