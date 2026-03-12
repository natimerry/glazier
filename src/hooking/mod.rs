pub mod pattern;

use crate::ExpError;
use crate::hde::hde64_disasm;
use crate::hde::hde64s;
use crate::runtime::memory::MemoryView;
use crate::runtime::pe64_runtime::PE64Runtime;
use crate::winapi::FlushInstructionCache;
use crate::winapi::GetCurrentProcess;
use crate::winapi::GetSystemInfo;
use crate::winapi::HANDLE;
use crate::winapi::LPBYTE;
use crate::winapi::LPVOID;
use crate::winapi::MEMORY_BASIC_INFORMATION;
use crate::winapi::SYSTEM_INFO;
use crate::winapi::VirtualAlloc;
use crate::winapi::VirtualAllocEx;
use crate::winapi::VirtualQuery;
use crate::winapi::VirtualQueryEx;
use log::trace;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::u8;
use thiserror::Error;

pub static mut GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
            size_of::<MEMORY_BASIC_INFORMATION>() as u64,
        );
    } else {
        VirtualQuery(
            address as LPVOID,
            &mut mi as *mut _,
            size_of::<MEMORY_BASIC_INFORMATION>() as u64,
        );
    }

    return mi.State == 0x00001000 && (mi.Protect & (0x10 | 0x20 | 0x40 | 0x80)) != 0;
}

unsafe fn get_memory_block<M: MemoryView>(origin: *mut u8, m: &M) -> *mut MemoryBlock {
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
        if addr >= min_addr && addr < max_addr {
            if !(m.read::<MemoryBlock>(block as u64))
                .expect("Failed to read memory block")
                .free
                .is_null()
            {
                return block;
            }
        }
        block = m.read::<MemoryBlock>(block as u64).unwrap().next;
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
                MEMORY_BLOCK_SIZE as u64,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x40,   // PAGE_EXECUTE_READWRITE
            )
        } else {
            VirtualAlloc(
                alloc_addr as LPVOID,
                MEMORY_BLOCK_SIZE as u64,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x40,   // PAGE_EXECUTE_READWRITE
            )
        } as *mut MemoryBlock;

        if !new_block.is_null() {
            initialize_block(m, new_block);
            return new_block;
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

        let new_block = VirtualAlloc(alloc_addr as LPVOID, MEMORY_BLOCK_SIZE as u64, 0x3000, 0x40)
            as *mut MemoryBlock;

        if !new_block.is_null() {
            initialize_block(m, new_block);
            return new_block;
        }
    }

    null_mut()
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

        addr = mbi.BaseAddress as usize + region_size; // always advance past this region
    }
    0
}

pub unsafe fn allocate_buffer<M: MemoryView>(origin: *mut u8, m: &M) -> *mut u8 {
    let block = get_memory_block(origin, m);
    if block.is_null() {
        return null_mut();
    }

    let slot = (*block).free;
    if slot.is_null() {
        return null_mut();
    }

    let mut b = m.read::<MemoryBlock>(block as u64).unwrap();
    let s = m.read::<MemorySlot>(b.free as u64).unwrap();

    b.free = s.next;
    b.used_count += 1;

    m.write::<MemoryBlock>(block as u64, b).unwrap();

    // Debug fill
    m.write_bytes(slot as u64, &[0xCC; MEMORY_SLOT_SIZE]);

    slot as *mut u8
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
            Some(module) => PE64Runtime::from_module(module)?,
            None => PE64Runtime::from_current_module()?,
        };

        let runtime_addr = runtime.find_export(func_name.to_string())?;

        Self::new(runtime_addr.func_addr as *mut u8, detour, runtime.memory)
    }

    pub fn new(target: *mut u8, detour: *mut u8, m: impl MemoryView) -> Result<Self, HookError> {
        if target.is_null() || detour.is_null() {
            return Err(HookError::InvalidPointer);
        }

        let handle = m.get_handle();
        // problem for future me

        if let None = handle {
            return Err(HookError::ExternalHook);
        }

        unsafe {
            if !check_address_executable(target, handle)
                || !check_address_executable(detour, handle)
            {
                return Err(HookError::InvalidPointer);
            }

            let buffer_addr = allocate_buffer(target, &m);
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

            hook.backup = m.read_bytes(src as u64, size).unwrap().try_into().unwrap();

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
            m.copy_non_overlapping(self.backup.as_ptr() as u64, patch_target as u64, patch_size);
        }

        m.virtual_protect(patch_target, patch_size, old_protect, &mut old_protect);

        FlushInstructionCache(
            m.get_handle().unwrap_or(GetCurrentProcess()),
            patch_target as LPVOID,
            patch_size as u64,
        );

        self.enabled = !self.enabled;

        Ok(())
    }

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
struct CallAbs {
    opcode0: u8, // FF15 00000002: CALL [+6]
    opcode1: u8,
    dummy0: u32,
    dummy1: u8, // EB 08:         JMP +10
    dummy2: u8,
    address: u64, // Absolute destination address
}
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct JccAbs {
    opcode: u8, // 7* 0E:         J** +16
    dummy0: u8,
    dummy1: u8, // FF25 00000000: JMP [+6]
    dummy2: u8,
    dummy3: u32,
    address: u64, // Absolute destination address
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

#[allow(unused)]
impl Trampoline {
    pub unsafe fn new<M: MemoryView>(
        target: *mut u8,
        detour: *mut u8,
        trampoline: *mut u8,
        m: &M,
    ) -> Result<Self, HookError> {
        let mut call = CallAbs {
            opcode0: 0xFF,
            opcode1: 0x15,
            dummy0: 0x00000002, // FF15 00000002: CALL [+6]
            dummy1: 0xEB,
            dummy2: 0x08,                // EB 08:         JMP +10
            address: 0x0000000000000000, // Absolute destination address
        };

        let mut jmp = JmpAbs {
            opcode0: 0xff,
            opcode1: 0x25,
            dummy: 0x0,
            address: 0,
        };

        let mut jcc = JccAbs {
            opcode: 0x70,
            dummy0: 0x0e,
            dummy1: 0xff,
            dummy2: 0x25,
            dummy3: 0x0,
            address: 0x0,
        };

        let mut old_pos = 0u8;
        let mut new_pos = 0u8;
        let mut jmp_dest = 0u64;

        let mut inst_buffer = [0u8; 16];

        let mut finished = false;
        let mut ct = Self {
            target,
            detour,
            trampoline,
            relay: null_mut(),
            patch_above: false,
            num_ips: 0,
            old_ips: [0; 8],
            new_ips: [0; 8],
        };

        while !finished {
            let mut hs = hde64s::default();
            let mut copysize = 0;
            let mut copysrc: LPVOID = null_mut();

            let old_inst = ct.target.offset(old_pos as isize);
            let new_inst = ct.trampoline.offset(new_pos as isize);

            copysize = hde64_disasm(old_inst as *const c_void, &mut hs, m);

            trace!(
                "old_pos={} old_inst=0x{:x} opcode={:02x} modrm={:02x} len={} copySize={}",
                old_pos, old_inst as usize, hs.opcode, hs.modrm, hs.len, copysize
            );

            match hs.opcode {
                0xE8 => trace!("  → CALL"),
                0xE9 | 0xEB => trace!("  → JMP"),
                0x70..=0x7F | 0x0F if hs.opcode2 & 0xF0 == 0x80 => trace!("  → Jcc"),
                0xC2 | 0xC3 => trace!("  → RET"),
                _ if (hs.modrm & 0xC7) == 0x05 => trace!("  → RIP-relative"),
                _ => trace!("  → COPY"),
            }

            if (hs.flags & crate::hde::F_ERROR) != 0 {
                return Err(HookError::DisassemblyError);
            }

            copysrc = old_inst as LPVOID;

            if old_pos as usize >= size_of::<JmpRel>() {
                jmp.address = old_inst as u64;
                copysrc = &jmp as *const _ as LPVOID;
                copysize = size_of_val(&jmp) as u32;
                finished = true;
            } else if (hs.modrm & 0xC7) == 0x05 {
                println!("RIP RELATIVE OVERRIDE");
                // Instructions using RIP relative addressing. (ModR/M = 00???101B)
                // std::ptr::copy_nonoverlapping(
                //     old_inst as *const u8,
                //     inst_buffer.as_mut_ptr(),
                //     hs.len as usize, // Use hs.len, not copysize
                // );

                m.copy_non_overlapping(
                    old_inst as u64,
                    inst_buffer.as_mut_ptr() as u64,
                    hs.len as usize,
                );

                copysrc = inst_buffer.as_mut_ptr() as LPVOID;

                // Relative address is stored at (instruction length - immediate value length -
                // 4).
                let disp_size = ((hs.flags & 0x3C) >> 2) as isize;
                let rel_addr = inst_buffer
                    .as_mut_ptr()
                    .offset(hs.len as isize)
                    .offset(-disp_size)
                    .offset(-4) as u64;

                let old_target = old_inst
                    .offset(hs.len as isize)
                    .offset(hs.disp.disp32 as isize);
                let new_base = new_inst.offset(hs.len as isize);
                let delta: isize = old_target.offset_from(new_base);

                if delta < i32::MIN as isize || delta > i32::MAX as isize {
                    return Err(HookError::TrampolineError);
                }

                m.write::<u32>(rel_addr, delta as i32 as u32)?;

                // Complete the function if JMP (FF /4).
                if hs.opcode == 0xFF && hs.modrm_reg == 4 {
                    finished = true;
                }
            } else if hs.opcode == 0xE8 {
                // Direct relative CALL
                let dest = old_inst
                    .offset(hs.len as isize)
                    .offset(hs.imm.imm32 as i32 as isize) as u64;

                call.address = dest;
                copysrc = &call as *const _ as LPVOID;

                copysize = size_of_val(&call) as u32;
            } else if (hs.opcode & 0xFD) == 0xE9 {
                // Direct relative JMP (EB or E9)
                let mut dest = old_inst.offset(hs.len as isize) as u64;

                // short jmp
                if hs.opcode == 0xEB {
                    dest += hs.imm.imm8 as u64;
                } else {
                    dest += hs.imm.imm32 as u64;
                }

                let start = ct.target as u64;
                let end = start + core::mem::size_of::<JmpRel>() as u64;

                if start <= dest && dest < end {
                    if jmp_dest < dest {
                        jmp_dest = dest;
                    }
                } else {
                    jmp.address = dest;

                    copysrc = &jmp as *const _ as LPVOID;
                    copysize = size_of_val(&jmp) as u32;

                    finished = old_inst as u64 >= jmp_dest;
                }
            } else if (hs.opcode & 0xF0) == 0x70
                || (hs.opcode & 0xFC) == 0xE0
                || (hs.opcode2 & 0xF0) == 0x80
            {
                let mut dest = old_inst.offset(hs.len as isize) as u64;

                if (hs.opcode & 0xF0) == 0x70      // Jcc
                    || (hs.opcode & 0xFC) == 0xE0
                // LOOPNZ/LOOPZ/LOOP/JECXZ
                {
                    dest += hs.imm.imm8 as u64;
                } else {
                    dest += hs.imm.imm32 as u64;
                }

                let start = ct.target as u64;
                let end = start + core::mem::size_of::<JmpRel>() as u64;

                if start <= dest && dest < end {
                    if jmp_dest < dest {
                        jmp_dest = dest;
                    }
                } else if (hs.opcode & 0xFC) == 0xE0 {
                    return Err(HookError::DisassemblyError);
                } else {
                    let cond: u8 = {
                        let opcode = if hs.opcode != 0x0F {
                            hs.opcode
                        } else {
                            hs.opcode2
                        };

                        opcode & 0x0F
                    };

                    // Invert the condition in x64 mode to simplify the conditional jump logic.
                    jcc.opcode = 0x71 ^ cond;
                    jcc.address = dest;

                    copysrc = &jcc as *const _ as LPVOID;
                    copysize = size_of::<JccAbs>() as u32;
                }
            } else if (hs.opcode & 0xFE) == 0xC2 {
                // we reached ret
                finished = old_inst as u64 >= jmp_dest;
            }
            if (old_inst as u64) < jmp_dest && copysize != hs.len as u32 {
                return Err(HookError::TrampolineError);
            }

            if (new_pos as u64 + copysize as u64) > ((64 - size_of::<JmpAbs>()) as u64) {
                return Err(HookError::TrampolineError);
            }

            if (ct.num_ips as u64 >= ct.old_ips.len() as u64) {
                return Err(HookError::TrampolineError);
            }

            ct.old_ips[ct.num_ips as usize] = old_pos;
            ct.new_ips[ct.num_ips as usize] = new_pos;
            ct.num_ips += 1;

            m.copy_non_overlapping(
                copysrc as u64,
                ct.trampoline.add(new_pos as usize) as u64,
                copysize as usize,
            );

            debug_assert!(copysize > 0);
            debug_assert!((new_pos as usize + copysize as usize) <= 64 - size_of::<JmpAbs>());

            new_pos += copysize as u8;
            old_pos += hs.len;
        }

        // try jong jmp
        //
        if (old_pos as usize) < size_of::<JmpRel>()
            && !Self::is_code_padding(
                m,
                ct.target.add(old_pos as usize) as u64,
                (size_of::<JmpRel>() as u64) - old_pos as u64,
            )?
        {
            // Is there enough place for a short jump?
            //
            if (old_pos as usize) < size_of::<JmpRelShort>()
                && !Self::is_code_padding(
                    m,
                    ct.target.add(old_pos as usize) as u64,
                    (size_of::<JmpRelShort>() as u64) - old_pos as u64,
                )?
            {
                return Err(HookError::TrampolineError);
            }

            // Can we place the long jump above the function?
            if !check_address_executable(
                ct.target.sub(size_of::<JmpRel>() as usize),
                m.get_handle(),
            ) {
                return Err(HookError::TrampolineError);
            }

            if !Self::is_code_padding(
                m,
                ct.target.sub(size_of::<JmpRel>() as usize) as u64,
                size_of::<JmpRel>() as u64,
            )? {
                return Err(HookError::TrampolineError);
            }

            ct.patch_above = true;
        }

        jmp.address = ct.detour as u64;
        ct.relay = ct.trampoline.add(new_pos as usize);

        // std::ptr::copy_nonoverlapping(
        //     &jmp as *const _ as *const u8,
        //     ct.relay,
        //     std::mem::size_of_val(&jmp),
        // );
        //
        m.copy_non_overlapping(
            &jmp as *const _ as u64,
            ct.relay as u64,
            std::mem::size_of_val(&jmp),
        );

        return Ok(ct);
    }

    fn is_code_padding<M: MemoryView>(m: &M, inst: u64, size: u64) -> Result<bool, ExpError> {
        let first = m.read::<u8>(inst)?;

        if first != 0x0 && first != 0x90 && first != 0xCC {
            return Ok(false);
        }

        for i in 1..size {
            if m.read::<u8>(inst + i)? != first {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
