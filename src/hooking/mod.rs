pub mod pattern;

use crate::hde::hde64_disasm;
use crate::hde::hde64s;
use crate::winapi::__movsb;
use crate::winapi::LPBYTE;
use crate::winapi::LPVOID;
use crate::winapi::MEMORY_BASIC_INFORMATION;
use crate::winapi::VirtualQuery;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::u8;
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

    #[error("Disassembly error")]
    DisassemblyError,

    #[error("Trampoline Error")]
    TrampolineError,
}

unsafe fn check_address_executable(address: *mut u8) -> bool {
    let mut mi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

    VirtualQuery(
        address as LPVOID,
        &mut mi as *mut _,
        size_of::<MEMORY_BASIC_INFORMATION>() as u64,
    );

    return (mi.State == 0x00001000 && (mi.Protect & (0x10 | 0x20 | 0x40 | 0x80)) != 0);
}

impl HookEntry {
    pub fn new(target: *mut u8, detour: *mut u8) -> Result<Self, HookError> {
        if target.is_null() || detour.is_null() {
            return Err(HookError::InvalidPointer);
        }

        unsafe {
            if !check_address_executable(target) || !check_address_executable(detour) {
                return Err(HookError::InvalidPointer);
            }
        }

        todo!()
    }
}
#[repr(C, packed)]
struct JmpAbs {
    opcode0: u8, // FF25 00000000: JMP [+6]
    opcode1: u8,
    dummy: u32,
    address: u64,
}
#[repr(C, packed)]
struct CallAbs {
    opcode0: u8, // FF15 00000002: CALL [+6]
    opcode1: u8,
    dummy0: u32,
    dummy1: u8, // EB 08:         JMP +10
    dummy2: u8,
    address: u64, // Absolute destination address
}
#[repr(C, packed)]
struct JccAbs {
    opcode: u8, // 7* 0E:         J** +16
    dummy0: u8,
    dummy1: u8, // FF25 00000000: JMP [+6]
    dummy2: u8,
    dummy3: u32,
    address: u64, // Absolute destination address
}
#[repr(C, packed)]
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
struct JmpRel {
    opcode: u8,   // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
    operand: i32, // Relative destination address
}
#[repr(C, packed)]
struct JmpRelShort {
    opcode: u8,  // EB xx: JMP +2+xx
    operand: i8, // Relative destination address
}

impl Trampoline {
    pub unsafe fn new(
        target: *mut u8,
        detour: *mut u8,
        trampoline: *mut u8,
    ) -> Result<(), HookError> {
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

            copysize = hde64_disasm(old_inst as *const c_void, &mut hs);

            if (hs.flags & crate::hde::F_ERROR) != 0 {
                return Err(HookError::DisassemblyError);
            }

            copysrc = old_inst as LPVOID;

            if (old_pos as usize >= size_of::<JmpRel>()) {
                // The trampoline function is long enough.
                // Complete the function with the jump to the target function.

                jmp.address = old_inst as u64;
                copysrc = &jmp as *const _ as LPVOID;
                copysize = size_of_val(&jmp) as u32;
                finished = true;
            } else if (hs.modrm & 0xC7) == 0x05 {
                // Instructions using RIP relative addressing. (ModR/M =
                // 00???101B)
                //

                let mut rel_addr: *mut u8 = null_mut();
                __movsb(inst_buffer.as_mut_ptr(), old_inst, copysize as u64);

                copysrc = inst_buffer.as_mut_ptr() as *mut _;

                // Relative address is stored at (instruction length - immediate value length -
                // 4).
                let disp_size = ((hs.flags & 0x3C) >> 2) as isize;

                let rel_addr = inst_buffer
                    .as_mut_ptr()
                    .offset(hs.len as isize)
                    .offset(-disp_size)
                    .offset(-4) as *mut u32;

                let new_value = (old_inst
                    .offset(hs.len as isize)
                    .offset(hs.disp.disp32 as isize))
                .offset_from(new_inst.offset(hs.len as isize))
                    as u32;

                *rel_addr = new_value;

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
                finished = (old_inst as u64 >= jmp_dest);
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

            __movsb(
                ct.trampoline.offset(new_pos as isize),
                copysrc as *mut u8,
                copysize as u64,
            );

            new_pos += copysize as u8;
            old_pos += hs.len;
        }

        // try jong jmp
        //
        if (old_pos as usize) < size_of::<JmpRel>()
            && !Self::is_code_padding(
                ct.target.add(old_pos as usize),
                (size_of::<JmpRel>() as u64) - old_pos as u64,
            )
        {
            // Is there enough place for a short jump?
            //
            if (old_pos as usize) < size_of::<JmpRelShort>()
                && !Self::is_code_padding(
                    ct.target.add(old_pos as usize),
                    (size_of::<JmpRelShort>() as u64) - old_pos as u64,
                )
            {
                return Err(HookError::TrampolineError);
            }

            // Can we place the long jump above the function?
            if !check_address_executable(ct.target.sub(size_of::<JmpRel>() as usize)) {
                return Err(HookError::TrampolineError);
            }

            if !Self::is_code_padding(
                ct.target.sub(size_of::<JmpRel>() as usize),
                size_of::<JmpRel>() as u64,
            ) {
                return Err(HookError::TrampolineError);
            }

            ct.patch_above = true;
        }

        jmp.address = ct.detour as u64;
        ct.relay = ct.trampoline.add(new_pos as usize);

        std::ptr::copy_nonoverlapping(
            &jmp as *const _ as *const u8,
            ct.relay,
            std::mem::size_of_val(&jmp),
        );

        return Ok(());
    }

    unsafe fn is_code_padding(inst: LPBYTE, size: u64) -> bool {
        if *inst != 0x0 && *inst != 0x90 && *inst != 0xCC {
            return false;
        }

        for i in 1..size {
            if *(inst.add(i as usize)) != *inst {
                return false;
            }
        }

        return true;
    }
}
